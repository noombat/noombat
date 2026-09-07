// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared utilities for OAuth authentication flows.

use noombat_core::error::{NoombatError, Result};
use sqlx::PgPool;

/// Generate a cryptographically random OAuth state token.
pub fn generate_state_token() -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut buf = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Percent-encode a string for use in a URL query parameter.
pub fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Ensure the proposed username is unique by appending a numeric
/// suffix if necessary.
///
/// Truncates the base to 27 characters to leave room for a three-digit
/// suffix within the 30-character username limit.
pub async fn ensure_unique_username(pool: &PgPool, base: &str, domain: &str) -> Result<String> {
    let truncated: String = base.chars().take(27).collect();

    if !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM actors WHERE username = $1 AND domain = $2 AND is_local = TRUE)",
    )
    .bind(&truncated)
    .bind(domain)
    .fetch_one(pool)
    .await?
    {
        return Ok(truncated);
    }

    for i in 1u32..1000 {
        let candidate = format!("{truncated}{i}");
        if !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM actors WHERE username = $1 AND domain = $2 AND is_local = TRUE)",
        )
        .bind(&candidate)
        .bind(domain)
        .fetch_one(pool)
        .await?
        {
            return Ok(candidate);
        }
    }

    Err(NoombatError::Internal(
        "failed to generate unique username".into(),
    ))
}

/// Attach an external identity to an account that already exists.
///
/// This is a second way in being added, not a sign-in. Returns the
/// account's username so the caller can answer with it.
///
/// Uniqueness of `(provider, external_id)` is enforced by the schema and
/// surfaces here as a refusal rather than a 500. One external identity
/// belongs to one account: quietly re-pointing it would take somebody
/// else's second way in away from them without telling either party.
pub async fn link_identity(
    pool: &PgPool,
    actor_id: uuid::Uuid,
    provider: &str,
    external_id: &str,
) -> Result<String> {
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM actors WHERE id = $1 AND is_local = TRUE")
            .bind(actor_id)
            .fetch_optional(pool)
            .await?;

    let username = username.ok_or(NoombatError::Forbidden)?;

    sqlx::query(
        "INSERT INTO oauth_identities (actor_id, provider, external_id) VALUES ($1, $2, $3)",
    )
    .bind(actor_id)
    .bind(provider)
    .bind(external_id)
    .execute(pool)
    .await
    .map_err(|e| {
        if matches!(&e, sqlx::Error::Database(db) if db.is_unique_violation()) {
            NoombatError::BadRequest("that identity is already linked to an account".into())
        } else {
            NoombatError::from(e)
        }
    })?;

    Ok(username)
}

/// Find the local actor an OAuth identity is already linked to.
///
/// The `a.is_local = TRUE` filter matters: `actors` also holds remote
/// actors mirrored from other instances, and an OAuth identity must never
/// resolve to one of those.
pub async fn find_linked_actor(
    pool: &PgPool,
    provider: &str,
    external_id: &str,
) -> Result<Option<(uuid::Uuid, String)>> {
    sqlx::query_as::<_, (uuid::Uuid, String)>(
        r#"SELECT a.id, a.username FROM actors a
           JOIN oauth_identities oi ON oi.actor_id = a.id
           WHERE oi.provider = $1
             AND oi.external_id = $2
             AND a.is_local = TRUE"#,
    )
    .bind(provider)
    .bind(external_id)
    .fetch_optional(pool)
    .await
    .map_err(NoombatError::from)
}

/// Sign in an OAuth identity, or register a new local actor for it.
///
/// This is the single gate on OAuth account creation. Both providers'
/// callbacks reach it, so `allow_registration` closes both doors at once.
///
/// **The guard sits after the linked-identity lookup, deliberately.**
/// Closing registration must not lock out the accounts that already exist:
/// an account created through OAuth and never given a password (the
/// upgrade path is `set_password`) has no other way in, so refusing before
/// the lookup would strand it. Registration is about new actors only.
///
/// Returns `(actor_id, username, is_new)`. The two callers' result types
/// differ (ORCID carries the iD), so the tuple is what they have in common.
pub async fn sign_in_or_register(
    pool: &PgPool,
    provider: &str,
    external_id: &str,
    base_username: &str,
    display_name: Option<String>,
    our_domain: &str,
    allow_registration: bool,
) -> Result<(uuid::Uuid, String, bool)> {
    if let Some((actor_id, username)) = find_linked_actor(pool, provider, external_id).await? {
        return Ok((actor_id, username, false));
    }

    if !allow_registration {
        // Before the keypair, which is the expensive part, and before any
        // write. A refused sign-up must leave nothing behind.
        return Err(NoombatError::Forbidden);
    }

    let username = ensure_unique_username(pool, base_username, our_domain).await?;
    let keypair = crate::keys::generate_keypair_async().await?;

    let new_actor = noombat_core::actor::NewActor {
        actor_type: noombat_core::actor::ActorType::Individual,
        username: username.clone(),
        display_name: display_name.filter(|s| !s.is_empty()),
        domain: our_domain.to_owned(),
        public_key_pem: keypair.rsa.public_pem,
        private_key_pem: keypair.rsa.private_pem,
        ed25519_public_key: keypair.ed25519.public_multibase,
        ed25519_private_key: keypair.ed25519.private_base64,
    };

    let actor = crate::repo::create_actor(pool, &new_actor).await?;

    sqlx::query(
        "INSERT INTO oauth_identities (actor_id, provider, external_id) VALUES ($1, $2, $3)",
    )
    .bind(actor.id)
    .bind(provider)
    .bind(external_id)
    .execute(pool)
    .await?;

    Ok((actor.id, username, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noombat_core::actor::{ActorType, NewActor};

    const PROVIDER: &str = "mastodon";
    const EXTERNAL: &str = "alice@remote.example";
    const DOMAIN: &str = "local.test";

    async fn seed_linked_actor(pool: &PgPool) -> uuid::Uuid {
        let keypair = crate::keys::generate_keypair_async().await.unwrap();
        let actor = crate::repo::create_actor(
            pool,
            &NewActor {
                actor_type: ActorType::Individual,
                username: "alice".to_owned(),
                display_name: None,
                domain: DOMAIN.to_owned(),
                public_key_pem: keypair.rsa.public_pem,
                private_key_pem: keypair.rsa.private_pem,
                ed25519_public_key: keypair.ed25519.public_multibase,
                ed25519_private_key: keypair.ed25519.private_base64,
            },
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO oauth_identities (actor_id, provider, external_id) VALUES ($1, $2, $3)",
        )
        .bind(actor.id)
        .bind(PROVIDER)
        .bind(EXTERNAL)
        .execute(pool)
        .await
        .unwrap();
        actor.id
    }

    async fn actor_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM actors")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_closed_instance_refuses_an_unknown_identity(pool: PgPool) {
        let result =
            sign_in_or_register(&pool, PROVIDER, EXTERNAL, "alice", None, DOMAIN, false).await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "registration is closed, so an unknown identity must be refused, got {result:?}"
        );
        // The stronger of the two observations. The behaviour being removed
        // is one that succeeds and leaves a row behind, so a refusal that
        // still wrote an actor would pass an error-only assertion.
        assert_eq!(
            actor_count(&pool).await,
            0,
            "a refused sign-up must leave no actor behind"
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_closed_instance_still_signs_in_a_linked_identity(pool: PgPool) {
        // The regression guard. An account created through OAuth and never
        // given a password has no other way in, so closing registration
        // must not lock it out.
        let seeded = seed_linked_actor(&pool).await;

        let (actor_id, username, is_new) =
            sign_in_or_register(&pool, PROVIDER, EXTERNAL, "alice", None, DOMAIN, false)
                .await
                .expect("a linked identity signs in whatever the registration policy is");

        assert_eq!(actor_id, seeded, "signed in as the wrong actor");
        assert_eq!(username, "alice");
        assert!(!is_new, "an existing account must not be reported as new");
        assert_eq!(actor_count(&pool).await, 1, "no second actor was created");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_open_instance_registers_an_unknown_identity(pool: PgPool) {
        let (actor_id, username, is_new) =
            sign_in_or_register(&pool, PROVIDER, EXTERNAL, "alice", None, DOMAIN, true)
                .await
                .expect("registration is open");

        assert!(is_new, "a new identity must be reported as new");
        assert_eq!(username, "alice");
        assert_eq!(actor_count(&pool).await, 1);
        let linked = find_linked_actor(&pool, PROVIDER, EXTERNAL)
            .await
            .unwrap()
            .expect("the identity is linked so the next sign-in finds it");
        assert_eq!(
            linked.0, actor_id,
            "the oauth_identities row points elsewhere"
        );
    }
}
