// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Account migration via the ActivityPub `Move` activity.
//!
//! A `Move` activity signals that an actor has migrated to a new
//! account on a different instance. The protocol follows the Mastodon
//! convention:
//!
//! 1. The **target** actor (on the new instance) lists the **source**
//!    actor's AP URI as an alias in its `alsoKnownAs` property (or
//!    equivalent). In Noombat, aliases are stored in the
//!    `actor_aliases` table.
//! 2. The **source** actor sends a `Move` activity:
//!
//!    ```json
//!    {
//!      "type": "Move",
//!      "actor": "https://old.example/users/alice",
//!      "object": "https://old.example/users/alice",
//!      "target": "https://new.example/users/alice"
//!    }
//!    ```
//!
//! 3. Followers of the source actor who observe the `Move`:
//!    - Verify that the target actor's `alsoKnownAs` includes the
//!      source actor's URI.
//!    - Unfollow the source actor.
//!    - Follow the target actor.
//!
//! This module handles both **outbound** (local actor migrating away)
//! and **inbound** (remote actor notifying this instance of their
//! migration) flows.

use noombat_ap::activity::Activity;
use noombat_ap::context::default_context;
use noombat_core::error::{NoombatError, Result};
use serde_json::json;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::delivery;
use crate::inbox::resolve_actor;

// ..... Outbound: local actor initiates migration .....

/// Add an alias to a local actor's `alsoKnownAs` list.
///
/// This is the prerequisite step on the **target** instance: before
/// the old account can send a `Move`, the new account must declare
/// the old account as an alias.
pub async fn add_alias(pool: &PgPool, actor_id: Uuid, alias_uri: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO actor_aliases (actor_id, alias) \
         VALUES ($1, $2) \
         ON CONFLICT (actor_id, alias) DO NOTHING",
    )
    .bind(actor_id)
    .bind(alias_uri)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove an alias from a local actor's `alsoKnownAs` list.
pub async fn remove_alias(pool: &PgPool, actor_id: Uuid, alias_uri: &str) -> Result<()> {
    sqlx::query("DELETE FROM actor_aliases WHERE actor_id = $1 AND alias = $2")
        .bind(actor_id)
        .bind(alias_uri)
        .execute(pool)
        .await?;
    Ok(())
}

/// Retrieve all aliases for a local actor.
pub async fn list_aliases(pool: &PgPool, actor_id: Uuid) -> Result<Vec<String>> {
    let aliases =
        sqlx::query_scalar::<_, String>("SELECT alias FROM actor_aliases WHERE actor_id = $1")
            .bind(actor_id)
            .fetch_all(pool)
            .await?;
    Ok(aliases)
}

/// Revoke every outstanding application grant held by a migrating actor,
/// returning how many. A grant is bound to this instance's domain and is
/// never re-pointed, so leaving it live serves the applicant's CV from an
/// instance they have left. `account_migrated` rather than
/// `applicant_withdrew`: the same 410 to an employer, a different
/// sentence to the applicant.
pub async fn revoke_grants_for_migration(pool: &PgPool, source_actor_id: Uuid) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE application_grants g \
         SET state = 'revoked', revoked_at = now(), revoked_reason = 'account_migrated' \
         FROM applications a \
         WHERE g.application_id = a.id \
           AND a.applicant_id = $1 \
           AND g.state = 'active'",
    )
    .bind(source_actor_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Initiate an outbound `Move`: set the local actor's `moved_to`
/// column and broadcast the `Move` activity to all followers.
///
/// Outstanding application grants are revoked first. See
/// [`revoke_grants_for_migration`] for why they are not carried over.
///
/// # Preconditions
///
/// The caller must verify that the **target** actor has already
/// listed the **source** actor as an alias (i.e. the target's
/// `alsoKnownAs` includes the source's AP URI). This verification
/// is typically performed by fetching the target's profile and
/// checking for the alias before calling this function.
pub async fn initiate_move(
    pool: &PgPool,
    source_actor_id: Uuid,
    source_ap_id: &str,
    target_ap_id: &str,
) -> Result<()> {
    // Before `moved_to` is set, so a failure stops the move rather than
    // leaving live grants served from an instance the actor has left.
    let revoked = revoke_grants_for_migration(pool, source_actor_id).await?;
    if revoked > 0 {
        tracing::info!(
            actor_id = %source_actor_id,
            revoked,
            "revoked application grants on migration"
        );
    }

    // Record the move locally.
    sqlx::query("UPDATE actors SET moved_to = $1 WHERE id = $2")
        .bind(target_ap_id)
        .bind(source_actor_id)
        .execute(pool)
        .await?;

    // Construct the Move activity.
    let move_id = format!(
        "{source_ap_id}#move-{}",
        chrono::Utc::now().timestamp_millis()
    );
    let move_activity = json!({
        "@context": default_context(),
        "id": move_id,
        "type": "Move",
        "actor": source_ap_id,
        "object": source_ap_id,
        "target": target_ap_id,
    });

    // Deliver to all followers.
    let inboxes = noombat_identity::repo::get_follower_inboxes(pool, source_actor_id).await?;
    for inbox in inboxes {
        if let Err(e) = delivery::enqueue(pool, source_actor_id, &move_activity, &inbox).await {
            warn!(
                target_inbox = %inbox,
                error = %e,
                "failed to enqueue Move activity"
            );
        }
    }

    info!(
        source = source_ap_id,
        target = target_ap_id,
        "Move activity broadcast to followers"
    );
    Ok(())
}

// ..... Inbound: remote actor notifies this instance of migration .....

/// Handle an inbound `Move` activity from a remote actor.
///
/// Verification steps:
/// 1. The `actor` and `object` of the Move must be the same URI
///    (the source actor asserts the move of itself).
/// 2. The `target` actor's profile must include the source URI in
///    its `alsoKnownAs` array.
///
/// **Security note:** The inbox handler has already verified the HTTP
/// Signature against the source actor's public key before dispatching
/// to this function, so step 1 implicitly confirms that the actor who
/// signed the request is the one claiming to move.
///
/// The target actor's profile is fetched with an HTTP Signature
/// using the first available local actor's key (instance-level
/// signed fetch), ensuring compatibility with instances that require
/// authenticated fetches (e.g. GotoSocial).
///
/// On successful verification, all local followers of the source
/// actor are migrated: the old follow is removed and a new `Follow`
/// is sent to the target actor.
pub async fn handle_inbound_move(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let source_uri = &activity.actor;
    let object_uri = activity
        .object
        .as_str()
        .ok_or_else(|| NoombatError::BadRequest("Move: object must be a string URI".into()))?;

    // Step 1: actor == object.
    if source_uri != object_uri {
        return Err(NoombatError::BadRequest(
            "Move: actor and object must match".into(),
        ));
    }

    // Extract the target URI from the `target` field of the Move activity.
    let target_uri = activity
        .target
        .as_deref()
        .ok_or_else(|| NoombatError::BadRequest("Move: missing target field".into()))?;

    info!(
        source = %source_uri,
        target = %target_uri,
        "processing inbound Move"
    );

    // Step 2: fetch the target actor and check alsoKnownAs.
    // Use a signed fetch so that instances requiring authenticated
    // requests (e.e. GotoSocial) do not reject the lookup.
    let signing_actor_id = find_local_signing_actor(pool).await?;

    let target_response =
        crate::signed_fetch::signed_get(pool, http_client, target_uri, signing_actor_id).await?;

    if !target_response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "target actor returned HTTP {}",
            target_response.status()
        )));
    }

    let target_profile: serde_json::Value = target_response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("invalid target actor JSON: {e}")))?;

    let aliases = target_profile
        .get("alsoKnownAs")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    if !aliases.contains(&source_uri.as_str()) {
        warn!(
            source = %source_uri,
            target = %target_uri,
            "Move rejected: target does not list source in alsoKnownAs"
        );
        return Err(NoombatError::Federation(
            "Move rejected: target actor does not list source as alias".into(),
        ));
    }

    // Resolve the source actor locally.
    let source_actor = resolve_actor(pool, http_client, source_uri).await?;

    // Record the move on the cached remote actor.
    sqlx::query("UPDATE actors SET moved_to = $1 WHERE id = $2")
        .bind(target_uri)
        .bind(source_actor.id)
        .execute(pool)
        .await?;

    // Migrate local followers: for each local actor that follows the
    // source, unfollow the source and send a Follow to the target.
    let local_follower_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT f.follower_id FROM follows f \
         JOIN actors a ON a.id = f.follower_id \
         WHERE f.following_id = $1 AND a.is_local = TRUE AND f.accepted = TRUE",
    )
    .bind(source_actor.id)
    .fetch_all(pool)
    .await?;

    // Resolve the target actor so that we have its inbox.
    let target_actor = resolve_actor(pool, http_client, target_uri).await?;
    let target_inbox = target_actor
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{target_uri}/inbox"));

    for follower_id in &local_follower_ids {
        // Remove the old follow.
        noombat_identity::repo::delete_follow(pool, *follower_id, source_actor.id).await?;

        // Look up the follower's AP ID for the Follow activity.
        let follower = match noombat_identity::repo::find_by_id(pool, *follower_id).await {
            Ok(a) => a,
            Err(e) => {
                warn!(follower_id = %follower_id, error = %e, "failed to look up follower; skipping");
                continue;
            }
        };

        // Send a Follow to the target.
        let follow_id = format!(
            "{}#move-follow-{}",
            follower.ap_id,
            chrono::Utc::now().timestamp_millis()
        );
        let follow_activity = json!({
            "@context": default_context(),
            "id": follow_id,
            "type": "Follow",
            "actor": follower.ap_id,
            "object": target_uri,
        });

        if let Err(e) = delivery::enqueue(pool, *follower_id, &follow_activity, &target_inbox).await
        {
            warn!(
                follower = %follower.ap_id,
                target = %target_uri,
                error = %e,
                "failed to enqueue move-follow"
            );
        }
    }

    info!(
        source = %source_uri,
        target = %target_uri,
        migrated_followers = local_follower_ids.len(),
        "inbound Move processed; followers migrated"
    );

    Ok(())
}

/// Find any local actor with a private key to use for signed fetches.
///
/// Delegates to [`crate::signed_fetch::find_local_signing_actor`],
/// the shared implementation used across the federation crate.
async fn find_local_signing_actor(pool: &PgPool) -> Result<Uuid> {
    crate::signed_fetch::find_local_signing_actor(pool).await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn insert_actor(pool: &PgPool, username: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO actors
                   (actor_type, ap_id, username, domain, public_key_pem, is_local)
               VALUES ('individual', $1, $2, 'noombat.example', 'KEY', TRUE)
               RETURNING id"#,
        )
        .bind(format!("https://noombat.example/users/{username}"))
        .bind(username)
        .fetch_one(pool)
        .await
        .expect("actor fixture inserted")
    }

    /// An applicant, an application, and one active grant.
    async fn insert_grant(pool: &PgPool, applicant: Uuid, suffix: &str) -> Uuid {
        let recruiter = insert_actor(pool, &format!("recruiter{suffix}")).await;
        let listing = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO job_listings (actor_id, ap_id, title, description_md, description_html) \
             VALUES ($1, $2, 'Engineer', 'md', '<p>md</p>') RETURNING id",
        )
        .bind(recruiter)
        .bind(format!("https://noombat.example/jobs/{suffix}"))
        .fetch_one(pool)
        .await
        .expect("listing fixture inserted");

        let application = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO applications \
                 (applicant_id, job_listing_id, listing_title, listing_company, ap_id) \
             VALUES ($1, $2, 'Engineer', 'Acme', $3) RETURNING id",
        )
        .bind(applicant)
        .bind(listing)
        .bind(format!("https://noombat.example/applications/{suffix}"))
        .fetch_one(pool)
        .await
        .expect("application fixture inserted");

        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO application_grants \
                 (application_id, token_hash, audience_ap_id, audience_origin, \
                  expires_at, document_uses_remaining, cv_uses_remaining) \
             VALUES ($1, $2, 'https://acme.example/actor', 'https://acme.example', \
                     now() + interval '7 days', 5, 5) RETURNING id",
        )
        .bind(application)
        .bind(format!("hash-{suffix}"))
        .fetch_one(pool)
        .await
        .expect("grant fixture inserted")
    }

    async fn grant_state(pool: &PgPool, id: Uuid) -> (String, Option<String>) {
        sqlx::query_as("SELECT state, revoked_reason FROM application_grants WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("grant readable")
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_marks_active_grants_migrated(pool: PgPool) {
        let applicant = insert_actor(&pool, "alice").await;
        let grant = insert_grant(&pool, applicant, "a").await;

        let revoked = revoke_grants_for_migration(&pool, applicant)
            .await
            .expect("revocation ran");

        assert_eq!(revoked, 1);
        let (state, reason) = grant_state(&pool, grant).await;
        assert_eq!(state, "revoked");
        // Not `applicant_withdrew`: the applicant withdrew nothing.
        assert_eq!(reason.as_deref(), Some("account_migrated"));
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_leaves_another_applicants_grants_alone(pool: PgPool) {
        let alice = insert_actor(&pool, "alice").await;
        let bob = insert_actor(&pool, "bob").await;
        let alice_grant = insert_grant(&pool, alice, "a").await;
        let bob_grant = insert_grant(&pool, bob, "b").await;

        let revoked = revoke_grants_for_migration(&pool, alice)
            .await
            .expect("revocation ran");

        assert_eq!(revoked, 1, "only alice's grant should be revoked");
        assert_eq!(grant_state(&pool, alice_grant).await.0, "revoked");
        assert_eq!(grant_state(&pool, bob_grant).await.0, "active");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_already_revoked_grant_keeps_its_first_reason(pool: PgPool) {
        // A migration must not rewrite an earlier revocation's reason.
        let applicant = insert_actor(&pool, "alice").await;
        let grant = insert_grant(&pool, applicant, "a").await;
        sqlx::query(
            "UPDATE application_grants SET state = 'revoked', revoked_at = now(), \
             revoked_reason = 'applicant_withdrew' WHERE id = $1",
        )
        .bind(grant)
        .execute(&pool)
        .await
        .expect("pre-revoked");

        let revoked = revoke_grants_for_migration(&pool, applicant)
            .await
            .expect("revocation ran");

        assert_eq!(revoked, 0);
        assert_eq!(
            grant_state(&pool, grant).await.1.as_deref(),
            Some("applicant_withdrew")
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn initiating_a_move_revokes_the_grants(pool: PgPool) {
        // The wiring, not the query.
        let applicant = insert_actor(&pool, "alice").await;
        let grant = insert_grant(&pool, applicant, "a").await;

        initiate_move(
            &pool,
            applicant,
            "https://noombat.example/users/alice",
            "https://elsewhere.example/users/alice",
        )
        .await
        .expect("move initiated");

        assert_eq!(grant_state(&pool, grant).await.0, "revoked");
    }
}
