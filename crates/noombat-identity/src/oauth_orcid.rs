// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! "Sign in with ORCID" via OAuth 2.0 / OIDC.
//!
//! Flow:
//! 1. The user clicks "Sign in with ORCID."
//! 2. Noombat redirects to `https://orcid.org/oauth/authorize`.
//! 3. On callback, Noombat exchanges the code for an access token and
//!    the authenticated ORCID iD.
//! 4. The ORCID iD is stored in the `orcid` column; if no local
//!    account exists, one is created.

use noombat_core::actor::{ActorType, NewActor};
use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::keys;

/// ORCID OAuth configuration.
#[derive(Debug, Clone)]
pub struct OrcidConfig {
    pub client_id: String,
    pub client_secret: String,
    /// The base URI of the ORCID API (default: `https://orcid.org`).
    pub base_uri: String,
    /// The base URI of the ORCID public API (default: `https://pub.orcid.org`).
    pub pub_api_uri: String,
}

impl Default for OrcidConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            base_uri: "https://orcid.org".to_owned(),
            pub_api_uri: "https://pub.orcid.org".to_owned(),
        }
    }
}

/// Response from `POST /oauth/token` on ORCID.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields deserialised from the ORCID token response.
struct OrcidTokenResponse {
    access_token: String,
    orcid: String,
    name: Option<String>,
}

/// The result of a successful ORCID OAuth callback.
#[derive(Debug, Serialize)]
pub struct OrcidAuthResult {
    pub actor_id: Uuid,
    pub username: String,
    pub orcid: String,
    pub is_new: bool,
}

/// Build the ORCID authorisation URL.
///
/// `link_actor_id` is `Some` when an account that already exists is adding
/// ORCID as a second way in, and `None` when this is a sign-in. It is taken
/// from the session that starts the flow and recorded here, never read back
/// from the redirect: a callback that took the account to link from
/// anything it received would let an attacker attach their own ORCID to
/// somebody else's account by handing them a link.
///
/// Returns `(authorise_url, state_token)`.
pub async fn build_authorise_url(
    pool: &PgPool,
    orcid_config: &OrcidConfig,
    our_domain: &str,
    link_actor_id: Option<Uuid>,
) -> Result<(String, String)> {
    let redirect_uri = format!("https://{our_domain}/api/v1/auth/orcid/callback");
    let state = crate::oauth_util::generate_state_token();

    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
    sqlx::query(
        r#"INSERT INTO oauth_states (state, provider, instance_domain, link_actor_id, expires_at)
           VALUES ($1, 'orcid', NULL, $2, $3)"#,
    )
    .bind(&state)
    .bind(link_actor_id)
    .bind(expires)
    .execute(pool)
    .await?;

    let url = format!(
        "{}/oauth/authorize?client_id={}&response_type=code&scope=/authenticate&redirect_uri={}&state={state}",
        orcid_config.base_uri,
        crate::oauth_util::urlencoding(&orcid_config.client_id),
        crate::oauth_util::urlencoding(&redirect_uri),
    );

    Ok((url, state))
}

/// Handle the OAuth callback from ORCID.
pub async fn handle_callback(
    pool: &PgPool,
    http_client: &reqwest::Client,
    orcid_config: &OrcidConfig,
    our_domain: &str,
    code: &str,
    state: &str,
) -> Result<OrcidAuthResult> {
    // Validate and consume the OAuth state, recovering the account to link
    // to if this flow was started as a link rather than as a sign-in.
    let (link_actor_id,) = sqlx::query_as::<_, (Option<Uuid>,)>(
        r#"DELETE FROM oauth_states
           WHERE state = $1 AND provider = 'orcid' AND expires_at > now()
           RETURNING link_actor_id"#,
    )
    .bind(state)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::Forbidden)?;

    let redirect_uri = format!("https://{our_domain}/api/v1/auth/orcid/callback");

    // Exchange the code for an access token.
    let token_resp = http_client
        .post(format!("{}/oauth/token", orcid_config.base_uri))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", orcid_config.client_id.as_str()),
            ("client_secret", orcid_config.client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("ORCID token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let body = token_resp.text().await.unwrap_or_default();
        return Err(NoombatError::Federation(format!(
            "ORCID token exchange returned {status}: {body}"
        )));
    }

    let token: OrcidTokenResponse = token_resp
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("malformed ORCID token response: {e}")))?;

    // Check whether a local actor with this ORCID iD already exists.
    let existing = sqlx::query_as::<_, (Uuid, String)>(
        r#"SELECT a.id, a.username FROM actors a
           JOIN oauth_identities oi ON oi.actor_id = a.id
           WHERE oi.provider = 'orcid'
             AND oi.external_id = $1
             AND a.is_local = TRUE"#,
    )
    .bind(&token.orcid)
    .fetch_optional(pool)
    .await?;

    // Linking: attach this ORCID iD to the account that started the flow.
    if let Some(actor_id) = link_actor_id {
        if let Some((owner, _)) = existing {
            // One iD, one account. Silently re-pointing it would take the
            // second way in away from whoever holds it now.
            return Err(if owner == actor_id {
                NoombatError::BadRequest("that ORCID iD is already linked to this account".into())
            } else {
                NoombatError::BadRequest("that ORCID iD is linked to another account".into())
            });
        }

        let username =
            crate::oauth_util::link_identity(pool, actor_id, "orcid", &token.orcid).await?;

        // The iD also lives on the actor, for display and for the profile
        // import. Set after the link, so a refused link leaves nothing.
        sqlx::query("UPDATE actors SET orcid = $1, updated_at = now() WHERE id = $2")
            .bind(&token.orcid)
            .bind(actor_id)
            .execute(pool)
            .await?;

        info!(
            username = %username,
            orcid = %token.orcid,
            "ORCID linked to an existing account"
        );
        return Ok(OrcidAuthResult {
            actor_id,
            username,
            orcid: token.orcid,
            is_new: false,
        });
    }

    if let Some((actor_id, username)) = existing {
        return Ok(OrcidAuthResult {
            actor_id,
            username,
            orcid: token.orcid,
            is_new: false,
        });
    }

    // Create a new local actor.
    let base_username = derive_username_from_orcid(&token.orcid, token.name.as_deref());
    let final_username =
        crate::oauth_util::ensure_unique_username(pool, &base_username, our_domain).await?;

    let keypair = keys::generate_keypair_async().await?;

    let new_actor = NewActor {
        actor_type: ActorType::Individual,
        username: final_username.clone(),
        display_name: token.name.filter(|s| !s.is_empty()),
        domain: our_domain.to_owned(),
        public_key_pem: keypair.rsa.public_pem,
        private_key_pem: keypair.rsa.private_pem,
        ed25519_public_key: keypair.ed25519.public_multibase,
        ed25519_private_key: keypair.ed25519.private_base64,
    };

    let actor = crate::repo::create_actor(pool, &new_actor).await?;

    // Store the ORCID iD on the actor (for display and profile use).
    sqlx::query("UPDATE actors SET orcid = $1 WHERE id = $2")
        .bind(&token.orcid)
        .bind(actor.id)
        .execute(pool)
        .await?;

    // Record the OAuth identity linkage.
    sqlx::query(
        r#"INSERT INTO oauth_identities (actor_id, provider, external_id)
           VALUES ($1, 'orcid', $2)"#,
    )
    .bind(actor.id)
    .bind(&token.orcid)
    .execute(pool)
    .await?;

    info!(
        username = %final_username,
        orcid = %token.orcid,
        "ORCID OAuth account created"
    );

    Ok(OrcidAuthResult {
        actor_id: actor.id,
        username: final_username,
        orcid: token.orcid,
        is_new: true,
    })
}

// ..... Helpers .....

/// Derive a Noombat-compatible username from an ORCID iD or name.
fn derive_username_from_orcid(orcid: &str, name: Option<&str>) -> String {
    if let Some(name) = name {
        let sanitised: String = name
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .split('_')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("_");

        if !sanitised.is_empty() && sanitised.starts_with(|c: char| c.is_ascii_lowercase()) {
            let truncated: String = sanitised.chars().take(28).collect();
            return truncated;
        }
    }

    // Fallback: use the last four digits of the ORCID iD.
    let suffix: String = orcid
        .chars()
        .rev()
        .filter(|c| c.is_ascii_digit())
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    format!("orcid_{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_username_from_name() {
        let u = derive_username_from_orcid("0000-0002-1825-0097", Some("Jane Doe"));
        assert_eq!(u, "jane_doe");
    }

    #[test]
    fn derive_username_fallback() {
        let u = derive_username_from_orcid("0000-0002-1825-0097", None);
        assert_eq!(u, "orcid_0097");
    }

    #[test]
    fn derive_username_non_ascii_name() {
        let u = derive_username_from_orcid("0000-0002-1825-0097", Some("José García"));
        // Non-ASCII letters are replaced with underscores and collapsed.
        assert!(u.starts_with("jos"));
    }
}
