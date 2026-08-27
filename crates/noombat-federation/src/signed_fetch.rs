// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Signed HTTP fetch for authenticated retrieval of remote ActivityPub
//! resources.
//!
//! Instances that require signed fetches (e.g. GotoSocial with
//! `accounts-allow-incoming-from-known-instances-only`) reject
//! unsigned GET requests for actor profiles. This module provides a
//! helper that attaches an HTTP Signature to outbound GET requests,
//! using a local actor's RSA private key.

use std::sync::OnceLock;
use std::time::Duration;

use http_signature_normalization_reqwest::prelude::*;
use noombat_core::error::{NoombatError, Result};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

// ..... Process-global unsigned-fetch policy .....

/// Whether `signed_get` falls back to an unsigned GET when the
/// signing key is unavailable or signing fails. Set once at startup
/// via [`set_allow_unsigned_fetch`]; defaults to `false`.
static ALLOW_UNSIGNED_FETCH: OnceLock<bool> = OnceLock::new();

/// Set the process-global unsigned-fetch policy.
///
/// Must be called before any federation activity is processed.
/// Passing `true` enables the unsigned fallback (not recommended
/// for production).
pub fn set_allow_unsigned_fetch(allow: bool) {
    let _ = ALLOW_UNSIGNED_FETCH.set(allow);
}

fn allow_unsigned_fallback() -> bool {
    ALLOW_UNSIGNED_FETCH.get().copied().unwrap_or(false)
}

/// Find the actor whose key signs server-to-server fetches.
///
/// The instance actor, where one exists: a signed fetch tells the peer who
/// asked, and signing as an administrator names a privileged account to
/// every host this instance fetches from, including hosts chosen by the
/// party being fetched.
///
/// Falls back to any local actor with a key, because an instance mid-setup
/// may not have minted one yet. `ensure_instance_actor` runs at boot, so
/// that is a window rather than a resting state.
///
/// This function is shared across the federation crate: it is used
/// by `signed_get`, `handle_update_actor` (in `crate::inbox`), and
/// `handle_inbound_move` (in `crate::move_actor`).
pub async fn find_local_signing_actor(pool: &PgPool) -> Result<Uuid> {
    let instance: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM actors \
         WHERE is_local = TRUE AND private_key_pem IS NOT NULL \
           AND actor_type = 'application' \
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(NoombatError::from)?;

    if let Some(id) = instance {
        return Ok(id);
    }

    // Fall back to any local actor with a key.
    let any: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM actors \
         WHERE is_local = TRUE AND private_key_pem IS NOT NULL \
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(NoombatError::from)?;

    any.ok_or_else(|| {
        NoombatError::Internal(
            "no local actor with a private key available for signed fetch".into(),
        )
    })
}

/// Fetch a remote resource with an HTTP Signature attached.
///
/// Uses the specified local actor's private key to sign the request.
///
/// When the process-global unsigned-fetch policy (set via
/// [`set_allow_unsigned_fetch`]) is `true`, falls back to an unsigned
/// GET if the signing key is unavailable or signing fails. When
/// `false` (the default), these conditions return an error.
///
/// **Note:** The returned [`reqwest::Response`] may carry a non-success
/// HTTP status. The caller is responsible for checking
/// `response.status().is_success()` and handling errors as appropriate
/// (e.g. distinguishing 404 from 410 from 5xx).
pub async fn signed_get(
    pool: &PgPool,
    http_client: &reqwest::Client,
    url: &str,
    signing_actor_id: Uuid,
) -> Result<reqwest::Response> {
    // Checked here as well as in `unsigned_get`, because the signed path
    // below does not go through it and is the one the inbox uses.
    crate::http::check_url(
        &reqwest::Url::parse(url)
            .map_err(|e| NoombatError::BadRequest(format!("unusable URI {url}: {e}")))?,
    )?;

    let fallback = allow_unsigned_fallback();
    // Look up the signing actor's AP ID and private key.
    let row = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT ap_id, private_key_pem FROM actors WHERE id = $1",
    )
    .bind(signing_actor_id)
    .fetch_optional(pool)
    .await
    .map_err(NoombatError::from)?;

    let (ap_id, sealed_pem) = match row {
        Some((ap_id, Some(pem))) => (ap_id, pem),
        _ => {
            if fallback {
                warn!(
                    url,
                    "signed_get: no private key available; falling back to unsigned fetch"
                );
                return unsigned_get(http_client, url).await;
            }
            return Err(NoombatError::Federation(
                "signed_get: no private key available and unsigned fallback is disabled".into(),
            ));
        }
    };

    // Decrypt the private key from the database.
    let private_key_pem = noombat_core::envelope::open_auto(&sealed_pem)?;

    let key_id = format!("{ap_id}#main-key");

    // Build the signing config for GET requests. Unlike POST
    // deliveries, GET requests have no body, so `require_digest()`
    // is not used.
    let config: Config = Config::default()
        .mastodon_compat()
        .set_expiration(Duration::from_secs(30));

    let signed_request = http_client
        .get(url)
        .header("Accept", "application/activity+json")
        .signature(&config, key_id, move |signing_string| {
            crate::delivery::rsa_sha256_sign(signing_string, &private_key_pem)
        })
        .await;

    let signed_request = match signed_request {
        Ok(r) => r,
        Err(e) => {
            if fallback {
                warn!(
                    url,
                    "signed_get: signing failed ({e}); falling back to unsigned fetch"
                );
                return unsigned_get(http_client, url).await;
            }
            return Err(NoombatError::Federation(format!(
                "signed_get: signing failed and unsigned fallback is disabled: {e}"
            )));
        }
    };

    http_client
        .execute(signed_request)
        .await
        .map_err(|e| NoombatError::Federation(format!("signed fetch of {url} failed: {e}")))
}

/// Unsigned GET with the ActivityPub Accept header.
///
/// **Note:** The returned [`reqwest::Response`] may carry a non-success
/// HTTP status. The caller is responsible for status checking.
async fn unsigned_get(http_client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    crate::http::guarded_get(http_client, url).await
}
