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

use std::time::Duration;

use http_signature_normalization_reqwest::prelude::*;
use noombat_core::error::{NoombatError, Result};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

/// Find any local actor with a private key to use for signed fetches.
///
/// Prefers an admin actor; falls back to any local actor with a
/// private key. Returns an error if no suitable actor exists (which
/// would mean the instance has no local actors at all, an unlikely
/// but possible state during initial setup).
///
/// This function is shared across the federation crate: it is used
/// by `signed_get`, `handle_update_actor` (in `crate::inbox`), and
/// `handle_inbound_move` (in `crate::move_actor`).
pub async fn find_local_signing_actor(pool: &PgPool) -> Result<Uuid> {
    // Try admins first (they are most likely to exist on any instance).
    let admin: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM actors \
         WHERE is_local = TRUE AND private_key_pem IS NOT NULL \
           AND instance_role = 'admin' \
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(NoombatError::from)?;

    if let Some(id) = admin {
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
/// Falls back to an unsigned fetch if the signing key is unavailable.
///
/// **Note:** The returned [`reqwest::Response`] may carry a non-success
/// HTTP status. The caller is responsible for checking
/// `response.status().is_success()` and handling errors as appropriate
/// (e.g. distinguishing 404 from 410 from 5xx).
///
/// # Arguments
///
/// * `pool`: Database connection pool (used to look up the signing key).
/// * `http_client`: The HTTP client for the outbound request.
/// * `url`: The URL to fetch.
/// * `signing_actor_id`: UUID of the local actor whose key is used
///   for signing.
pub async fn signed_get(
    pool: &PgPool,
    http_client: &reqwest::Client,
    url: &str,
    signing_actor_id: Uuid,
) -> Result<reqwest::Response> {
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
            // No signing key available; fall back to unsigned fetch.
            warn!(
                url,
                "signed_get: no private key available; falling back to unsigned fetch"
            );
            return unsigned_get(http_client, url).await;
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
            warn!(
                url,
                "signed_get: signing failed ({e}); falling back to unsigned fetch"
            );
            return unsigned_get(http_client, url).await;
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
    http_client
        .get(url)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("fetch of {url} failed: {e}")))
}
