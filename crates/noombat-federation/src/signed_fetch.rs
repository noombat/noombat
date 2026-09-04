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

/// The most of a peer's URL worth repeating back in an error message.
const URL_IN_MESSAGE: usize = 200;

/// Render a peer-supplied URL for an error message.
///
/// Two reasons not to interpolate it directly. `Debug` escapes a control
/// character that `Display` would write raw, and these messages are built
/// before anything has decided where they will be read: an error string
/// carrying a newline forges a line in whatever log receives it. The
/// length is the peer's choice too, and the failing URL is recognisable
/// long before its two-hundredth character.
fn in_message(url: &str) -> String {
    match url.char_indices().nth(URL_IN_MESSAGE) {
        Some((cut, _)) => format!("{:?}...", &url[..cut]),
        None => format!("{url:?}"),
    }
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
    crate::http::check_url(&reqwest::Url::parse(url).map_err(|e| {
        NoombatError::BadRequest(format!("unusable URI {}: {e}", in_message(url)))
    })?)?;

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
                // `?url` rather than the bare field: Debug escapes, and a
                // peer chooses this string.
                warn!(
                    url = ?url,
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
                    url = ?url,
                    "signed_get: signing failed ({e}); falling back to unsigned fetch"
                );
                return unsigned_get(http_client, url).await;
            }
            return Err(NoombatError::Federation(format!(
                "signed_get: signing failed and unsigned fallback is disabled: {e}"
            )));
        }
    };

    http_client.execute(signed_request).await.map_err(|e| {
        NoombatError::Federation(format!("signed fetch of {} failed: {e}", in_message(url)))
    })
}

/// Unsigned GET with the ActivityPub Accept header.
///
/// **Note:** The returned [`reqwest::Response`] may carry a non-success
/// HTTP status. The caller is responsible for status checking.
async fn unsigned_get(http_client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    crate::http::guarded_get(http_client, url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // The guard is the first statement in `signed_get`, before the pool
    // is touched, so a lazy pool never opens a socket. Asserting only
    // that the call failed would pass with no guard at all, because the
    // address is unroutable either way: the reason is the assertion.
    #[tokio::test]
    async fn signed_get_refuses_a_private_address_before_touching_the_database() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://noombat:noombat@127.0.0.1:1/absent")
            .expect("a lazy pool needs no server");

        let error = super::signed_get(
            &pool,
            &reqwest::Client::new(),
            "https://169.254.169.254/latest/meta-data/",
            uuid::Uuid::nil(),
        )
        .await
        .expect_err("a link-local address must be refused");

        let reason = error.to_string();
        assert!(
            reason.contains("private or reserved address"),
            "refused for the wrong reason, so the guard may not have run: {reason}"
        );
    }

    #[test]
    fn a_newline_cannot_forge_a_log_line() {
        let forged = in_message("https://a.test/x\nERROR peer is trusted");
        assert!(
            !forged.contains('\n'),
            "a raw newline survived into the message: {forged}"
        );
        assert!(
            forged.contains("\\n"),
            "the newline should be escaped, not dropped: {forged}"
        );
    }

    #[test]
    fn a_carriage_return_and_a_quote_are_escaped_too() {
        let shown = in_message("https://a.test/\r\"");
        assert!(
            !shown.contains('\r'),
            "a raw carriage return survived: {shown}"
        );
        assert!(shown.contains("\\r") && shown.contains("\\\""), "{shown}");
    }

    #[test]
    fn a_long_url_is_cut_to_a_bounded_length() {
        let long = format!("https://a.test/{}", "x".repeat(5_000));
        let shown = in_message(&long);
        assert!(
            shown.len() < long.len() / 2,
            "the message grew with the peer's URL: {} chars",
            shown.len()
        );
        assert!(
            shown.ends_with("\"..."),
            "a cut value should say so: {shown}"
        );
    }

    #[test]
    fn an_ordinary_url_is_shown_whole() {
        let shown = in_message("https://a.test/users/bob");
        assert_eq!(shown, "\"https://a.test/users/bob\"");
    }

    // A cut must count characters, not bytes. Counting bytes keeps the
    // wrong amount and, where the offset falls inside a character,
    // panics instead of truncating. Asserting only "it did not panic"
    // passes whenever the byte offset happens to land on a boundary,
    // which is half the time, so count what was kept.
    #[test]
    fn a_multibyte_url_is_cut_on_a_character_boundary() {
        let wide = format!("https://a.test/{}", "é".repeat(5_000));
        let shown = in_message(&wide);
        assert!(shown.ends_with("\"..."), "{shown}");

        let kept = shown.trim_end_matches("...").trim_matches('"');
        assert_eq!(
            kept.chars().count(),
            URL_IN_MESSAGE,
            "the cut kept the wrong number of characters: {shown}"
        );
    }
}
