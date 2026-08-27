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
