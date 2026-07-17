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
