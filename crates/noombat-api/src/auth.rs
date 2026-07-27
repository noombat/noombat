// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared authentication helpers.
//!
//! Centralises the development-only bearer-token check.

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use hmac::{Hmac, Mac};
use noombat_core::error::NoombatError;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Fixed domain-separation tag used as the HMAC message. The tag
/// itself is not secret; its purpose is to ensure the HMAC output is
/// specific to this comparison context.
const HMAC_TAG: &[u8] = b"noombat-bearer-token-verify";

/// Constant-time token comparison that does not leak the length of
/// the expected secret.
///
/// Both values are hashed with HMAC-SHA256 (keyed by each value,
/// message = [`HMAC_TAG`]) to produce fixed-length (32-byte) digests
/// before comparison. This eliminates the length oracle inherent in
/// comparing variable-length byte slices, regardless of whether the
/// underlying constant-time primitive short-circuits on length
/// mismatch.
pub fn constant_time_token_eq(a: &str, b: &str) -> bool {
    let mut mac_a =
        HmacSha256::new_from_slice(a.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac_a.update(HMAC_TAG);
    let digest_a = mac_a.finalize().into_bytes();

    let mut mac_b =
        HmacSha256::new_from_slice(b.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac_b.update(HMAC_TAG);
    let digest_b = mac_b.finalize().into_bytes();

    use subtle::ConstantTimeEq;
    digest_a.ct_eq(&digest_b).into()
}

/// Verify that the request carries an `Authorization: Bearer <token>`
/// header matching the configured admin token.
///
/// The comparison uses [`constant_time_token_eq`] (HMAC-SHA256 digest
/// comparison) to prevent both timing and length oracle attacks.
///
/// Returns `Err(Forbidden)` if no admin token is configured, if the
/// header is absent or malformed, or if the token does not match.
pub fn verify_bearer_token(
    headers: &HeaderMap,
    expected: &Option<String>,
) -> Result<(), NoombatError> {
    let expected = expected.as_deref().ok_or(NoombatError::Forbidden)?;

    let header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(NoombatError::Forbidden)?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or(NoombatError::Forbidden)?;

    if !constant_time_token_eq(token, expected) {
        return Err(NoombatError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_tokens_match() {
        assert!(constant_time_token_eq("secret-token-42", "secret-token-42"));
    }

    #[test]
    fn unequal_tokens_do_not_match() {
        assert!(!constant_time_token_eq("correct-token", "wrong-token"));
    }

    #[test]
    fn different_length_tokens_do_not_match() {
        assert!(!constant_time_token_eq(
            "short",
            "a-much-longer-token-value"
        ));
    }

    #[test]
    fn empty_tokens_match() {
        assert!(constant_time_token_eq("", ""));
    }
}
