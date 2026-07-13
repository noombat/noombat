// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared authentication helpers.
//!
//! Centralises the development-only bearer-token check.

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use noombat_core::error::NoombatError;
use subtle::ConstantTimeEq;

/// Verify that the request carries an `Authorization: Bearer <token>`
/// header matching the configured admin token.
///
/// The comparison is performed in constant time (via the `subtle`
/// crate) to prevent timing side-channel attacks.
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

    if token.len() != expected.len() || token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1
    {
        return Err(NoombatError::Forbidden);
    }
    Ok(())
}
