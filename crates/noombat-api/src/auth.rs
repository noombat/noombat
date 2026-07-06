// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared authentication helpers.
//!
//! Centralises the development-only bearer-token check.

use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use noombat_core::error::NoombatError;

/// Verify that the request carries an `Authorization: Bearer <token>`
/// header matching the configured admin token.
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

    if token != expected {
        return Err(NoombatError::Forbidden);
    }
    Ok(())
}
