// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Local login: verifies the authentication key against the stored
//! Argon2id hash.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use noombat_core::actor::InstanceRole;
use noombat_core::error::{NoombatError, Result};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Request body for `POST /api/v1/auth/login`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    /// Hex-encoded authentication key (32 bytes / 64 hex chars).
    pub auth_key: String,
    /// Optional TOTP code when 2FA is enrolled.
    pub totp_code: Option<String>,
}

/// Authenticate a local user by verifying the authentication key.
///
/// Returns `(actor_id, username, role)` on success.
///
/// # Errors
///
/// Returns `Forbidden` if the username is unknown, the account has no
/// password (OAuth-only), or the authentication key does not match.
pub async fn verify_credentials(
    pool: &PgPool,
    req: &LoginRequest,
) -> Result<(Uuid, String, InstanceRole, bool)> {
    // Fetch the stored hash. The query deliberately excludes
    // suspended actors (login is disabled for them).
    let row = sqlx::query_as::<_, (Uuid, String, Option<String>, InstanceRole)>(
        r#"SELECT a.id, a.username, a.auth_key_hash, a.instance_role
           FROM actors a
           WHERE a.username = $1
             AND a.is_local = TRUE
             AND a.actor_status != 'suspended'"#,
    )
    .bind(&req.username)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::Forbidden)?;

    let (actor_id, username, auth_key_hash_opt, role) = row;

    let auth_key_hash = auth_key_hash_opt.ok_or(NoombatError::Forbidden)?;

    // Check whether TOTP is enrolled and verified.
    let has_totp = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM totp_secrets WHERE actor_id = $1 AND verified = TRUE)",
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .unwrap_or(false);

    // Verify the authentication key against the Argon2id hash.
    // Offload to a blocking thread to avoid starving the Tokio runtime.
    let auth_key = req.auth_key.clone();
    let hash_clone = auth_key_hash.clone();
    let valid = tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&hash_clone).map_err(|_| NoombatError::Forbidden)?;
        Argon2::default()
            .verify_password(auth_key.as_bytes(), &parsed)
            .map_err(|_| NoombatError::Forbidden)
    })
    .await
    .map_err(|e| NoombatError::Internal(format!("verify task failed: {e}")))?;

    valid?;

    // If TOTP is enrolled, verify the code.
    if has_totp {
        let totp_code = req
            .totp_code
            .as_deref()
            .ok_or_else(|| NoombatError::BadRequest("TOTP code required".into()))?;
        crate::totp::verify_totp(pool, actor_id, totp_code).await?;
    }

    Ok((actor_id, username, role, has_totp))
}
