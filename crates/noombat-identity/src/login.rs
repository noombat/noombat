// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Local login: verifies the authentication key against the stored
//! Argon2id hash.

use argon2::Argon2;
use argon2::password_hash::PasswordVerifier;
use argon2::password_hash::phc::PasswordHash;
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
/// Returns `(actor_id, username, role)` on success, and `Forbidden` for
/// all three failures alike: unknown username, an OAuth-only account with
/// no password, and a key that does not match.
pub async fn verify_credentials(
    pool: &PgPool,
    req: &LoginRequest,
) -> Result<(Uuid, String, InstanceRole, bool)> {
    // Fetch the stored hash. The query admits only actors who may sign in,
    // stated as an allowlist rather than as `!= 'suspended'`: a status added
    // later is refused by default, and the pending state that admission
    // introduced would otherwise have signed in like any other account.
    //
    // 'silenced' is admitted deliberately. Silencing withholds reach, not
    // access, so a silenced actor still logs in.
    let row = sqlx::query_as::<_, (Uuid, String, Option<String>, InstanceRole)>(
        r#"SELECT a.id, a.username, a.auth_key_hash, a.instance_role
           FROM actors a
           WHERE a.username = $1
             AND a.is_local = TRUE
             AND a.actor_status IN ('active', 'silenced')"#,
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

    hash_matches(auth_key_hash, req.auth_key.clone()).await?;

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

/// `Forbidden` unless `actor_id` is a local account that may sign in.
pub async fn may_sign_in(pool: &PgPool, actor_id: Uuid) -> Result<()> {
    let admitted: Option<bool> = sqlx::query_scalar(
        "SELECT actor_status IN ('active', 'silenced') FROM actors WHERE id = $1 AND is_local",
    )
    .bind(actor_id)
    .fetch_optional(pool)
    .await?;
    match admitted {
        Some(true) => Ok(()),
        _ => Err(NoombatError::Forbidden),
    }
}

/// Check that `auth_key` is the signed-in account's own, for a step that
/// asks for the password again. The session met any second factor at sign
/// in, so only the key is checked. `Forbidden` for a key that does not
/// match and for an account with no password.
pub async fn verify_auth_key(pool: &PgPool, actor_id: Uuid, auth_key: &str) -> Result<()> {
    let hash: Option<String> =
        sqlx::query_scalar("SELECT auth_key_hash FROM actors WHERE id = $1 AND is_local = TRUE")
            .bind(actor_id)
            .fetch_optional(pool)
            .await?
            .flatten();
    hash_matches(hash.ok_or(NoombatError::Forbidden)?, auth_key.to_owned()).await
}

/// `Forbidden` unless `auth_key` is the key `hash` was made from. On a
/// blocking thread, so the Argon2id work does not starve the runtime.
async fn hash_matches(hash: String, auth_key: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&hash).map_err(|_| NoombatError::Forbidden)?;
        Argon2::default()
            .verify_password(auth_key.as_bytes(), &parsed)
            .map_err(|_| NoombatError::Forbidden)
    })
    .await
    .map_err(|e| NoombatError::Internal(format!("verify task failed: {e}")))?
}
