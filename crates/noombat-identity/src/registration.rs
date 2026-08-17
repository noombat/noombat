// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Local account registration with split key derivation.
//!
//! The client derives an authentication key from the user's password
//! via PBKDF2-SHA256 to HKDF-Expand("noombat-auth") and sends it to
//! the server. The server hashes it with Argon2id and stores the
//! result. The blob-encryption key (HKDF-Expand("noombat-chat-crypto"))
//! never leaves the browser.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};
use noombat_core::actor::{ActorType, NewActor};
use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;

use crate::keys;

/// Request body for `POST /api/v1/auth/register`.
///
/// The `auth_key` field is the authentication key derived client-side
/// via split key derivation. It is *not* the user's password.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub display_name: Option<String>,
    /// The authentication key (hex-encoded, 32 bytes / 64 hex chars),
    /// derived client-side from the user's password via
    /// PBKDF2-SHA256 to HKDF-Expand("noombat-auth").
    pub auth_key: String,
}

/// Response body for a successful registration.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub actor_id: uuid::Uuid,
    pub username: String,
    pub ap_id: String,
}

/// Validate a proposed username.
///
/// Usernames must be 1 to 30 characters, consist solely of ASCII
/// lowercase letters, digits, and underscores, and must begin with a
/// letter.
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() || username.len() > 30 {
        return Err(NoombatError::BadRequest(
            "username must be 1-30 characters".into(),
        ));
    }
    let mut chars = username.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(NoombatError::BadRequest(
            "username must begin with a lowercase letter".into(),
        ));
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err(NoombatError::BadRequest(
            "username may contain only lowercase letters, digits, and underscores".into(),
        ));
    }
    Ok(())
}

/// Validate the auth key format (hex-encoded, 32 bytes).
fn validate_auth_key(auth_key: &str) -> Result<()> {
    if auth_key.len() != 64 {
        return Err(NoombatError::BadRequest(
            "auth_key must be 64 hex characters (32 bytes)".into(),
        ));
    }
    if !auth_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NoombatError::BadRequest(
            "auth_key must be hex-encoded".into(),
        ));
    }
    Ok(())
}

/// Hash an authentication key with Argon2id.
///
/// Returns the PHC-formatted hash string.
pub fn hash_auth_key(auth_key: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(auth_key.as_bytes(), &salt)
        .map_err(|e| NoombatError::Internal(format!("Argon2id hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Register a new local account.
///
/// `ActorAlreadyExists` if the username is taken, `BadRequest` if the
/// username or authentication key is invalid.
pub async fn register(
    pool: &PgPool,
    domain: &str,
    req: &RegisterRequest,
) -> Result<RegisterResponse> {
    validate_username(&req.username)?;
    validate_auth_key(&req.auth_key)?;

    // Check uniqueness before generating keys (which is expensive).
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM actors WHERE username = $1 AND domain = $2 AND is_local = TRUE)",
    )
    .bind(&req.username)
    .bind(domain)
    .fetch_one(pool)
    .await?;

    if exists {
        return Err(NoombatError::ActorAlreadyExists(req.username.clone()));
    }

    // Generate key material (offloaded to a blocking thread).
    let keypair = keys::generate_keypair_async().await?;

    // Hash the authentication key with Argon2id.
    let auth_key_clone = req.auth_key.clone();
    let auth_key_hash = tokio::task::spawn_blocking(move || hash_auth_key(&auth_key_clone))
        .await
        .map_err(|e| NoombatError::Internal(format!("hash task failed: {e}")))?
        .map_err(|e| NoombatError::Internal(format!("hash failed: {e}")))?;

    // Create the actor.
    let new_actor = NewActor {
        actor_type: ActorType::Individual,
        username: req.username.clone(),
        display_name: req.display_name.clone(),
        domain: domain.to_owned(),
        public_key_pem: keypair.rsa.public_pem,
        private_key_pem: keypair.rsa.private_pem,
        ed25519_public_key: keypair.ed25519.public_multibase,
        ed25519_private_key: keypair.ed25519.private_base64,
    };

    // Create the actor and store the auth_key_hash atomically.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| NoombatError::Internal(format!("transaction begin failed: {e}")))?;

    let actor = match crate::repo::create_actor_tx(&mut tx, &new_actor).await {
        Ok(a) => a,
        Err(NoombatError::Database(ref e))
            if e.as_database_error()
                .and_then(|dbe| dbe.code())
                .map(|c| c == "23505")
                .unwrap_or(false) =>
        {
            return Err(NoombatError::ActorAlreadyExists(req.username.clone()));
        }
        Err(e) => return Err(e),
    };

    sqlx::query("UPDATE actors SET auth_key_hash = $1 WHERE id = $2")
        .bind(&auth_key_hash)
        .bind(actor.id)
        .execute(&mut *tx)
        .await?;

    tx.commit()
        .await
        .map_err(|e| NoombatError::Internal(format!("transaction commit failed: {e}")))?;

    info!(username = %actor.username, "local account registered");

    Ok(RegisterResponse {
        actor_id: actor.id,
        username: actor.username,
        ap_id: actor.ap_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("alice_bob").is_ok());
        assert!(validate_username("a123").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn invalid_usernames() {
        assert!(validate_username("").is_err());
        assert!(validate_username("Alice").is_err());
        assert!(validate_username("1alice").is_err());
        assert!(validate_username("alice-bob").is_err());
        assert!(validate_username("alice.bob").is_err());
        assert!(validate_username(&"a".repeat(31)).is_err());
    }

    #[test]
    fn valid_auth_key() {
        let key = "a".repeat(64);
        assert!(validate_auth_key(&key).is_ok());
    }

    #[test]
    fn invalid_auth_key_length() {
        assert!(validate_auth_key("abcd").is_err());
    }

    #[test]
    fn invalid_auth_key_chars() {
        let key = "g".repeat(64);
        assert!(validate_auth_key(&key).is_err());
    }

    #[test]
    fn argon2_hash_roundtrip() {
        use argon2::password_hash::PasswordVerifier;
        let auth_key = "ab".repeat(32);
        let hash = hash_auth_key(&auth_key).unwrap();
        let parsed = argon2::password_hash::PasswordHash::new(&hash).unwrap();
        assert!(
            Argon2::default()
                .verify_password(auth_key.as_bytes(), &parsed)
                .is_ok()
        );
    }
}
