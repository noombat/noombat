// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Session management: JWT access-token issuance and opaque
//! refresh-token lifecycle.
//!
//! Access tokens are short-lived JWTs (HS256) verified statelessly by
//! the middleware. Refresh tokens are opaque random strings persisted
//! in the `sessions` table, enabling explicit revocation.

use chrono::{TimeDelta, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use noombat_core::actor::InstanceRole;
use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Claims encoded in the JWT access token.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Subject: the actor's UUID.
    pub sub: String,
    /// Actor username.
    pub username: String,
    /// Instance role at token-issuance time.
    pub role: String,
    /// Audience: the instance domain that issued this token.
    ///
    /// Binds the token to a specific instance, preventing cross-
    /// instance token reuse when two instances share the same
    /// `jwt_secret` (misconfiguration defence).
    pub aud: String,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
}

/// The result of a successful authentication: an access/refresh token
/// pair plus the authenticated actor's identity.
#[derive(Debug, Serialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub actor_id: Uuid,
    pub username: String,
}

/// Configuration for session token lifetimes.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// JWT signing secret (HS256). Must be at least 32 bytes.
    pub jwt_secret: String,
    /// Instance domain, used as the `aud` (audience) claim.
    pub domain: String,
    /// Access-token lifetime in seconds (default: 900 = 15 min).
    pub access_ttl_secs: i64,
    /// Refresh-token lifetime in seconds (default: 2_592_000 = 30 days).
    pub refresh_ttl_secs: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            jwt_secret: String::new(),
            domain: "localhost".to_owned(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
        }
    }
}

/// Issue a new access/refresh token pair for the given actor.
pub async fn create_session(
    pool: &PgPool,
    config: &SessionConfig,
    actor_id: Uuid,
    username: &str,
    role: InstanceRole,
    user_agent: Option<&str>,
    ip_addr: Option<&str>,
) -> Result<SessionTokens> {
    let now = Utc::now();
    let access_exp = now + TimeDelta::seconds(config.access_ttl_secs);
    let refresh_exp = now + TimeDelta::seconds(config.refresh_ttl_secs);

    let role_str = match role {
        InstanceRole::User => "user",
        InstanceRole::Moderator => "moderator",
        InstanceRole::Admin => "admin",
    };

    let claims = AccessClaims {
        sub: actor_id.to_string(),
        username: username.to_owned(),
        role: role_str.to_owned(),
        aud: config.domain.clone(),
        iat: now.timestamp(),
        exp: access_exp.timestamp(),
    };

    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| NoombatError::Internal(format!("JWT encoding failed: {e}")))?;

    let refresh_token = generate_refresh_token();

    sqlx::query(
        r#"INSERT INTO sessions
               (actor_id, refresh_token, user_agent, ip_addr, expires_at)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(actor_id)
    .bind(&refresh_token)
    .bind(user_agent)
    .bind(ip_addr)
    .bind(refresh_exp)
    .execute(pool)
    .await?;

    Ok(SessionTokens {
        access_token,
        refresh_token,
        expires_in: config.access_ttl_secs,
        actor_id,
        username: username.to_owned(),
    })
}

/// Decode and validate an access token, returning the claims.
///
/// Validates the `aud` claim against the configured instance domain,
/// rejecting tokens issued for a different instance.
pub fn verify_access_token(token: &str, config: &SessionConfig) -> Result<AccessClaims> {
    let mut validation = Validation::default();
    validation.set_required_spec_claims(&["sub", "exp", "iat", "aud"]);
    validation.set_audience(&[&config.domain]);

    let data = decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| NoombatError::Forbidden)?;

    Ok(data.claims)
}

/// Refresh an expired access token using a valid refresh token.
///
/// Returns a new access/refresh token pair. The old refresh token is
/// revoked (single-use rotation).
pub async fn refresh_session(
    pool: &PgPool,
    config: &SessionConfig,
    old_refresh_token: &str,
) -> Result<SessionTokens> {
    // Find the session and verify it is not revoked or expired.
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, InstanceRole)>(
        r#"SELECT s.id, s.actor_id, a.username, a.instance_role
           FROM sessions s
           JOIN actors a ON a.id = s.actor_id
           WHERE s.refresh_token = $1
             AND s.revoked_at IS NULL
             AND s.expires_at > now()"#,
    )
    .bind(old_refresh_token)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::Forbidden)?;

    let (session_id, actor_id, username, role) = row;

    // Revoke the old refresh token (rotation).
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;

    create_session(pool, config, actor_id, &username, role, None, None).await
}

/// Revoke a session (logout).
pub async fn revoke_session(pool: &PgPool, refresh_token: &str) -> Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE refresh_token = $1")
        .bind(refresh_token)
        .execute(pool)
        .await?;
    Ok(())
}

/// Generate a cryptographically random opaque refresh token.
fn generate_refresh_token() -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SessionConfig {
        SessionConfig {
            jwt_secret: "test-secret-at-least-32-bytes-long!!".to_owned(),
            domain: "test.noombat.social".to_owned(),
            access_ttl_secs: 60,
            refresh_ttl_secs: 3600,
        }
    }

    #[test]
    fn jwt_roundtrip() {
        let config = test_config();
        let now = Utc::now();
        let claims = AccessClaims {
            sub: Uuid::new_v4().to_string(),
            username: "alice".to_owned(),
            role: "user".to_owned(),
            aud: "test.noombat.social".to_owned(),
            iat: now.timestamp(),
            exp: (now + TimeDelta::seconds(60)).timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .unwrap();

        let decoded = verify_access_token(&token, &config).unwrap();
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.aud, "test.noombat.social");
    }

    #[test]
    fn invalid_secret_rejects() {
        let config = test_config();
        let now = Utc::now();
        let claims = AccessClaims {
            sub: Uuid::new_v4().to_string(),
            username: "alice".to_owned(),
            role: "user".to_owned(),
            aud: "test.noombat.social".to_owned(),
            iat: now.timestamp(),
            exp: (now + TimeDelta::seconds(60)).timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"wrong-secret-wrong-secret-wrong!"),
        )
        .unwrap();

        assert!(verify_access_token(&token, &config).is_err());
    }

    #[test]
    fn wrong_audience_rejects() {
        let config = test_config();
        let now = Utc::now();
        let claims = AccessClaims {
            sub: Uuid::new_v4().to_string(),
            username: "alice".to_owned(),
            role: "user".to_owned(),
            aud: "other-instance.example".to_owned(),
            iat: now.timestamp(),
            exp: (now + TimeDelta::seconds(60)).timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .unwrap();

        assert!(
            verify_access_token(&token, &config).is_err(),
            "token with wrong audience must be rejected"
        );
    }

    #[test]
    fn refresh_token_is_url_safe() {
        let token = generate_refresh_token();
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert!(token.len() >= 40); // 32 bytes → ~43 base64url chars
    }
}
