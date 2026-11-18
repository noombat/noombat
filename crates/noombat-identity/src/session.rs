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
    /// The `sessions` row this token was issued with, which ties a write
    /// authenticated by the session cookie to that session's CSRF token.
    /// Optional when read: a token without one still verifies, and is
    /// refused only for those writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
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
    /// The session's CSRF token, which pages carry masked; never sent in
    /// the sign-in answer.
    #[serde(skip)]
    pub csrf_token: String,
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

/// Why a session is being issued.
///
/// This exists so that `last_sign_in_at`, and therefore the NodeInfo
/// active-user figures, cannot drift back into meaning something else.
/// Every caller of [`create_session`] has to say which of these it is,
/// rather than the distinction living in a comment that a future call
/// site never reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOrigin {
    /// The actor presented credentials and they were accepted. This is a
    /// sign-in in the sense NodeInfo means, and it is recorded.
    SignIn,
    /// An existing session's refresh token was rotated. Nothing is
    /// recorded: a refresh proves a client still holds a valid token,
    /// which a background tab can do for the whole thirty-day refresh
    /// lifetime without the person being there. Counting it would
    /// reintroduce the over-count that `updated_at` produced.
    Refresh,
}

/// What is known about the session being issued.
///
/// These three describe the event rather than the actor, and they are
/// grouped rather than passed separately because adding `origin` as a
/// further parameter took `create_session` past clippy's argument limit.
#[derive(Debug, Clone, Copy)]
pub struct SessionContext<'a> {
    /// The client's `User-Agent`, when the caller has one to record.
    pub user_agent: Option<&'a str>,
    /// The client's address, when the caller has one to record.
    pub ip_addr: Option<&'a str>,
    /// Whether this is a fresh sign-in or a rotation of an existing one.
    pub origin: SessionOrigin,
    /// The CSRF token a rotation carries over; a sign-in makes a new one.
    pub csrf_token: Option<&'a str>,
}

impl<'a> SessionContext<'a> {
    /// A fresh sign-in, with no client details recorded.
    ///
    /// Every caller currently passes `None` for both `user_agent` and
    /// `ip_addr`, so the `sessions` columns behind them are always NULL.
    /// They are kept because the schema has them and a session-management
    /// view would need them, not because anything populates them today.
    pub fn sign_in() -> Self {
        Self {
            user_agent: None,
            ip_addr: None,
            origin: SessionOrigin::SignIn,
            csrf_token: None,
        }
    }

    /// A refresh-token rotation, with no client details recorded, keeping
    /// the rotated session's CSRF token.
    pub fn refresh(csrf_token: &'a str) -> Self {
        Self {
            user_agent: None,
            ip_addr: None,
            origin: SessionOrigin::Refresh,
            csrf_token: Some(csrf_token),
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
    context: SessionContext<'_>,
) -> Result<SessionTokens> {
    let now = Utc::now();
    let access_exp = now + TimeDelta::seconds(config.access_ttl_secs);
    let refresh_exp = now + TimeDelta::seconds(config.refresh_ttl_secs);

    let role_str = match role {
        InstanceRole::User => "user",
        InstanceRole::Moderator => "moderator",
        InstanceRole::Admin => "admin",
    };

    // The row's id is made here so the access token can name it.
    let session_id = Uuid::new_v4();
    let claims = AccessClaims {
        sub: actor_id.to_string(),
        username: username.to_owned(),
        role: role_str.to_owned(),
        aud: config.domain.clone(),
        iat: now.timestamp(),
        exp: access_exp.timestamp(),
        sid: Some(session_id.to_string()),
    };

    let access_token = encode_access_token(&claims, config)?;

    let refresh_token = random_token();
    let csrf_token = context.csrf_token.map_or_else(random_token, str::to_owned);

    sqlx::query(
        r#"INSERT INTO sessions
               (id, actor_id, refresh_token, user_agent, ip_addr, expires_at, csrf_token)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(session_id)
    .bind(actor_id)
    .bind(&refresh_token)
    .bind(context.user_agent)
    .bind(context.ip_addr)
    .bind(refresh_exp)
    .bind(&csrf_token)
    .execute(pool)
    .await?;

    if context.origin == SessionOrigin::SignIn {
        sqlx::query("UPDATE actors SET last_sign_in_at = now() WHERE id = $1")
            .bind(actor_id)
            .execute(pool)
            .await?;
    }

    Ok(SessionTokens {
        access_token,
        refresh_token,
        expires_in: config.access_ttl_secs,
        actor_id,
        username: username.to_owned(),
        csrf_token,
    })
}

/// The CSRF token of the session an access token names, while that session
/// stands: a refresh replaces the cookie with one naming the new session,
/// which carries the same token, so only a session ended by logout or a
/// revocation still names this row, and its writes are refused.
pub async fn csrf_token(pool: &PgPool, session_id: Uuid) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT csrf_token FROM sessions WHERE id = $1 AND revoked_at IS NULL")
            .bind(session_id)
            .fetch_optional(pool)
            .await?,
    )
}

/// Sign `claims` as this instance signs its access tokens: the reverse of
/// [`verify_access_token`].
pub fn encode_access_token(claims: &AccessClaims, config: &SessionConfig) -> Result<String> {
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes())
        .map_err(|e| NoombatError::Internal(format!("JWT signing key unusable: {e}")))?;
    encode(&Header::default(), claims, &key)
        .map_err(|e| NoombatError::Internal(format!("JWT encoding failed: {e}")))
}

/// Decode and validate an access token, returning the claims.
///
/// Validates the `aud` claim against the configured instance domain,
/// rejecting tokens issued for a different instance.
pub fn verify_access_token(token: &str, config: &SessionConfig) -> Result<AccessClaims> {
    let mut validation = Validation::default();
    validation.set_required_spec_claims(&["sub", "exp", "iat", "aud"]);
    validation.set_audience(&[&config.domain]);

    // An empty secret is no key: nothing verifies against it.
    let key = DecodingKey::from_secret(config.jwt_secret.as_bytes())
        .map_err(|_| NoombatError::Forbidden)?;
    let data =
        decode::<AccessClaims>(token, &key, &validation).map_err(|_| NoombatError::Forbidden)?;

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
    // Find the session and verify it is not revoked or expired, and that
    // its account may still sign in, as login requires.
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, InstanceRole, String)>(
        r#"SELECT s.id, s.actor_id, a.username, a.instance_role, s.csrf_token
           FROM sessions s
           JOIN actors a ON a.id = s.actor_id
           WHERE s.refresh_token = $1
             AND s.revoked_at IS NULL
             AND s.expires_at > now()
             AND a.actor_status IN ('active', 'silenced')"#,
    )
    .bind(old_refresh_token)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::Forbidden)?;

    let (session_id, actor_id, username, role, csrf_token) = row;

    // Revoke the old refresh token (rotation), once: a second use of it
    // finds it revoked and mints nothing.
    let rotated =
        sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
            .bind(session_id)
            .execute(pool)
            .await?;
    if rotated.rows_affected() == 0 {
        return Err(NoombatError::Forbidden);
    }

    let tokens = create_session(
        pool,
        config,
        actor_id,
        &username,
        role,
        SessionContext::refresh(&csrf_token),
    )
    .await?;
    keep_only_if_admitted(pool, actor_id, tokens).await
}

/// `tokens`, unless the account was suspended while they were made: a
/// suspension sets the status before it revokes, so a session made after
/// its revocation is found here, and revoked.
pub async fn keep_only_if_admitted(
    pool: &PgPool,
    actor_id: Uuid,
    tokens: SessionTokens,
) -> Result<SessionTokens> {
    if crate::login::may_sign_in(pool, actor_id).await.is_err() {
        revoke_session(pool, &tokens.refresh_token).await?;
        return Err(NoombatError::Forbidden);
    }
    Ok(tokens)
}

/// Revoke a session (logout).
pub async fn revoke_session(pool: &PgPool, refresh_token: &str) -> Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE refresh_token = $1")
        .bind(refresh_token)
        .execute(pool)
        .await?;
    Ok(())
}

/// The bytes in a random token, and in a CSRF token's pad.
const TOKEN_BYTES: usize = 32;

/// A cryptographically random opaque token: 32 bytes, base64url.
fn random_token() -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut buf = [0u8; TOKEN_BYTES];
    rand::fill(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// A session's CSRF token as a page carries it: a fresh random pad, then
/// the token XORed with it, base64url. No two pages hold the same text, so
/// compressing a page beside text a requester chose cannot give it away.
pub fn mask_csrf_token(token: &str) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let token = URL_SAFE_NO_PAD.decode(token).ok()?;
    if token.len() != TOKEN_BYTES {
        return None;
    }
    let mut masked = vec![0u8; TOKEN_BYTES];
    rand::fill(&mut masked[..]);
    let hidden: Vec<u8> = masked.iter().zip(&token).map(|(pad, b)| pad ^ b).collect();
    masked.extend(hidden);
    Some(URL_SAFE_NO_PAD.encode(masked))
}

/// The token a page's masked copy stands for. Only a masked copy is
/// accepted: no page serves the bare token.
pub fn unmask_csrf_token(masked: &str) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let masked = URL_SAFE_NO_PAD.decode(masked).ok()?;
    if masked.len() != 2 * TOKEN_BYTES {
        return None;
    }
    let (pad, hidden) = masked.split_at(TOKEN_BYTES);
    let token: Vec<u8> = pad.iter().zip(hidden).map(|(pad, b)| pad ^ b).collect();
    Some(URL_SAFE_NO_PAD.encode(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_masked_token_stands_for_the_token_and_differs_each_time() {
        let token = random_token();
        let first = mask_csrf_token(&token).expect("a token masks");
        let second = mask_csrf_token(&token).expect("a token masks");
        assert_ne!(first, second, "two masks of one token must differ");
        assert_eq!(unmask_csrf_token(&first).as_deref(), Some(token.as_str()));
        assert_eq!(unmask_csrf_token(&second).as_deref(), Some(token.as_str()));
    }

    #[test]
    fn only_a_masked_token_unmasks() {
        let token = random_token();
        let masked = mask_csrf_token(&token).expect("a token masks");
        assert_eq!(unmask_csrf_token(&token), None, "the bare token");
        assert_eq!(unmask_csrf_token("not base64url!"), None, "not base64url");
        assert_eq!(unmask_csrf_token(&masked[1..]), None, "a truncated mask");
        let overlong = format!("{masked}AAAA");
        assert_eq!(unmask_csrf_token(&overlong), None, "an overlong mask");
        assert_eq!(
            unmask_csrf_token(&format!("{masked}==")),
            None,
            "a padded mask"
        );
    }

    #[test]
    fn only_a_token_of_the_right_length_masks() {
        assert_eq!(mask_csrf_token("AAAA"), None);
    }

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
            sid: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()).expect("a non-empty secret"),
        )
        .unwrap();

        let decoded = verify_access_token(&token, &config).unwrap();
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.aud, "test.noombat.social");
    }

    /// With an empty secret, which would be no key at all, nothing verifies.
    #[test]
    fn an_empty_secret_verifies_nothing() {
        let config = test_config();
        let now = Utc::now();
        let claims = AccessClaims {
            sub: Uuid::new_v4().to_string(),
            username: "alice".to_owned(),
            role: "user".to_owned(),
            aud: "test.noombat.social".to_owned(),
            iat: now.timestamp(),
            exp: (now + TimeDelta::seconds(60)).timestamp(),
            sid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()).expect("a non-empty secret"),
        )
        .unwrap();

        let empty = SessionConfig {
            jwt_secret: String::new(),
            ..config
        };
        assert!(matches!(
            verify_access_token(&token, &empty),
            Err(NoombatError::Forbidden)
        ));
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
            sid: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"wrong-secret-wrong-secret-wrong!")
                .expect("a non-empty secret"),
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
            sid: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()).expect("a non-empty secret"),
        )
        .unwrap();

        assert!(
            verify_access_token(&token, &config).is_err(),
            "token with wrong audience must be rejected"
        );
    }

    #[test]
    fn refresh_token_is_url_safe() {
        let token = random_token();
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert!(token.len() >= 40); // 32 bytes → ~43 base64url chars
    }
}
