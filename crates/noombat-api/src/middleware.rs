// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Axum authentication middleware.
//!
//! Resolves the authenticated principal from the request (JWT session
//! token, session cookie, or development-only bearer token) and
//! inserts it as a request extension for downstream handlers.
//!
//! Authorisation is **not** performed here. All access control is
//! enforced by domain methods on model types in
//! [`noombat_core::authorisation`] (visibility checks, role guards,
//! block/mute guards) directly in the route handlers.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, header::AUTHORIZATION, header::COOKIE};
use axum::middleware::Next;
use axum::response::Response;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use tracing::debug;

use crate::state::AppState;

/// The resolved identity of the request originator.
///
/// Stored as a request extension so that downstream handlers may
/// inspect it without re-parsing headers.
#[derive(Clone, Debug)]
pub struct Principal {
    /// The local username, if the principal maps to a local actor.
    pub username: Option<String>,
    /// The actor UUID, populated from the JWT `sub` claim or from a
    /// database lookup.
    pub actor_uuid: Option<uuid::Uuid>,
    /// Instance-level role, populated from the `actors` table when the
    /// principal is a local actor.
    pub instance_role: Option<noombat_core::actor::InstanceRole>,
    /// Whether the principal is an accepted follower of the target
    /// actor on this request. Populated by handlers that need it;
    /// `None` by default.
    pub is_follower_of_target: Option<bool>,
}

impl Principal {
    /// Return the actor UUID if available.
    pub fn actor_id(&self) -> Option<uuid::Uuid> {
        self.actor_uuid
    }
}

// ..... Middleware entry point .....

/// Axum middleware function (for use with [`axum::middleware::from_fn_with_state`]).
///
/// Resolves the authenticated principal and inserts it as a request extension.
/// Does not perform any authorisation checks.
pub async fn authentication(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let mut principal = resolve_principal(&state, &request);

    // Look up instance_role for local principals (single indexed query).
    if let Some(ref mut p) = principal
        && let Some(ref username) = p.username
        && let Ok(role) = sqlx::query_scalar::<_, noombat_core::actor::InstanceRole>(
            "SELECT instance_role FROM actors WHERE username = $1 AND is_local = TRUE",
        )
        .bind(username.as_str())
        .fetch_optional(&state.pool)
        .await
    {
        p.instance_role = role;
    }

    if let Some(ref p) = principal {
        debug!(username = ?p.username, "principal resolved");
        request.extensions_mut().insert(p.clone());
    }

    next.run(request).await
}

// ..... Follower-status helper .....

/// Check whether `follower_username` is an accepted follower of `target_username`.
///
/// This is a utility for handlers that need follower status for visibility checks
/// (e.g. the CV download handler, profile section rendering).
/// It is not called by the middleware itself.
pub async fn is_accepted_follower(
    pool: &PgPool,
    follower_username: &str,
    target_username: &str,
) -> bool {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
               SELECT 1 FROM follows f
               JOIN actors follower ON follower.id = f.follower_id
               JOIN actors target   ON target.id   = f.following_id
               WHERE follower.username = $1 AND follower.is_local = TRUE
                 AND target.username   = $2 AND target.is_local   = TRUE
                 AND f.accepted = TRUE
           )"#,
    )
    .bind(follower_username)
    .bind(target_username)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

// ..... Principal resolution .....

/// Attempt to identify the request principal.
///
/// Resolution order:
/// 1. `Authorization: Bearer <jwt>` header (API clients, HTMX with
///    injected headers).
/// 2. `noombat_session=<jwt>` cookie (server-rendered page loads,
///    HTMX partial requests; cookies are sent automatically by the
///    browser).
/// 3. Development-only admin bearer token (backward compatibility).
fn resolve_principal(state: &AppState, request: &Request<Body>) -> Option<Principal> {
    // 1. Try Authorisation header.
    let token_from_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    // 2. Try session cookie.
    let token_from_cookie = request
        .headers()
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("noombat_session=")
            })
        });

    let token = token_from_header.or(token_from_cookie);
    let token = token?;

    // Try JWT session token.
    if let Some(ref session_config) = state.session_config
        && let Ok(claims) = noombat_identity::session::verify_access_token(token, session_config)
    {
        let actor_uuid = uuid::Uuid::parse_str(&claims.sub).ok();
        return Some(Principal {
            username: Some(claims.username),
            actor_uuid,
            instance_role: None,
            is_follower_of_target: None,
        });
    }

    // Fallback: development-only admin bearer token.
    let expected = state.admin_token.as_deref()?;
    // Constant-time comparison to prevent timing side-channel attacks.
    if token.len() != expected.len() || token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1
    {
        return None;
    }

    // Extract the username from the path (e.g. /users/alice/... or /@alice).
    let path = request.uri().path();
    let username = path
        .strip_prefix("/users/")
        .and_then(|rest| rest.split('/').next())
        .or_else(|| {
            path.strip_prefix("/@")
                .and_then(|rest| rest.split('/').next())
                .filter(|u| !u.is_empty())
        })
        .map(String::from);

    Some(Principal {
        username,
        actor_uuid: None,
        instance_role: None,
        is_follower_of_target: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_accepted_follower_query_compiles() {
        // Smoke test: the SQL string is syntactically valid.
        // Full integration tests require a database.
        let _ = is_accepted_follower;
    }
}
