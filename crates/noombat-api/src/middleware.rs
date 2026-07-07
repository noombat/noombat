// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Axum authorisation middleware.
//!
//! Resolves the authenticated principal from the request, maps the
//! HTTP method and path to a Cedar `(action, resource)` pair,
//! constructs the authorisation context, and delegates the decision
//! to the [`AuthorisationBackend`] held in [`AppState`].

use axum::body::Body;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use noombat_core::auth::{AuthContext, Decision};

use crate::state::AppState;

/// The resolved identity of the request originator.
///
/// Stored as a request extension so that downstream handlers may
/// inspect it without re-parsing headers.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Cedar entity UID, e.g. `Noombat::Actor::"alice"`.
    pub entity_uid: String,
    /// The local username, if the principal maps to a local actor.
    pub username: Option<String>,
    /// Instance-level role (`"user"`, `"moderator"`, `"admin"`), populated
    /// from the `actors` table when the principal is a local actor.
    pub instance_role: Option<String>,
}

/// Axum middleware function (for use with [`axum::middleware::from_fn_with_state`]).
pub async fn authorisation(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // ..... Resolve principal .....

    let principal = resolve_principal(&state, &request);

    // Look up instance_role for local principals (single indexed query).
    let principal = match principal {
        Some(mut p) => {
            if let Some(ref username) = p.username {
                if let Ok(role) = sqlx::query_scalar::<_, String>(
                    "SELECT instance_role FROM actors WHERE username = $1 AND is_local = TRUE",
                )
                .bind(username.as_str())
                .fetch_optional(&state.pool)
                .await
                {
                    p.instance_role = role;
                }
            }
            Some(p)
        }
        None => None,
    };

    if let Some(ref p) = principal {
        request.extensions_mut().insert(p.clone());
    }

    // ..... Determine whether the route requires authorisation .....

    let method = request.method().clone();
    let path = request.uri().path().to_owned();

    let mapping = map_route(&method, &path, &state.domain);

    let (action, resource, owner_username) = match mapping {
        Some(m) => m,
        None => {
            // Public or unmapped route: no authorisation required.
            return next.run(request).await;
        }
    };

    // ..... Skip if no principal (anonymous access) .....
    //
    // Routes that must reject anonymous access do so in the handler
    // (e.g. via `verify_bearer_token`). The middleware enforces
    // policy only when a principal *is* identified.

    let principal = match principal {
        Some(p) => p,
        None => return next.run(request).await,
    };

    // ..... Build context and evaluate .....

    let is_owner = principal
        .username
        .as_deref()
        .map(|u| u == owner_username)
        .unwrap_or(false);

    let mut context = AuthContext::new();
    context.insert("is_owner".into(), is_owner.to_string());
    if let Some(ref role) = principal.instance_role {
        context.insert("instance_role".into(), role.clone());
    }

    let decision = state
        .auth
        .is_authorised(&principal.entity_uid, &action, &resource, &context);

    match decision {
        Decision::Permit => {
            debug!(
                principal = %principal.entity_uid,
                %action,
                %resource,
                "authorised"
            );
            next.run(request).await
        }
        Decision::Deny => {
            warn!(
                principal = %principal.entity_uid,
                %action,
                %resource,
                "denied"
            );
            StatusCode::FORBIDDEN.into_response()
        }
    }
}

// ..... Helpers .....

/// Attempt to identify the request principal.
fn resolve_principal(state: &AppState, request: &Request<Body>) -> Option<Principal> {
    let expected = state.admin_token.as_deref()?;

    let header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;

    let token = header.strip_prefix("Bearer ")?;
    // Constant-time comparison to prevent timing side-channel attacks.
    if token.len() != expected.len() || token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1
    {
        return None;
    }

    // Extract the username from the path (e.g. /users/alice/...).
    let path = request.uri().path();
    let username = path
        .strip_prefix("/users/")
        .and_then(|rest| rest.split('/').next())
        .map(String::from);

    let entity_uid = match &username {
        Some(u) => format!(r#"Noombat::Actor::"{u}""#),
        None => r#"Noombat::Actor::"anonymous""#.to_owned(),
    };

    Some(Principal {
        entity_uid,
        username,
        instance_role: None,
    })
}

/// Map an HTTP `(method, path)` to a Cedar `(action, resource, owner_username)`.
///
/// Returns `None` for public/read-only routes that do not require
/// policy evaluation (GET on any resource, health, well-known).
fn map_route(method: &Method, path: &str, _domain: &str) -> Option<(String, String, String)> {
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return None;
    }

    // Extract the username from /users/{username}[/...].
    let rest = path.strip_prefix("/users/")?;
    let username = rest.split('/').next()?;

    let resource = format!(r#"Noombat::Profile::"{username}""#);

    let action = if rest.ends_with("/outbox") && method == Method::POST {
        r#"Noombat::Action::"create_post""#.to_owned()
    } else if rest.ends_with("/inbox") && method == Method::POST {
        // Inbound federation: authenticated via HTTP Signatures,
        // not the bearer token. Skip policy evaluation.
        return None;
    } else if method == Method::PATCH {
        r#"Noombat::Action::"edit""#.to_owned()
    } else if method == Method::DELETE {
        r#"Noombat::Action::"delete""#.to_owned()
    } else {
        return None;
    };

    Some((action, resource, username.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_requests_are_unmapped() {
        assert!(map_route(&Method::GET, "/users/alice", "localhost").is_none());
        assert!(map_route(&Method::GET, "/users/alice/outbox", "localhost").is_none());
    }

    #[test]
    fn post_outbox_maps_to_create_post() {
        let (action, resource, owner) =
            map_route(&Method::POST, "/users/alice/outbox", "localhost").unwrap();
        assert!(action.contains("create_post"));
        assert!(resource.contains("alice"));
        assert_eq!(owner, "alice");
    }

    #[test]
    fn patch_maps_to_edit() {
        let (action, _, _) = map_route(&Method::PATCH, "/users/alice", "localhost").unwrap();
        assert!(action.contains("edit"));
    }

    #[test]
    fn delete_maps_to_delete() {
        let (action, _, _) = map_route(&Method::DELETE, "/users/alice", "localhost").unwrap();
        assert!(action.contains("delete"));
    }

    #[test]
    fn inbox_post_is_skipped() {
        assert!(map_route(&Method::POST, "/users/alice/inbox", "localhost").is_none());
    }
}
