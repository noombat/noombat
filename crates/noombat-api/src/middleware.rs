// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Axum authorisation middleware.
//!
//! Resolves the authenticated principal from the request, maps the
//! HTTP method and path to a Cedar `(action, resource)` pair,
//! constructs the authorisation context, including the target
//! actor's privacy settings and the principal's follower
//! relationship, and delegates the decision to the
//! [`AuthorisationBackend`] held in [`AppState`].

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use noombat_core::auth::{AuthContext, Decision};
use noombat_core::privacy::{ActorPrivacy, CvDownload};

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
    /// Instance-level role, populated from the `actors` table when the
    /// principal is a local actor.
    pub instance_role: Option<noombat_core::actor::InstanceRole>,
    /// Whether the principal is an accepted follower of the target
    /// actor on this request. Populated by the middleware for routes
    /// that fetch privacy context; `None` otherwise.
    pub is_follower_of_target: Option<bool>,
}

// ..... Privacy context .....

/// Privacy-related fields for the target actor, fetched from the
/// database when the matched route requires them.
struct PrivacyContext {
    discoverable: bool,
    federate_profile: bool,
    cv_download: String,
    is_follower: bool,
}

/// Fetch the target actor's privacy settings and, when a principal
/// is identified, whether the principal is an accepted follower.
///
/// Returns `None` if the target actor does not exist (the handler
/// will produce a 404 independently).
async fn fetch_privacy_context(
    pool: &PgPool,
    target_username: &str,
    principal_username: Option<&str>,
) -> Option<PrivacyContext> {
    let privacy_json = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT actor_privacy FROM actors WHERE username = $1 AND is_local = TRUE",
    )
    .bind(target_username)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;

    let privacy: ActorPrivacy = serde_json::from_value(privacy_json).ok()?;

    let is_follower = match principal_username {
        Some(p_username) => sqlx::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1 FROM follows f
                   JOIN actors follower ON follower.id = f.follower_id
                   JOIN actors target   ON target.id   = f.following_id
                   WHERE follower.username = $1 AND follower.is_local = TRUE
                     AND target.username   = $2 AND target.is_local   = TRUE
                     AND f.accepted = TRUE
               )"#,
        )
        .bind(p_username)
        .bind(target_username)
        .fetch_one(pool)
        .await
        .unwrap_or(false),
        None => false,
    };

    let cv_download = match privacy.cv_download {
        CvDownload::Public => "public",
        CvDownload::Followers => "followers",
        CvDownload::SelfOnly => "self",
    };

    Some(PrivacyContext {
        discoverable: privacy.discoverable,
        federate_profile: privacy.federate_profile,
        cv_download: cv_download.to_owned(),
        is_follower,
    })
}

// ..... Middleware entry point .....

/// Axum middleware function (for use with [`axum::middleware::from_fn_with_state`]).
pub async fn authorisation(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // ..... Resolve principal .....

    let principal = resolve_principal(&state, &request);

    // Look up instance_role for local principals (single indexed query).
    let mut principal = match principal {
        Some(mut p) => {
            if let Some(ref username) = p.username
                && let Ok(role) = sqlx::query_scalar::<_, noombat_core::actor::InstanceRole>(
                    "SELECT instance_role FROM actors WHERE username = $1 AND is_local = TRUE",
                )
                .bind(username.as_str())
                .fetch_optional(&state.pool)
                .await
            {
                p.instance_role = role;
            }
            Some(p)
        }
        None => None,
    };

    // ..... Determine whether the route requires authorisation .....

    let method = request.method().clone();
    let path = request.uri().path().to_owned();

    let mapping = map_route(&method, &path);

    let (action, resource, owner_username) = match mapping {
        Some(m) => m,
        None => {
            // Public or unmapped route: insert the principal (if any)
            // for downstream handlers and pass through.
            if let Some(ref p) = principal {
                request.extensions_mut().insert(p.clone());
            }
            return next.run(request).await;
        }
    };

    // ..... Build context .....

    let principal_username = principal.as_ref().and_then(|p| p.username.as_deref());

    let is_owner = principal_username
        .map(|u| u == owner_username)
        .unwrap_or(false);

    let mut context = AuthContext::new();
    context.insert("is_owner".into(), is_owner.to_string());
    context.insert("is_authenticated".into(), principal.is_some().to_string());

    if let Some(ref p) = principal
        && let Some(role) = p.instance_role
    {
        let role_str = match role {
            noombat_core::actor::InstanceRole::User => "user",
            noombat_core::actor::InstanceRole::Moderator => "moderator",
            noombat_core::actor::InstanceRole::Admin => "admin",
        };
        context.insert("instance_role".into(), role_str.to_owned());
    }

    // Fetch privacy-related context for actions that reference it.
    if action_needs_privacy_context(&action) {
        if let Some(priv_ctx) =
            fetch_privacy_context(&state.pool, &owner_username, principal_username).await
        {
            context.insert("discoverable".into(), priv_ctx.discoverable.to_string());
            context.insert(
                "federate_profile".into(),
                priv_ctx.federate_profile.to_string(),
            );
            context.insert("cv_download".into(), priv_ctx.cv_download);
            context.insert("is_follower".into(), priv_ctx.is_follower.to_string());

            // Profile pages are always accessible via direct URL
            // (`discoverable` controls search results, not direct access).
            // Set `visibility` to `"public"` so that the `public-view` Cedar policy
            // permits the request.
            if action.contains("view") {
                context.insert("visibility".into(), "public".to_owned());
            }

            // Propagate the follower status to the principal extension
            // so that downstream handlers (e.g. the CV handler) may
            // read it without a redundant database query.
            if let Some(ref mut p) = principal {
                p.is_follower_of_target = Some(priv_ctx.is_follower);
            }
        } else {
            // The target actor does not exist. Pass through so that
            // the handler produces the appropriate 404 response rather
            // than the middleware returning a misleading 403.
            if let Some(ref p) = principal {
                request.extensions_mut().insert(p.clone());
            }
            return next.run(request).await;
        }
    }

    // Insert the (potentially enriched) principal into request
    // extensions for downstream handlers.
    if let Some(ref p) = principal {
        request.extensions_mut().insert(p.clone());
    }

    // ..... Evaluate .....

    // Use a synthetic anonymous principal when no real principal is
    // identified. This allows Cedar policies to distinguish between
    // "no credential supplied" and "credential supplied but not the
    // owner", which is necessary for access-controlled GET routes
    // (e.g. CV download).
    let principal_uid = match &principal {
        Some(p) => p.entity_uid.as_str(),
        None => r#"Noombat::Actor::"anonymous""#,
    };

    let decision = state
        .auth
        .is_authorised(principal_uid, &action, &resource, &context);

    match decision {
        Decision::Permit => {
            debug!(
                principal = %principal_uid,
                %action,
                %resource,
                "authorised"
            );
            next.run(request).await
        }
        Decision::Deny => {
            warn!(
                principal = %principal_uid,
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

    let entity_uid = match &username {
        Some(u) => format!(r#"Noombat::Actor::"{u}""#),
        None => r#"Noombat::Actor::"anonymous""#.to_owned(),
    };

    Some(Principal {
        entity_uid,
        username,
        instance_role: None,
        is_follower_of_target: None,
    })
}

/// Whether the given Cedar action requires privacy-context fields
/// (`discoverable`, `federate_profile`, `cv_download`, `is_follower`)
/// to be fetched from the database before evaluation.
fn action_needs_privacy_context(action: &str) -> bool {
    action.contains("download_cv") || action.contains("view")
}

/// Map an HTTP `(method, path)` to a Cedar `(action, resource, owner_username)`.
///
/// Returns `None` for routes that do not require policy evaluation:
/// health, well-known endpoints, outbox/followers/following
/// collections, feed pages, and inbound federation (authenticated
/// via HTTP Signatures rather than bearer tokens).
fn map_route(method: &Method, path: &str) -> Option<(String, String, String)> {
    // Extract the username from either /users/{username}[/...] or
    // /@{username} (the human-facing profile URL).
    let (username, subpath) = if let Some(rest) = path.strip_prefix("/users/") {
        let username = rest.split('/').next()?;
        let subpath = &rest[username.len()..]; // "" or "/..." after username
        (username, subpath)
    } else {
        let rest = path.strip_prefix("/@")?;
        let username = rest.split('/').next().filter(|u| !u.is_empty())?;
        (username, "")
    };

    let resource = format!(r#"Noombat::Profile::"{username}""#);

    let action = match (method, subpath) {
        // ..... Write operations .....
        (&Method::POST, "/outbox") => r#"Noombat::Action::"create_post""#,
        (&Method::POST, "/inbox") => {
            // Inbound federation: authenticated via HTTP Signatures,
            // not the bearer token. Skip policy evaluation.
            return None;
        }
        (&Method::PATCH, _) => r#"Noombat::Action::"edit""#,
        (&Method::DELETE, _) => r#"Noombat::Action::"delete""#,

        // ..... Read operations (privacy-controlled) .....
        (&Method::GET, "/cv") => r#"Noombat::Action::"download_cv""#,
        (&Method::GET, "" | "/") => r#"Noombat::Action::"view""#,

        // Everything else (outbox GET, followers, following, posts,
        // profile-section CRUD sub-routes, etc.): no policy evaluation
        // at the middleware level. Handlers apply fine-grained checks
        // (e.g. per-section visibility) via the authorisation backend
        // directly.
        _ => return None,
    };

    Some((action.to_owned(), resource, username.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmapped_routes() {
        // Public collections and well-known paths.
        assert!(map_route(&Method::GET, "/healthz").is_none());
        assert!(map_route(&Method::GET, "/.well-known/webfinger").is_none());
        assert!(map_route(&Method::GET, "/users/alice/outbox").is_none());
        assert!(map_route(&Method::GET, "/users/alice/followers").is_none());
        assert!(map_route(&Method::GET, "/users/alice/following").is_none());
    }

    #[test]
    fn post_outbox_maps_to_create_post() {
        let (action, resource, owner) = map_route(&Method::POST, "/users/alice/outbox").unwrap();
        assert!(action.contains("create_post"));
        assert!(resource.contains("alice"));
        assert_eq!(owner, "alice");
    }

    #[test]
    fn patch_maps_to_edit() {
        let (action, _, _) = map_route(&Method::PATCH, "/users/alice").unwrap();
        assert!(action.contains("edit"));
    }

    #[test]
    fn delete_maps_to_delete() {
        let (action, _, _) = map_route(&Method::DELETE, "/users/alice").unwrap();
        assert!(action.contains("delete"));
    }

    #[test]
    fn inbox_post_is_skipped() {
        assert!(map_route(&Method::POST, "/users/alice/inbox").is_none());
    }

    #[test]
    fn get_cv_maps_to_download_cv() {
        let (action, resource, owner) = map_route(&Method::GET, "/users/alice/cv").unwrap();
        assert!(action.contains("download_cv"));
        assert!(resource.contains("alice"));
        assert_eq!(owner, "alice");
    }

    #[test]
    fn get_profile_maps_to_view() {
        let (action, resource, owner) = map_route(&Method::GET, "/users/alice").unwrap();
        assert!(action.contains("view"));
        assert!(resource.contains("alice"));
        assert_eq!(owner, "alice");
    }

    #[test]
    fn get_profile_trailing_slash_maps_to_view() {
        let (action, _, _) = map_route(&Method::GET, "/users/alice/").unwrap();
        assert!(action.contains("view"));
    }

    #[test]
    fn action_needs_privacy_context_for_cv() {
        assert!(action_needs_privacy_context(
            r#"Noombat::Action::"download_cv""#
        ));
    }

    #[test]
    fn action_needs_privacy_context_for_view() {
        assert!(action_needs_privacy_context(r#"Noombat::Action::"view""#));
    }

    #[test]
    fn action_does_not_need_privacy_context_for_edit() {
        assert!(!action_needs_privacy_context(r#"Noombat::Action::"edit""#));
    }

    // ..... /@{username} (human-facing profile URL) .....

    #[test]
    fn at_prefix_profile_maps_to_view() {
        let (action, resource, owner) = map_route(&Method::GET, "/@alice").unwrap();
        assert!(action.contains("view"));
        assert!(resource.contains("alice"));
        assert_eq!(owner, "alice");
    }

    #[test]
    fn at_prefix_bare_slash_is_unmapped() {
        // `/@` alone has no username.
        assert!(map_route(&Method::GET, "/@").is_none());
    }
}
