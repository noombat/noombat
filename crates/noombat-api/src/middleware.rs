// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Axum authentication middleware and response security headers.
//!
//! Resolves the authenticated viewer from the request (a JWT session
//! token, carried either as a bearer header or as the session cookie)
//! and inserts it as a request extension for downstream handlers.
//!
//! Authorisation is **not** performed here, with one exception: a viewer
//! whose account may not sign in, suspended or awaiting admission, is
//! refused every request with an unsafe method and every request to the
//! administration surfaces, since the access token they hold outlives the
//! change. All other access control is enforced by domain methods on
//! model types in [`noombat_core::authorisation`] (visibility checks, role
//! guards, block/mute guards) directly in the route handlers.
//!
//! This module additionally builds the response security headers
//! applied to every route; see [`security_headers`].

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Request, header, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{debug, error};

use crate::state::AppState;

/// Who is making this request, and what standing they hold.
///
/// **Anonymity is the extension being absent**, never a `Viewer` full of
/// `None`s: a handler holding one holds an authenticated local actor.
///
/// Deliberately absent: key material, which must not ride in an
/// extension every handler can read; `actor_privacy`, which is the
/// *owner's* policy and belongs to the actor being viewed, not the one
/// viewing; and follower status, which is pairwise and travels as
/// [`noombat_core::authorisation::Relationship`].
///
/// The predicates take a bare `Option<uuid::Uuid>` instead. They compare
/// identities, and loading a whole actor to do that is what kept routes
/// from calling them.
#[derive(Clone, Debug)]
pub struct Viewer {
    pub actor_id: uuid::Uuid,
    /// Routes are keyed on it in the path.
    pub username: String,
    /// Non-optional: `may_moderate` and `may_administer` match on it
    /// exhaustively, and an `Option` is what forced routes to
    /// re-implement both inline.
    pub instance_role: noombat_core::actor::InstanceRole,
    /// Gates whether the request proceeds at all.
    pub actor_status: noombat_core::actor::ActorStatus,
}

/// Each delegates to the enum predicate in
/// [`noombat_core::authorisation`], so a guard here and one on a loaded
/// [`noombat_core::actor::Actor`] cannot disagree.
impl Viewer {
    pub fn may_moderate(&self) -> bool {
        self.instance_role.may_moderate()
    }

    pub fn may_administer(&self) -> bool {
        self.instance_role.may_administer()
    }

    pub fn is_active(&self) -> bool {
        self.actor_status.is_active()
    }

    pub fn is_pending(&self) -> bool {
        self.actor_status.is_pending()
    }

    pub fn is_suspended(&self) -> bool {
        self.actor_status.is_suspended()
    }
}

// ..... Middleware entry point .....

/// Axum middleware function (for use with [`axum::middleware::from_fn_with_state`]).
///
/// Resolves the authenticated viewer and inserts it as a request extension.
/// Refuses a write by a viewer whose account may not sign in, and performs
/// no other authorisation check.
pub async fn authentication(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // The token is copied out before the lookup rather than borrowed
    // across it. `axum::body::Body` is not `Sync`, so a `&Request<Body>`
    // held across an await makes this future non-`Send` and the layer
    // stops satisfying `Service`.
    let token = bearer_or_cookie_token(&request).map(|(token, cookie)| (token.to_owned(), cookie));

    if let Some((token, from_cookie)) = token
        && let Some((viewer, session_id)) = resolve_viewer(&state, &token).await
    {
        // Reads go on while the token lasts, so the pages telling the
        // member why still render.
        if !viewer.is_active() && (acts_as_viewer(&request) || administers(&request)) {
            debug!(username = %viewer.username, "write refused: the account may not sign in");
            return crate::error::ApiError(noombat_core::error::NoombatError::Forbidden)
                .into_response();
        }
        debug!(username = %viewer.username, "viewer resolved");
        if from_cookie {
            request
                .extensions_mut()
                .insert(crate::csrf::CookieSession { session_id });
        }
        request.extensions_mut().insert(viewer);
    }

    next.run(request).await
}

/// Whether the request is a write that may act as the signed-in account:
/// any unsafe method but these. Signing in (with a password, or by starting
/// a Mastodon or ORCID sign-in), registering, refreshing and logging out
/// act by credentials in the request, never the session's,
/// and signing in and refreshing check the account's status themselves;
/// the theme and contrast controls set a cookie and act on no account.
pub(crate) fn acts_as_viewer(request: &Request<Body>) -> bool {
    let exempt = [
        "/api/v1/auth/login",
        "/api/v1/auth/mastodon",
        "/api/v1/auth/orcid",
        "/api/v1/auth/register",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/settings/theme",
        "/settings/contrast",
    ];
    !request.method().is_safe() && !exempt.contains(&request.uri().path())
}

/// Whether the request reaches the moderation and administration surfaces,
/// which an account that may not sign in neither reads nor changes.
fn administers(request: &Request<Body>) -> bool {
    let path = request.uri().path();
    ["/admin", "/api/v1/admin"].iter().any(|root| {
        path == *root
            || path
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

// ..... Viewer resolution .....

/// The session token a request carries, if any, and whether it came from
/// the cookie.
///
/// Resolution order:
/// 1. `Authorization: Bearer <jwt>` header (API clients, HTMX with
///    injected headers).
/// 2. The session cookie (server-rendered page loads, HTMX partial
///    requests; cookies are sent automatically by the browser), when
///    exactly one is sent.
///
/// A request that carries neither is anonymous. There is deliberately
/// no third way in: an instance-wide token that named its account from
/// the request path would let one secret act as every user.
fn bearer_or_cookie_token(request: &Request<Body>) -> Option<(&str, bool)> {
    // 1. Try Authorisation header.
    let token_from_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    // 2. Try the session cookie: two count as none, so the order the
    // browser sends them in does not decide which session a page runs on.
    let token_from_cookie = crate::cookie::single(request.headers(), crate::cookie::COOKIE_NAME);

    token_from_header
        .map(|token| (token, false))
        .or(token_from_cookie.map(|token| (token, true)))
}

/// Turn a session token into the viewer it names, and the session it was
/// issued with when it names one.
///
/// A valid token whose actor no longer exists resolves to nothing, so a
/// session outlives its account by one request at most.
async fn resolve_viewer(state: &AppState, token: &str) -> Option<(Viewer, Option<uuid::Uuid>)> {
    // A JWT session token is the only thing that identifies a caller.
    let session_config = state.session_config.as_ref()?;
    let claims = noombat_identity::session::verify_access_token(token, session_config).ok()?;
    let actor_id = uuid::Uuid::parse_str(&claims.sub).ok()?;

    // One indexed lookup, on the id rather than the username, because
    // the id is what the token asserts and a username can be reissued.
    let (instance_role, actor_status) = sqlx::query_as::<
        _,
        (
            noombat_core::actor::InstanceRole,
            noombat_core::actor::ActorStatus,
        ),
    >(
        "SELECT instance_role, actor_status FROM actors WHERE id = $1 AND is_local = TRUE",
    )
    .bind(actor_id)
    .fetch_optional(&state.pool)
    .await
    .ok()??;

    let session_id = claims
        .sid
        .as_deref()
        .and_then(|sid| uuid::Uuid::parse_str(sid).ok());
    Some((
        Viewer {
            actor_id,
            username: claims.username,
            instance_role,
            actor_status,
        },
        session_id,
    ))
}

// ..... Response security headers .....

/// Content-Security-Policy served when the configured domain cannot
/// be embedded in a header value.
///
/// Identical to the policy built by [`content_security_policy`]
/// except that `connect-src` omits the WebSocket origin, which would
/// be the offending component.
const FALLBACK_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                            connect-src 'self'; img-src 'self' data:; font-src 'self'; \
                            frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

/// Permissions-Policy denying every feature the application does not
/// use.
const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), payment=(), \
                                  usb=(), magnetometer=(), gyroscope=(), accelerometer=(), \
                                  interest-cohort=()";

/// Whether the configured domain designates a local, non-TLS deployment.
///
/// Mirrors the convention applied by the server's production-security
/// check, which treats `localhost` and `localhost:PORT` as
/// development deployments. The loopback addresses are included
/// because a browser also grants them secure-context status.
pub fn is_local_domain(domain: &str) -> bool {
    if domain == "[::1]" || domain.starts_with("[::1]:") {
        return true;
    }
    let host = domain.split(':').next().unwrap_or(domain);
    host == "localhost" || host == "127.0.0.1"
}

/// The origin the browser uses for the chat WebSocket.
///
/// A development instance is served over plain HTTP, where the
/// browser rejects a `wss://` connection; a production instance is
/// served over TLS, where it rejects `ws://`. An origin the operator
/// configured, for a local instance behind a TLS proxy, wins over both.
/// The value returned here is pinned in `connect-src` and is also the
/// origin embedded in the chat page, so the two cannot disagree.
///
/// Both must also agree with the origin the browser actually used. A
/// host source in a Content-Security-Policy that names no port matches
/// only the scheme's default, so `ws://localhost` permits port 80
/// alone: a development instance on 8443 had its WebSocket blocked by
/// its own policy, and the URL on the page named the wrong port too.
pub fn websocket_origin(domain: &str, public_port: u16, configured: Option<&str>) -> String {
    let (secure, authority) = origin_parts(domain, public_port, configured);
    format!("{}://{authority}", if secure { "wss" } else { "ws" })
}

/// Build the HTTP origin a browser addresses this instance by.
///
/// Differs from [`websocket_origin`] in scheme alone, and shares the host
/// and port reasoning with it so the two can never disagree about which
/// requests are same-origin.
pub fn http_origin(domain: &str, public_port: u16, configured: Option<&str>) -> String {
    let (secure, authority) = origin_parts(domain, public_port, configured);
    format!("{}://{authority}", if secure { "https" } else { "http" })
}

/// Whether this instance's origin is served over TLS, and its
/// `host[:port]`: the `configured` origin's, else the domain's.
fn origin_parts(domain: &str, public_port: u16, configured: Option<&str>) -> (bool, String) {
    if let Some(origin) = configured {
        if let Some(authority) = origin.strip_prefix("https://") {
            return (true, authority.to_owned());
        }
        if let Some(authority) = origin.strip_prefix("http://") {
            return (false, authority.to_owned());
        }
    }
    (
        !is_local_domain(domain),
        origin_authority(domain, public_port),
    )
}

/// The `host[:port]` half of this instance's origin.
///
/// A remote deployment sits behind a TLS terminator on 443, where the
/// default port is correct and naming it would only add noise. A local
/// one is reached directly on its listening port, except that a port
/// already in the domain wins: an operator who wrote `localhost:9000`
/// meant it.
fn origin_authority(domain: &str, public_port: u16) -> String {
    if !is_local_domain(domain) || domain.contains(':') {
        domain.to_owned()
    } else {
        format!("{domain}:{public_port}")
    }
}

/// Build the Content-Security-Policy for the configured domain.
///
/// `connect-src` names the WebSocket origin explicitly rather than
/// allowing the scheme wholesale with `wss:`. A scheme-wide source
/// permits exfiltration to any host over that scheme, which defeats
/// much of the point of a `default-src 'none'` policy.
pub fn content_security_policy(domain: &str, public_port: u16, configured: Option<&str>) -> String {
    format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; \
         connect-src 'self' {origin}; img-src 'self' data:; font-src 'self'; \
         frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        origin = websocket_origin(domain, public_port, configured),
    )
}

/// Apply the response security headers to `router`.
///
/// The headers are emitted by the application rather than by the
/// reverse proxy so that a deployment without Caddy is protected
/// identically, and so that exactly one component owns the policy.
/// `Strict-Transport-Security` is the exception: browsers honour it
/// only over TLS, so it remains with the TLS terminator.
///
/// Each header is set only when absent, leaving a proxy free to
/// override a value deliberately.
///
/// Apply this after every route and after the `/assets` service, so
/// that static assets and error responses produced by inner layers
/// carry the headers too.
pub fn security_headers<S>(
    router: Router<S>,
    domain: &str,
    public_port: u16,
    configured: Option<&str>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let csp = match HeaderValue::from_str(&content_security_policy(domain, public_port, configured))
    {
        Ok(value) => value,
        Err(e) => {
            error!(
                error = %e,
                domain = %domain,
                "configured domain cannot be embedded in a header value; \
                 serving a Content-Security-Policy without a WebSocket source, \
                 which will block chat"
            );
            HeaderValue::from_static(FALLBACK_CSP)
        }
    };

    router
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            csp,
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(PERMISSIONS_POLICY),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `is_accepted_follower` is covered where it is used, by the
    // database-backed CV access tests in routes/cv.rs, which exercise
    // both an accepted and a pending follow.

    // ..... Security headers .....

    #[test]
    fn local_domains_are_recognised() {
        assert!(is_local_domain("localhost"));
        assert!(is_local_domain("localhost:8443"));
        assert!(is_local_domain("127.0.0.1"));
        assert!(is_local_domain("127.0.0.1:8443"));
        assert!(is_local_domain("[::1]"));
        assert!(is_local_domain("[::1]:8443"));
    }

    #[test]
    fn public_domains_are_not_local() {
        assert!(!is_local_domain("noombat.social"));
        assert!(!is_local_domain("noombat.social:8443"));
        // A domain merely containing the substring must not match.
        assert!(!is_local_domain("localhost.example.com"));
        assert!(!is_local_domain("notlocalhost"));
    }

    #[test]
    fn websocket_origin_follows_the_deployment_scheme() {
        // A local domain gains the listening port, because a host
        // source naming no port matches only the scheme default.
        assert_eq!(
            websocket_origin("localhost", 8443, None),
            "ws://localhost:8443"
        );
        // A port already present is respected rather than doubled.
        assert_eq!(
            websocket_origin("localhost:9000", 8443, None),
            "ws://localhost:9000"
        );
        // Production is behind a terminator on 443.
        assert_eq!(
            websocket_origin("noombat.social", 8443, None),
            "wss://noombat.social"
        );
    }

    /// A local instance behind a TLS proxy is reached at the origin its
    /// operator configured, scheme and port both.
    #[test]
    fn a_configured_origin_wins() {
        let configured = Some("https://localhost:8443");
        assert_eq!(
            http_origin("localhost", 8444, configured),
            "https://localhost:8443"
        );
        assert_eq!(
            websocket_origin("localhost", 8444, configured),
            "wss://localhost:8443"
        );
        let plain = Some("http://localhost:9000");
        assert_eq!(
            http_origin("localhost", 8444, plain),
            "http://localhost:9000"
        );
        assert_eq!(
            websocket_origin("localhost", 8444, plain),
            "ws://localhost:9000"
        );
        assert!(
            content_security_policy("localhost", 8444, configured)
                .contains("connect-src 'self' wss://localhost:8443;")
        );
    }

    #[test]
    fn csp_pins_the_websocket_host_rather_than_the_scheme() {
        let csp = content_security_policy("noombat.social", 8443, None);

        let connect_src = csp
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("connect-src"))
            .expect("policy declares no connect-src directive");

        // Exactly two sources: the origin itself, and the one host the
        // chat WebSocket connects to.
        assert_eq!(connect_src, "connect-src 'self' wss://noombat.social");

        // A scheme source such as `wss:` permits connections to *any*
        // host over that scheme, which would negate much of a
        // `default-src 'none'` policy. Checked per source rather than
        // by substring, because `wss:` is a prefix of the host source
        // `wss://noombat.social` and a substring test cannot tell the
        // two apart.
        for source in connect_src.split_whitespace().skip(1) {
            let scheme_wide = source.ends_with(':') && !source.contains("//");
            assert!(
                !scheme_wide,
                "connect-src names the scheme-wide source {source}"
            );
        }
    }

    #[test]
    fn csp_denies_by_default_and_omits_unsafe_sources() {
        let csp = content_security_policy("noombat.social", 8443, None);
        assert!(csp.starts_with("default-src 'none';"));
        assert!(csp.contains("script-src 'self';"));
        assert!(csp.contains("style-src 'self';"));
        assert!(csp.contains("frame-ancestors 'none';"));
        assert!(csp.contains("base-uri 'self';"));
        assert!(csp.contains("form-action 'self'"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("unsafe-eval"));
    }

    #[test]
    fn csp_is_a_single_line_valid_header_value() {
        for domain in ["localhost", "localhost:8443", "noombat.social"] {
            let csp = content_security_policy(domain, 8443, None);
            assert!(!csp.contains('\n'), "{domain}: policy contains a newline");
            assert!(
                HeaderValue::from_str(&csp).is_ok(),
                "{domain}: policy is not a valid header value"
            );
        }
    }

    #[test]
    fn fallback_constants_are_valid_header_values() {
        // `HeaderValue::from_static` panics on an invalid value, so
        // this also guards the fallback path in `security_headers`.
        assert!(!HeaderValue::from_static(FALLBACK_CSP).is_empty());
        assert!(!HeaderValue::from_static(PERMISSIONS_POLICY).is_empty());
        assert!(!FALLBACK_CSP.contains('\n'));
        assert!(!PERMISSIONS_POLICY.contains('\n'));
    }
}
