// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Response security headers, asserted against the assembled router.
//!
//! The unit tests in `middleware` cover the header *values*: that the
//! policy denies by default, that `connect-src` names a host rather
//! than a scheme, and that the strings are valid header values. They
//! cannot cover the part that most easily regresses, which is where
//! the layer sits in the stack.
//!
//! `Router::layer` applies only to routes added before it. Moving the
//! call, or adding a route after it, silently drops the headers from
//! whatever it no longer wraps, and every value assertion still passes.
//!
//! These tests need no database. `/` and `/auth/login` are template
//! renders that touch no state, the authentication middleware queries
//! only once a viewer resolves (no request here carries a token),
//! and the rate limiter falls back to its in-process governor when
//! `redis` is `None`. The pool is therefore constructed lazily and
//! never connects.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use sqlx::PgPool;
use tower::ServiceExt;

// ..... Fixtures .....

/// The instance domain used for production-shaped assertions.
const DOMAIN: &str = "noombat.example";

/// Listening port, as a local deployment's browser-facing origin.
const PUBLIC_PORT: u16 = 8443;

/// Build an `AppState` with every optional subsystem disabled.
fn test_state(domain: &str) -> AppState {
    AppState {
        // Lazy: no connection is opened unless a query runs, and none
        // does on the routes exercised here.
        pool: PgPool::connect_lazy("postgres://noombat:noombat@localhost/noombat")
            .expect("lazy pool construction cannot fail for a well-formed URL"),
        domain: domain.to_owned(),
        public_port: PUBLIC_PORT,
        http_client: reqwest::Client::new(),
        open_registrations: true,
        search: None,
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: None,
        orcid_config: None,
        mailer: None,
        chatmail_domain: None,
        chatmail_admin_url: None,
        chatmail_admin_secret: None,
        chatmail_admin_client: None,
        contact_email: format!("admin@{domain}"),
        trending_cache: None,
        analytics: None,
        envelope_key: None,
        // High ceilings: rate limiting is not what these tests probe.
        fallback_rate_limiter: FallbackRateLimiter::new(),
        rate_limit: 100_000,
        rate_limit_window_secs: 60,
        fed_rate_limit: 100_000,
        fed_rate_limit_window_secs: 60,
        cv_download_limit: 100_000,
        cv_download_window_secs: 60,
        deletion_grace_days: 30,
        allow_unsigned_fetch: false,
        // A per-test directory: these tests never serve media, and a
        // shared path would let one test's objects outlive it.
        media: noombat_api::media::MediaStore::local(
            std::env::temp_dir().join(format!("noombat-test-media-{}", uuid::Uuid::new_v4())),
        )
        .expect("temp media root"),
    }
}

/// Issue a GET against the assembled router and return the response.
async fn get(domain: &str, path: &str) -> axum::response::Response {
    get_with(test_state(domain), path).await
}

/// Issue a GET against a router built from a caller-supplied state.
///
/// The seam `get` does not have: the registration tests need a state
/// with `open_registrations` turned off.
async fn get_with(state: AppState, path: &str) -> axum::response::Response {
    let router = build_router(state);
    let request = Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request construction");
    // No `accept-encoding`: the stack carries a `CompressionLayer`, and a
    // body read here must not have to un-gzip first.
    router
        .oneshot(request)
        .await
        .expect("the router is infallible")
}

/// Read a response body to a string, for the assertions that read copy.
async fn body_string(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("the body is small and fully buffered");
    String::from_utf8(bytes.to_vec()).expect("templates render UTF-8")
}

/// The content type Askama's web integration sets on a rendered page.
const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// Assert an HTML page declares the right content type.
///
/// Deliberately not part of [`assert_header_set`], which also runs
/// against static assets, redirects and unmatched paths, none of which
/// are HTML.
///
/// This is the one response header no code in this repository sets:
/// `askama_web` chooses it, so a templating upgrade can change it
/// without anything here failing to compile. Nothing else in the suite
/// would notice.
fn assert_html_content_type(response: &axum::response::Response, path: &str) {
    let actual = response
        .headers()
        .get("content-type")
        .unwrap_or_else(|| panic!("{path}: content-type is absent"))
        .to_str()
        .unwrap_or_else(|_| panic!("{path}: content-type is not valid UTF-8"));
    assert_eq!(actual, HTML_CONTENT_TYPE, "{path}: content-type");
}

/// Headers required on every response, with their exact values.
const EXACT_HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
];

/// Assert the full header set on a response.
fn assert_header_set(response: &axum::response::Response, path: &str) {
    let headers = response.headers();

    for (name, expected) in EXACT_HEADERS {
        let actual = headers
            .get(*name)
            .unwrap_or_else(|| panic!("{path}: {name} is absent"))
            .to_str()
            .unwrap_or_else(|_| panic!("{path}: {name} is not valid UTF-8"));
        assert_eq!(actual, *expected, "{path}: {name}");
    }

    assert!(
        headers.contains_key("content-security-policy"),
        "{path}: Content-Security-Policy is absent"
    );

    // `img-src` specifically, because it is the directive this suite used
    // to leave unguarded while asserting every other one. Featured images
    // render an author-supplied absolute URL into `<img src>`, unvalidated
    // on both write paths (`routes::actors` passes `featured_image_url`
    // through; `federation::inbox::extract_image_url` takes a remote
    // actor's `image` verbatim). Only this directive stops that becoming
    // a per-reader IP disclosure to an arbitrary host, so whoever makes
    // featured images work must not be able to relax it quietly.
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        csp.contains("img-src 'self' data:"),
        "{path}: CSP does not restrict img-src to 'self' data: -- got {csp}"
    );
    assert!(
        headers.contains_key("permissions-policy"),
        "{path}: Permissions-Policy is absent"
    );

    // HSTS is deliberately left to the TLS terminator; browsers honour
    // it only over TLS. Emitting it here would be inert at best and
    // misleading at worst.
    assert!(
        !headers.contains_key("strict-transport-security"),
        "{path}: HSTS belongs at the TLS terminator, not the application"
    );
}

// ..... Test cases .....

#[tokio::test]
async fn root_page_carries_the_header_set() {
    let response = get(DOMAIN, "/").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_header_set(&response, "/");
    assert_html_content_type(&response, "/");
}

#[tokio::test]
async fn login_page_carries_the_header_set() {
    let response = get(DOMAIN, "/auth/login").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_header_set(&response, "/auth/login");
    assert_html_content_type(&response, "/auth/login");
}

#[tokio::test]
async fn static_assets_carry_the_header_set() {
    // Served by `nest_service`, not by a route handler. A layer moved
    // inside the router would leave precisely this response bare while
    // every other assertion in this file still passed.
    //
    // The status is not asserted: `ServeDir` resolves relative to the
    // working directory, so the file is present when the frontend has
    // been built and absent otherwise. Either way the nested service
    // handled the request, which is the property under test.
    let response = get(DOMAIN, "/assets/htmx.js").await;
    assert_header_set(&response, "/assets/htmx.js");
}

// ..... Coverage of the remaining response paths .....

#[tokio::test]
async fn unmatched_paths_carry_the_header_set() {
    // A 404 is produced by the router's fallback rather than by any
    // handler, so it exercises a third code path.
    let response = get(DOMAIN, "/no-such-path").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_header_set(&response, "/no-such-path");
}

#[tokio::test]
async fn redirects_carry_the_header_set() {
    // Authenticated pages redirect when no viewer resolves. The
    // response never reaches a template, so it is a distinct path
    // again.
    let response = get(DOMAIN, "/chat").await;
    assert!(
        response.status().is_redirection(),
        "/chat: expected a redirect without a session, got {}",
        response.status()
    );
    assert_header_set(&response, "/chat");
}

// ..... Policy content on a live response .....

#[tokio::test]
async fn policy_pins_the_websocket_host_for_the_configured_domain() {
    let response = get(DOMAIN, "/auth/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP is absent")
        .to_str()
        .expect("CSP is not valid UTF-8");

    assert!(
        csp.contains(&format!("connect-src 'self' wss://{DOMAIN}")),
        "CSP does not pin the WebSocket host: {csp}"
    );
    assert!(!csp.contains("unsafe-inline"), "CSP permits inline: {csp}");
    assert!(!csp.contains("unsafe-eval"), "CSP permits eval: {csp}");
}

#[tokio::test]
async fn policy_uses_plain_websockets_for_a_local_domain() {
    // A development instance is served over HTTP, where the browser
    // refuses a `wss://` connection. The served page derives its
    // WebSocket URL from the same function, so the two cannot drift.
    let response = get("localhost", "/auth/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP is absent")
        .to_str()
        .expect("CSP is not valid UTF-8");

    // The port comes from the listener, not from `domain`, which is the
    // federation authority and carries none.
    assert!(
        csp.contains(&format!("connect-src 'self' ws://localhost:{PUBLIC_PORT}")),
        "CSP does not name the local WebSocket origin: {csp}"
    );
}

#[tokio::test]
async fn policy_is_emitted_exactly_once() {
    // Browsers enforce multiple policies as an intersection, so a
    // duplicate is safe but signals that the proxy and the application
    // have both begun emitting one. A single authoritative emitter is
    // the decision this guards.
    let response = get(DOMAIN, "/auth/login").await;
    let count = response
        .headers()
        .get_all("content-security-policy")
        .iter()
        .count();

    assert_eq!(count, 1, "expected exactly one Content-Security-Policy");
}

// ..... Registration policy .....
//
// These live here because this is the harness that assembles the real
// router without a database, which is what makes the login page and the
// register route reachable from a test at all.

/// A state whose operator has closed registration.
fn closed_state(domain: &str) -> AppState {
    AppState {
        open_registrations: false,
        ..test_state(domain)
    }
}

#[tokio::test]
async fn a_closed_instance_says_so_on_the_login_page() {
    let body = body_string(get_with(closed_state("example.test"), "/auth/login").await).await;
    assert!(
        body.contains("Registration is closed. You can still sign in below"),
        "a closed instance must say so where it offers the OAuth controls"
    );
}

#[tokio::test]
async fn a_closed_instance_still_offers_the_oauth_sign_in_controls() {
    // The regression guard that matters most here, and the reason the
    // template gates copy rather than controls. An account created
    // through Mastodon that never ran `set_password` has no other way
    // in, so hiding the form would lock out existing users rather than
    // turn away new ones. The refusal is server-side, in
    // `oauth_util::sign_in_or_register`, and is pinned by that module's
    // own tests.
    let body = body_string(get_with(closed_state("example.test"), "/auth/login").await).await;
    assert!(
        body.contains("/api/v1/auth/mastodon"),
        "closing registration must not remove the sign-in path for accounts that already exist"
    );
}

#[tokio::test]
async fn an_open_instance_does_not_say_registration_is_closed() {
    let body = body_string(get("example.test", "/auth/login").await).await;
    assert!(
        !body.contains("Registration is closed. You can still sign in below"),
        "the closed-registration copy must be conditional, not permanent"
    );
}

#[tokio::test]
async fn a_closed_instance_refuses_password_registration() {
    // A well-formed body, so that a 422 from the `Json` extractor cannot
    // be mistaken for the guard. The `open_registrations` check runs
    // before the mailer check, so `mailer: None` does not turn this into
    // a 503.
    let router = build_router(closed_state("example.test"));
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"username":"alice","auth_key":"a-well-formed-key"}"#,
        ))
        .expect("request construction");
    let response = router
        .oneshot(request)
        .await
        .expect("the router is infallible");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "closed registration must refuse the password door too"
    );
}
