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
//! only once a principal resolves (no request here carries a token),
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
        admin_token: None,
        search: None,
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: None,
        orcid_config: None,
        chatmail_domain: None,
        chatmail_admin_url: None,
        chatmail_admin_secret: None,
        chatmail_admin_client: None,
        contact_email: format!("admin@{domain}"),
        trending_cache: None,
        analytics: None,
        relay_verification_policy: None,
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
    }
}

/// Issue a GET against the assembled router and return the response.
async fn get(domain: &str, path: &str) -> axum::response::Response {
    let router = build_router(test_state(domain));
    let request = Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request construction");
    router
        .oneshot(request)
        .await
        .expect("the router is infallible")
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
}

#[tokio::test]
async fn login_page_carries_the_header_set() {
    let response = get(DOMAIN, "/auth/login").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_header_set(&response, "/auth/login");
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
    // Authenticated pages redirect when no principal resolves. The
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
