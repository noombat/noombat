// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Two-factor enrolment as the page at `/auth/totp` performs it.
//!
//! Loading the page enrols a fresh secret and shows it. The page's form then
//! posts the six-digit code to `/api/v1/auth/totp/verify` through htmx, which
//! encodes it as `application/x-www-form-urlencoded`, and the session rides
//! in the cookie. The handler has to accept that request as the page sends it.
//! Once enabled, the page's Disable form turns it off and is told so.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::cookie::COOKIE_NAME;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

fn test_state(pool: PgPool) -> AppState {
    AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
        http_client: reqwest::Client::new(),
        open_registrations: true,
        search: None,
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: Some(noombat_identity::session::SessionConfig {
            jwt_secret: JWT_SECRET.to_owned(),
            domain: DOMAIN.to_owned(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
        }),
        orcid_config: None,
        mailer: None,
        chatmail_domain: None,
        chatmail_admin_url: None,
        chatmail_admin_client: None,
        contact_email: format!("admin@{DOMAIN}"),
        trending_cache: None,
        analytics: None,
        fallback_rate_limiter: FallbackRateLimiter::new(),
        rate_limit: 100_000,
        rate_limit_window_secs: 60,
        fed_rate_limit: 100_000,
        fed_rate_limit_window_secs: 60,
        cv_download_limit: 100_000,
        cv_download_window_secs: 60,
        media: noombat_api::media::MediaStore::local(std::env::temp_dir())
            .expect("a local media store over the temp dir"),
        deletion_grace_days: 30,
        allow_unsigned_fetch: false,
    }
}

async fn insert_person(pool: &PgPool, username: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("person fixture")
}

/// The `Cookie` header a signed-in browser sends with every request.
async fn session_cookie(pool: &PgPool, actor_id: Uuid, username: &str) -> String {
    let token = noombat_identity::session::create_session(
        pool,
        &noombat_identity::session::SessionConfig {
            jwt_secret: JWT_SECRET.to_owned(),
            domain: DOMAIN.to_owned(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
        },
        actor_id,
        username,
        noombat_core::actor::InstanceRole::User,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await
    .expect("session created")
    .access_token;
    format!("{COOKIE_NAME}={token}")
}

/// The CSRF token of the session a cookie names, masked as that session's
/// pages carry it: a write the cookie authenticates must send it.
async fn csrf_of(pool: &PgPool, cookie: &str) -> String {
    let token = cookie
        .strip_prefix("__Host-noombat_session=")
        .unwrap_or(cookie);
    let config = noombat_identity::session::SessionConfig {
        jwt_secret: JWT_SECRET.to_owned(),
        domain: DOMAIN.to_owned(),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
    };
    let claims = noombat_identity::session::verify_access_token(token, &config)
        .expect("the session's access token verifies");
    let session = Uuid::parse_str(
        claims
            .sid
            .as_deref()
            .expect("the access token names its session"),
    )
    .expect("a session id");
    let token = noombat_identity::session::csrf_token(pool, session)
        .await
        .expect("sessions readable")
        .expect("the session has a CSRF token");
    noombat_identity::session::mask_csrf_token(&token).expect("the token masks")
}

/// The page's set-up form, as a browser posts it: its hidden token field.
async fn start_enrolment(pool: &PgPool, cookie: &str) -> axum::response::Response {
    build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/totp")
                .header("cookie", cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={}",
                    csrf_of(pool, cookie).await
                )))
                .expect("set-up request"),
        )
        .await
        .expect("the router is infallible")
}

/// The TOTP page's HTML.
async fn totp_page(pool: &PgPool, cookie: &str) -> String {
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/totp")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("page request"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the enrolment page must load"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("page body");
    String::from_utf8(bytes.to_vec()).expect("the page is UTF-8")
}

/// The secret a page shows for manual entry, if it shows one.
fn shown_secret(page: &str) -> Option<String> {
    page.split_once("select-all\">")
        .and_then(|(_, rest)| rest.split_once("</code>"))
        .map(|(secret, _)| secret.trim().to_owned())
        .filter(|secret| !secret.is_empty())
}

/// Start enrolment with the page's set-up form, then load the page, which
/// now shows the new secret, and return the secret it shows for manual
/// entry.
async fn open_enrolment_page(pool: &PgPool, cookie: &str) -> String {
    assert_eq!(
        start_enrolment(pool, cookie).await.status(),
        StatusCode::SEE_OTHER,
        "the set-up form must start enrolment and return to the page"
    );
    shown_secret(&totp_page(pool, cookie).await)
        .expect("the page shows the secret for manual entry")
}

/// The request the page's form sends: htmx's headers, its form encoding,
/// and the session cookie.
async fn submit_as_the_page_does(pool: &PgPool, cookie: &str, code: &str) -> StatusCode {
    build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/verify")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf_of(pool, cookie).await)
                .header("hx-request", "true")
                .header("hx-target", "totp-enrolment")
                .header("hx-current-url", format!("https://{DOMAIN}/auth/totp"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={}&code={code}",
                    csrf_of(pool, cookie).await
                )))
                .expect("form request"),
        )
        .await
        .expect("the router is infallible")
        .status()
}

async fn submit_as_json(pool: &PgPool, cookie: &str, code: &str) -> StatusCode {
    build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/totp/verify")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf_of(pool, cookie).await)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "code": code }).to_string()))
                .expect("JSON request"),
        )
        .await
        .expect("the router is infallible")
        .status()
}

async fn two_factor_enabled(pool: &PgPool, actor_id: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM totp_secrets WHERE actor_id = $1 AND verified = TRUE)",
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .expect("enrolment readable")
}

// ..... The code an authenticator app shows .....
//
// RFC 6238 with the parameters the instance issues: HMAC-SHA-1, 30-second
// steps, six digits.

fn code_at(secret_base32: &str, unix_time: u64) -> String {
    let secret =
        totp_rs::Secret::try_from_base32(secret_base32).expect("the page shows a base32 secret");
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(secret)
        .build()
        .expect("the instance's TOTP parameters are valid")
        .generate(unix_time)
        .to_string()
}

fn current_code(secret_base32: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock reads after 1970")
        .as_secs();
    code_at(secret_base32, now)
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_enrolment_pages_form_post_enables_two_factor(pool: PgPool) {
    // ASCII "12345678901234567890" in base32, with the RFC's codes cut to six.
    for (time, expected) in [
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_234_567_890, "005924"),
    ] {
        assert_eq!(
            code_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time),
            expected,
            "the test's code generator disagrees with RFC 6238 at t={time}"
        );
    }

    // The same flow sent as JSON first, so the code, the cookie and the page
    // are proved good before the page's own request is sent.
    let control = insert_person(&pool, "json_client").await;
    let control_cookie = session_cookie(&pool, control, "json_client").await;
    let control_secret = open_enrolment_page(&pool, &control_cookie).await;
    assert_eq!(
        submit_as_json(&pool, &control_cookie, &current_code(&control_secret)).await,
        StatusCode::OK,
        "a valid code sent as JSON must be accepted, or the form case proves nothing"
    );
    assert!(
        two_factor_enabled(&pool, control).await,
        "the JSON control must enable two-factor"
    );

    let member = insert_person(&pool, "member").await;
    let cookie = session_cookie(&pool, member, "member").await;
    let secret = open_enrolment_page(&pool, &cookie).await;
    let status = submit_as_the_page_does(&pool, &cookie, &current_code(&secret)).await;

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the enrolment page's form post is refused"
    );
    assert!(
        status.is_success() || status.is_redirection(),
        "the enrolment form was refused for another reason: {status}"
    );
    assert!(
        two_factor_enabled(&pool, member).await,
        "the enrolment form must enable two-factor"
    );
}

/// A DELETE of two-factor sign-in, sent as htmx sends the page's Disable
/// form when `from_page`, or as an API client does: its status and body.
async fn disable(pool: &PgPool, cookie: &str, from_page: bool) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/auth/totp")
        .header("cookie", cookie)
        .header("x-csrf-token", csrf_of(pool, cookie).await);
    if from_page {
        request = request
            .header("hx-request", "true")
            .header("hx-target", "totp-status")
            .header("hx-current-url", format!("https://{DOMAIN}/auth/totp"));
    }
    let response = build_router(test_state(pool.clone()))
        .oneshot(request.body(Body::empty()).expect("disable request"))
        .await
        .expect("the router is infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("answer body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The page shown to a member with two-factor enabled.
async fn enabled_page(pool: &PgPool, cookie: &str) -> String {
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .uri("/auth/totp")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("page request"),
        )
        .await
        .expect("the router is infallible");
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("page body");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The page's Disable form swaps its answer over the line saying two-factor
/// is enabled, so it is answered with a line saying it is now disabled; an
/// API client gets 204 and no body.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_disable_form_says_two_factor_is_disabled(pool: PgPool) {
    let member = insert_person(&pool, "member").await;
    let cookie = session_cookie(&pool, member, "member").await;

    let secret = open_enrolment_page(&pool, &cookie).await;
    assert_eq!(
        submit_as_json(&pool, &cookie, &current_code(&secret)).await,
        StatusCode::OK,
        "two-factor must be enabled first"
    );
    let page = enabled_page(&pool, &cookie).await;
    assert!(
        page.contains(r#"<div id="totp-status">"#)
            && page.contains(r#"hx-delete="/api/v1/auth/totp""#)
            && page.contains(r##"hx-target="#totp-status""##),
        "the page no longer renders the Disable form this test replays: {page}"
    );

    let (status, body) = disable(&pool, &cookie, true).await;
    assert_eq!(
        (
            status,
            body.contains("<p class=\"mb-4\">Two-factor authentication is disabled.</p>"),
            body.contains(concat!(
                r#"<span id="a11y-status" hx-swap-oob="innerHTML">"#,
                "Two-factor authentication is disabled.</span>",
            )),
        ),
        (StatusCode::OK, true, true),
        "the page must show and announce that two-factor is disabled: {body}"
    );
    assert!(
        !two_factor_enabled(&pool, member).await,
        "the form must disable two-factor"
    );

    let secret = open_enrolment_page(&pool, &cookie).await;
    assert_eq!(
        submit_as_json(&pool, &cookie, &current_code(&secret)).await,
        StatusCode::OK,
        "two-factor must be enabled again"
    );
    assert_eq!(
        disable(&pool, &cookie, false).await,
        (StatusCode::NO_CONTENT, String::new()),
        "an API client must get 204 and no body"
    );
    assert!(
        !two_factor_enabled(&pool, member).await,
        "the API must disable two-factor"
    );
}

/// Loading the TOTP page writes nothing: before set-up it offers the
/// set-up form, and once a secret exists it shows that same secret on
/// every load rather than replacing it.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn loading_the_totp_page_writes_nothing(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let cookie = session_cookie(&pool, alice, "alice").await;
    let secrets = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM totp_secrets")
            .fetch_one(&pool)
            .await
            .expect("secrets countable")
    };

    let before = totp_page(&pool, &cookie).await;
    totp_page(&pool, &cookie).await;
    assert_eq!(secrets().await, 0, "loading the page made a secret");
    assert!(
        before.contains(r#"action="/auth/totp""#) && shown_secret(&before).is_none(),
        "before set-up the page must offer the set-up form and no secret: {before}"
    );

    let first = open_enrolment_page(&pool, &cookie).await;
    let again = shown_secret(&totp_page(&pool, &cookie).await);
    assert_eq!(
        (secrets().await, again),
        (1, Some(first)),
        "a second load must show the same secret, not replace it"
    );
}

/// Set-up never replaces a verified secret: posted again once two-factor
/// is on, as a second tab still showing the set-up form would, it leaves
/// the secret and its verification as they are.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn set_up_never_replaces_a_verified_secret(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let cookie = session_cookie(&pool, alice, "alice").await;
    let secret = open_enrolment_page(&pool, &cookie).await;
    assert_eq!(
        submit_as_the_page_does(&pool, &cookie, &current_code(&secret)).await,
        StatusCode::OK,
        "two-factor could not be enabled"
    );
    let stored = || async {
        sqlx::query_as::<_, (String, bool)>(
            "SELECT secret, verified FROM totp_secrets WHERE actor_id = $1",
        )
        .bind(alice)
        .fetch_one(&pool)
        .await
        .expect("secret readable")
    };
    let before = stored().await;

    start_enrolment(&pool, &cookie).await;

    assert_eq!(
        stored().await,
        before,
        "a second set-up replaced the verified secret"
    );
    assert!(before.1, "the secret was not verified to begin with");
}
