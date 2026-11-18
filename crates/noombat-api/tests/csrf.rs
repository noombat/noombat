// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Forged writes: a request the session cookie authenticates changes
//! nothing unless it comes from this instance's own pages.
//!
//! Two checks, each driven here on its own: where the browser says the
//! request came from (`Sec-Fetch-Site`, else `Origin`), and the session's
//! token, which the session's pages carry and must send back. The write
//! used throughout is adding a skill, which answers 201 when it goes
//! through; a refusal by either check is a 403.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::oauth_orcid::OrcidConfig;
use noombat_identity::session::{
    AccessClaims, SessionConfig, SessionContext, SessionTokens, encode_access_token,
    mask_csrf_token, unmask_csrf_token,
};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const ORIGIN: &str = "https://noombat.example";
const USERNAME: &str = "alice";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";
const SKILLS: &str = "/users/alice/skills";
const FORM: &str = "application/x-www-form-urlencoded";
const JSON: &str = "application/json";

// ..... Fixtures .....

fn session_config() -> SessionConfig {
    SessionConfig {
        jwt_secret: JWT_SECRET.to_owned(),
        domain: DOMAIN.to_owned(),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
    }
}

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
        session_config: Some(session_config()),
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

async fn insert_person(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{USERNAME}"))
    .bind(USERNAME)
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("person fixture")
}

async fn sign_in(pool: &PgPool, actor_id: Uuid) -> SessionTokens {
    noombat_identity::session::create_session(
        pool,
        &session_config(),
        actor_id,
        USERNAME,
        noombat_core::actor::InstanceRole::User,
        SessionContext::sign_in(),
    )
    .await
    .expect("session created")
}

/// The session's token as its pages carry it, masked afresh.
fn masked(token: &str) -> String {
    mask_csrf_token(token).expect("a session's token masks")
}

/// The token a page's meta tag carries.
fn meta_token(html: &str) -> Option<String> {
    let tag = r#"<meta name="csrf-token" content=""#;
    let start = html.find(tag)? + tag.len();
    let end = start + html[start..].find('"')?;
    Some(html[start..end].to_owned())
}

fn cookie(session: &SessionTokens) -> String {
    format!("__Host-noombat_session={}", session.access_token)
}

/// An access token for `actor_id`, signed as the instance signs them,
/// naming the session `sid` or, with none, no session at all.
fn access_token(actor_id: Uuid, sid: Option<&str>) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = AccessClaims {
        sub: actor_id.to_string(),
        username: USERNAME.to_owned(),
        role: "user".to_owned(),
        aud: DOMAIN.to_owned(),
        iat: now,
        exp: now + 900,
        sid: sid.map(str::to_owned),
    };
    encode_access_token(&claims, &session_config()).expect("the claims sign")
}

/// A request with `headers`, through the assembled router: its status.
async fn send(
    pool: &PgPool,
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: Body,
) -> StatusCode {
    answer(pool, method, uri, headers, body).await.0
}

/// As [`send`], with the answer's text.
async fn answer(
    pool: &PgPool,
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: Body,
) -> (StatusCode, String) {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, value.as_str());
    }
    let response = build_router(test_state(pool.clone()))
        .oneshot(request.body(body).expect("request builds"))
        .await
        .expect("the router is infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("answer body read");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Adding a skill as JSON with the session cookie and `extra` headers.
async fn add_skill(
    pool: &PgPool,
    cookie: &str,
    name: &str,
    extra: &[(&str, String)],
) -> StatusCode {
    let mut headers = vec![
        ("cookie", cookie.to_owned()),
        ("content-type", JSON.to_owned()),
    ];
    headers.extend(extra.iter().cloned());
    send(
        pool,
        "POST",
        SKILLS,
        &headers,
        Body::from(format!(r#"{{"name":"{name}"}}"#)),
    )
    .await
}

/// A page as the signed-in browser loads it.
async fn page(pool: &PgPool, uri: &str, cookie: Option<&str>) -> String {
    page_from(test_state(pool.clone()), uri, cookie).await
}

/// As [`page`], from an instance in `state`.
async fn page_from(state: AppState, uri: &str, cookie: Option<&str>) -> String {
    let mut request = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = build_router(state)
        .oneshot(request.body(Body::empty()).expect("page request"))
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::OK, "{uri} must load");
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("page body read");
    String::from_utf8_lossy(&bytes).into_owned()
}

// ..... Where the request came from .....

/// Only this instance's own pages pass the first check: `Sec-Fetch-Site`
/// other than `same-origin`, a sibling subdomain's `same-site` included,
/// and without it an `Origin` other than this instance's, are refused even
/// with the right token.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_from_elsewhere_is_refused(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let cookie = cookie(&session);
    let token = ("x-csrf-token", masked(&session.csrf_token));

    for (i, from) in [
        ("sec-fetch-site", "same-site"),
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-site", "none"),
        ("origin", "https://chat.noombat.example"),
        ("origin", "https://elsewhere.example"),
        ("origin", "null"),
    ]
    .into_iter()
    .enumerate()
    {
        let status = add_skill(
            &pool,
            &cookie,
            &format!("Refused {i}"),
            &[token.clone(), (from.0, from.1.to_owned())],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{}: {} was let through",
            from.0,
            from.1
        );
    }

    let own = [
        vec![("sec-fetch-site", "same-origin".to_owned())],
        vec![("origin", ORIGIN.to_owned())],
        vec![],
    ];
    for (i, from) in own.into_iter().enumerate() {
        let mut headers = vec![token.clone()];
        headers.extend(from.clone());
        let status = add_skill(&pool, &cookie, &format!("Kept {i}"), &headers).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a request from {from:?} was refused"
        );
    }
}

// ..... The session's token .....

/// The second check: a write without the token, with a wrong one, with
/// another session's, with its own unmasked, or from an access token
/// naming no session, is refused even from this instance's own origin.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_without_the_sessions_token_is_refused(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let other = sign_in(&pool, alice).await;
    let cookie = cookie(&session);
    let same_origin = ("sec-fetch-site", "same-origin".to_owned());

    assert_ne!(
        session.csrf_token, other.csrf_token,
        "two sign-ins share a token"
    );
    for (name, extra) in [
        ("no token", vec![same_origin.clone()]),
        (
            "a wrong token",
            vec![same_origin.clone(), ("x-csrf-token", "x".repeat(43))],
        ),
        (
            "another session's token",
            vec![
                same_origin.clone(),
                ("x-csrf-token", masked(&other.csrf_token)),
            ],
        ),
        (
            "the session's own token unmasked",
            vec![
                same_origin.clone(),
                ("x-csrf-token", session.csrf_token.clone()),
            ],
        ),
    ] {
        assert_eq!(
            add_skill(&pool, &cookie, name, &extra).await,
            StatusCode::FORBIDDEN,
            "a write with {name} was let through"
        );
    }

    let skills: i64 = sqlx::query_scalar("SELECT count(*) FROM skills")
        .fetch_one(&pool)
        .await
        .expect("skills countable");
    assert_eq!(skills, 0, "a refused write still added a skill");

    // Two tokens alike but for the session they name, so the refusal is
    // the missing name's and not a token that failed to verify.
    let sid =
        noombat_identity::session::verify_access_token(&session.access_token, &session_config())
            .expect("the session's token verifies")
            .sid
            .expect("a session's token names it");
    let with_token = [
        same_origin.clone(),
        ("x-csrf-token", masked(&session.csrf_token)),
    ];
    let named = format!("__Host-noombat_session={}", access_token(alice, Some(&sid)));
    let unnamed = format!("__Host-noombat_session={}", access_token(alice, None));
    assert_eq!(
        (
            add_skill(&pool, &named, "Named", &with_token).await,
            add_skill(&pool, &unnamed, "Unnamed", &with_token).await,
        ),
        (StatusCode::CREATED, StatusCode::FORBIDDEN),
        "an access token naming no session must be refused, and only for that"
    );
}

/// A plain form carries the token in its body instead of a header, url-
/// encoded or multipart, and the body reaches the handler whole.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_plain_forms_field_carries_the_token(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let cookie = cookie(&session);
    let form = [
        ("cookie", cookie.clone()),
        ("content-type", FORM.to_owned()),
    ];

    let added = send(
        &pool,
        "POST",
        SKILLS,
        &form,
        Body::from(format!(
            "csrf_token={}&name=Type%20theory",
            masked(&session.csrf_token)
        )),
    )
    .await;
    let refused = send(
        &pool,
        "POST",
        SKILLS,
        &form,
        Body::from("csrf_token=wrong&name=Forged"),
    )
    .await;
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM skills ORDER BY name")
        .fetch_all(&pool)
        .await
        .expect("skills readable");
    assert_eq!(
        (added, refused, names),
        (
            StatusCode::CREATED,
            StatusCode::FORBIDDEN,
            vec!["Type theory".to_owned()]
        ),
        "the form's field must carry the token, and the body reach the handler"
    );

    let boundary = "noombat-boundary";
    let multipart = |token: &str| {
        Body::from(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{token}\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"avatar_alt\"\r\n\r\nA face\r\n\
             --{boundary}--\r\n"
        ))
    };
    let multipart_headers = vec![
        ("cookie", cookie.clone()),
        (
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        ),
    ];
    let with = answer(
        &pool,
        "POST",
        "/settings/avatar",
        &multipart_headers,
        multipart(&masked(&session.csrf_token)),
    )
    .await;
    let without = send(
        &pool,
        "POST",
        "/settings/avatar",
        &multipart_headers,
        multipart("wrong"),
    )
    .await;
    // With no image attached, the handler says so only once it has read
    // every part: the body reached it whole.
    assert_eq!(
        (with.0, with.1.as_str(), without),
        (
            StatusCode::BAD_REQUEST,
            "no image was attached",
            StatusCode::FORBIDDEN
        ),
        "a multipart form's field must carry the token, and the body reach the handler"
    );
}

// ..... Who is not checked .....

/// A bearer-token client carries no ambient credential, and the theme and
/// contrast forms act on no account: neither needs the token, from
/// anywhere.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn bearer_clients_and_the_theme_form_are_not_checked(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;

    let bearer = send(
        &pool,
        "POST",
        SKILLS,
        &[
            ("authorization", format!("Bearer {}", session.access_token)),
            ("content-type", JSON.to_owned()),
            ("origin", "https://elsewhere.example".to_owned()),
        ],
        Body::from(r#"{"name":"Rust"}"#),
    )
    .await;
    let theme = send(
        &pool,
        "POST",
        "/settings/theme",
        &[
            ("cookie", cookie(&session)),
            ("content-type", FORM.to_owned()),
            ("sec-fetch-site", "cross-site".to_owned()),
        ],
        Body::from("theme=dark"),
    )
    .await;
    assert_eq!(bearer, StatusCode::CREATED, "a bearer client was refused");
    assert_ne!(theme, StatusCode::FORBIDDEN, "the theme form was refused");
}

/// The chat WebSocket's handshake carries the session cookie and cannot
/// carry a header, so the first check alone guards it: a handshake from
/// another origin is refused before it reaches the upgrade.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_websocket_from_another_origin_is_refused(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let handshake = |origin: &str| {
        vec![
            ("cookie", cookie(&session)),
            ("connection", "upgrade".to_owned()),
            ("upgrade", "websocket".to_owned()),
            ("sec-websocket-version", "13".to_owned()),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==".to_owned()),
            ("origin", origin.to_owned()),
        ]
    };

    let foreign = send(
        &pool,
        "GET",
        "/api/v1/chat/ws",
        &handshake("https://chat.noombat.example"),
        Body::empty(),
    )
    .await;
    let own = send(
        &pool,
        "GET",
        "/api/v1/chat/ws",
        &handshake(ORIGIN),
        Body::empty(),
    )
    .await;
    assert_eq!(
        foreign,
        StatusCode::FORBIDDEN,
        "a sibling subdomain's handshake went through"
    );
    assert_ne!(
        own,
        StatusCode::FORBIDDEN,
        "the instance's own page's handshake was refused"
    );
}

// ..... The token on the pages .....

/// Every signed-in page carries its session's token in the meta tag that
/// htmx and the front end read, and each plain form carries it in a field;
/// a visitor with no session gets neither.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_pages_carry_the_sessions_token(pool: PgPool) {
    let alice = insert_person(&pool).await;
    // An avatar, so the profile page also shows the form that removes it.
    sqlx::query("UPDATE actors SET avatar_url = '/media/avatar.png' WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .expect("avatar fixture");
    let session = sign_in(&pool, alice).await;
    let cookie = cookie(&session);
    let field =
        |carried: &str| format!(r#"<input type="hidden" name="csrf_token" value="{carried}">"#);

    // The token a page carries, which must be the session's, masked.
    let carried_by = |uri: &str, html: &str| {
        let carried = meta_token(html).unwrap_or_default();
        assert_eq!(
            unmask_csrf_token(&carried).as_deref(),
            Some(session.csrf_token.as_str()),
            "{uri} does not carry the session's token"
        );
        carried
    };

    // Masked afresh for each answer: never the token itself, and never the
    // same text twice.
    let mut carried = Vec::new();
    for uri in [
        "/settings",
        "/settings/profile",
        "/settings/skills",
        "/settings/privacy",
        "/settings/migrate",
        "/compose",
        "/auth/totp",
        "/settings/account",
        "/@alice",
    ] {
        let html = page(&pool, uri, Some(&cookie)).await;
        carried.push(carried_by(uri, &html));
    }
    carried.sort();
    carried.dedup();
    assert_eq!(
        carried.len(),
        9,
        "two answers carried the same masked token"
    );
    for (uri, forms) in [
        ("/compose", 1),
        ("/settings/jobs/new", 1),
        ("/settings/profile", 2),
        ("/auth/totp", 1),
        ("/settings/account", 1),
    ] {
        let html = page(&pool, uri, Some(&cookie)).await;
        let token = carried_by(uri, &html);
        assert_eq!(
            html.matches(&field(&token)).count(),
            forms,
            "{uri}'s plain forms do not each carry the token"
        );
    }

    // With ORCID configured, the account page's second link form too.
    let mut orcid = test_state(pool.clone());
    orcid.orcid_config = Some(OrcidConfig {
        client_id: "stand-in-client".to_owned(),
        client_secret: "stand-in-secret".to_owned(),
        base_uri: "https://orcid.example".to_owned(),
        pub_api_uri: "https://pub.orcid.example".to_owned(),
    });
    let html = page_from(orcid, "/settings/account", Some(&cookie)).await;
    let token = carried_by("/settings/account with ORCID", &html);
    assert_eq!(
        html.matches(&field(&token)).count(),
        2,
        "with ORCID configured, both link forms must carry the token"
    );

    let visitor = page(&pool, "/auth/login", None).await;
    assert!(
        !visitor.contains(r#"name="csrf-token""#),
        "a page for a visitor with no session carries a token"
    );
}

/// A refresh keeps the session's token, so a page loaded before it keeps
/// working; a new sign-in gets a new one.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_keeps_the_token(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let refreshed = noombat_identity::session::refresh_session(
        &pool,
        &session_config(),
        &session.refresh_token,
    )
    .await
    .expect("the session refreshes");

    assert_eq!(refreshed.csrf_token, session.csrf_token);
    assert_eq!(
        add_skill(
            &pool,
            &cookie(&refreshed),
            "After refresh",
            &[("x-csrf-token", masked(&session.csrf_token))],
        )
        .await,
        StatusCode::CREATED,
        "the token a page held before the refresh was refused after it"
    );
}

// ..... Every writing method, and the routes it now guards .....

/// PATCH and DELETE are checked as POST is: each refused without the
/// token, and its twin with the token going through.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn patch_and_delete_need_the_token_too(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let cookie = cookie(&session);
    let skill: Uuid =
        sqlx::query_scalar("INSERT INTO skills (actor_id, name) VALUES ($1, 'Rust') RETURNING id")
            .bind(alice)
            .fetch_one(&pool)
            .await
            .expect("skill fixture");
    let json = |token: Option<&str>| {
        let mut headers = vec![
            ("cookie", cookie.clone()),
            ("content-type", JSON.to_owned()),
        ];
        headers.extend(token.map(|t| ("x-csrf-token", t.to_owned())));
        headers
    };
    let profile = r#"{"headline":"Research engineer"}"#;
    let delete = format!("{SKILLS}/{skill}");

    let refused = (
        send(
            &pool,
            "PATCH",
            "/users/alice",
            &json(None),
            Body::from(profile),
        )
        .await,
        send(&pool, "DELETE", &delete, &json(None), Body::empty()).await,
    );
    let allowed = (
        send(
            &pool,
            "PATCH",
            "/users/alice",
            &json(Some(&masked(&session.csrf_token))),
            Body::from(profile),
        )
        .await,
        send(
            &pool,
            "DELETE",
            &delete,
            &json(Some(&masked(&session.csrf_token))),
            Body::empty(),
        )
        .await,
    );
    assert_eq!(
        (refused, allowed),
        (
            (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN),
            (StatusCode::OK, StatusCode::NO_CONTENT)
        ),
        "PATCH and DELETE must be refused without the token and go through with it"
    );
}

/// The TOTP page's set-up form needs the token like any other write.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_totp_set_up_needs_the_token(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let form = [
        ("cookie", cookie(&session)),
        ("content-type", FORM.to_owned()),
    ];
    let secrets = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM totp_secrets")
            .fetch_one(&pool)
            .await
            .expect("secrets countable")
    };

    let refused = send(
        &pool,
        "POST",
        "/auth/totp",
        &form,
        Body::from("csrf_token=wrong"),
    )
    .await;
    let refused_left = secrets().await;
    let allowed = send(
        &pool,
        "POST",
        "/auth/totp",
        &form,
        Body::from(format!("csrf_token={}", masked(&session.csrf_token))),
    )
    .await;
    assert_eq!(
        (refused, refused_left, allowed, secrets().await),
        (StatusCode::FORBIDDEN, 0, StatusCode::SEE_OTHER, 1),
        "the set-up must be refused without the token, and only then"
    );
}

/// A form too large to read for its token is answered 413, not taken for
/// one without a token.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_oversized_form_is_too_large(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let body = format!(
        "csrf_token={}&name={}",
        masked(&session.csrf_token),
        "x".repeat(2 * 1024 * 1024)
    );
    let status = send(
        &pool,
        "POST",
        SKILLS,
        &[
            ("cookie", cookie(&session)),
            ("content-type", FORM.to_owned()),
        ],
        Body::from(body),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// Once a session is ended its token is refused, though its access token
/// still verifies until it expires.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_ended_sessions_token_is_refused(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    noombat_identity::session::revoke_session(&pool, &session.refresh_token)
        .await
        .expect("the session ends");
    assert_eq!(
        add_skill(
            &pool,
            &cookie(&session),
            "After logout",
            &[("x-csrf-token", masked(&session.csrf_token))],
        )
        .await,
        StatusCode::FORBIDDEN,
        "an ended session's token was accepted"
    );
}

/// Linking another way to sign in starts only from a POST with the token:
/// a GET any page could link to starts nothing, and neither does a post
/// without the token. With it, the request reaches the route, whose
/// provider this test cannot reach.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_starts_only_from_a_post_with_the_token(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let cookie = cookie(&session);
    let flows = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oauth_states")
            .fetch_one(&pool)
            .await
            .expect("flows countable")
    };
    let form = |token: &str| {
        (
            vec![
                ("cookie", cookie.clone()),
                ("content-type", FORM.to_owned()),
            ],
            format!("csrf_token={token}&handle=mallory%40evil.example"),
        )
    };

    for uri in ["/api/v1/auth/mastodon/link", "/api/v1/auth/orcid/link"] {
        let got = send(
            &pool,
            "GET",
            &format!("{uri}?handle=mallory@evil.example"),
            &[("cookie", cookie.clone())],
            Body::empty(),
        )
        .await;
        let (headers, body) = form("wrong");
        let forged = send(&pool, "POST", uri, &headers, Body::from(body)).await;
        let (headers, body) = form(&masked(&session.csrf_token));
        let own = send(&pool, "POST", uri, &headers, Body::from(body)).await;
        assert_eq!(
            (got, forged),
            (StatusCode::METHOD_NOT_ALLOWED, StatusCode::FORBIDDEN),
            "{uri}: a GET or a post without the token was not refused"
        );
        assert!(
            own != StatusCode::FORBIDDEN && own != StatusCode::METHOD_NOT_ALLOWED,
            "{uri}: the settings page's own post was refused: {own}"
        );
    }
    assert_eq!(flows().await, 0, "a refused start recorded a flow");
}

// ..... How a refusal reads, and what it leaves cached .....

/// A refusal answers as its asker reads: htmx gets the message as text,
/// marked for the page to show; a browser's own form post gets a page; an
/// API client gets the error document. The message is in the visitor's
/// language.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_refusal_answers_as_its_asker_reads(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let refused = |extra: Vec<(&'static str, String)>| {
        let mut headers = vec![
            ("cookie", cookie(&session)),
            ("content-type", FORM.to_owned()),
        ];
        headers.extend(extra);
        let pool = pool.clone();
        async move {
            let mut request = Request::builder().method("POST").uri(SKILLS);
            for (name, value) in &headers {
                request = request.header(*name, value.as_str());
            }
            let response = build_router(test_state(pool))
                .oneshot(
                    request
                        .body(Body::from("name=Forged"))
                        .expect("request builds"),
                )
                .await
                .expect("the router is infallible");
            let status = response.status();
            let marked = response.headers().contains_key("x-csrf-refused");
            let kind = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body read");
            (
                status,
                marked,
                kind,
                String::from_utf8_lossy(&bytes).into_owned(),
            )
        }
    };

    let htmx = refused(vec![("hx-request", "true".to_owned())]).await;
    let page = refused(vec![("accept", "text/html".to_owned())]).await;
    let api = refused(vec![]).await;
    let portuguese = refused(vec![
        ("hx-request", "true".to_owned()),
        ("accept-language", "pt-BR".to_owned()),
    ])
    .await;

    assert!(
        htmx.0 == StatusCode::FORBIDDEN
            && htmx.1
            && htmx.2.starts_with("text/plain")
            && htmx.3.contains("Reload the page"),
        "htmx must get the message as marked text: {htmx:?}"
    );
    assert!(
        page.0 == StatusCode::FORBIDDEN
            && page.2.starts_with("text/html")
            && page.3.contains("Reload the page")
            && page.3.contains("<h1"),
        "a browser's form post must get a page: {page:?}"
    );
    assert!(
        api.0 == StatusCode::FORBIDDEN && !api.1 && api.3.contains("no valid CSRF token"),
        "an API client must get the error document: {api:?}"
    );
    assert!(
        portuguese.3.contains("Recarregue a página"),
        "the message must be in the visitor's language: {portuguese:?}"
    );
}

/// A page answered to a session carries its token, so no cache may keep
/// it; a visitor's is left to the defaults.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_sessions_pages_are_not_cached(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    let cache = |cookie: Option<String>, uri: &'static str| {
        let pool = pool.clone();
        async move {
            let mut request = Request::builder().uri(uri);
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            build_router(test_state(pool))
                .oneshot(request.body(Body::empty()).expect("request builds"))
                .await
                .expect("the router is infallible")
                .headers()
                .get(header::CACHE_CONTROL)
                .map(|v| v.to_str().unwrap_or_default().to_owned())
        }
    };
    assert_eq!(
        (
            cache(Some(cookie(&session)), "/settings").await,
            cache(Some(cookie(&session)), "/auth/totp").await,
            cache(None, "/auth/login").await,
        ),
        (
            Some("private, no-store".to_owned()),
            Some("private, no-store".to_owned()),
            None
        )
    );
}

// ..... The cookie itself .....

/// A request carrying two session cookies is treated as signed out: which
/// one counted would otherwise be the browser's order, which a cookie set
/// elsewhere can arrange. In one `Cookie` header or, as HTTP/2 may send
/// them, in several.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn two_session_cookies_count_as_none(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let own = sign_in(&pool, alice).await;
    let planted = sign_in(&pool, alice).await;
    let settings = |cookies: Vec<String>| {
        let pool = pool.clone();
        async move {
            let mut request = Request::builder().uri("/settings");
            for cookie in cookies {
                request = request.header(header::COOKIE, cookie);
            }
            build_router(test_state(pool))
                .oneshot(request.body(Body::empty()).expect("request builds"))
                .await
                .expect("the router is infallible")
                .status()
        }
    };
    assert_eq!(
        (
            settings(vec![cookie(&own)]).await,
            settings(vec![format!("{}; {}", cookie(&planted), cookie(&own))]).await,
            settings(vec![cookie(&planted), cookie(&own)]).await,
        ),
        (
            StatusCode::OK,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::TEMPORARY_REDIRECT
        ),
        "two session cookies, in one header or two, must count as none"
    );
}

/// The WebSocket's exemption from the token holds only for its own
/// handshake: an `Upgrade` header on any other write changes nothing.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_upgrade_header_does_not_lift_the_token_check(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let session = sign_in(&pool, alice).await;
    assert_eq!(
        add_skill(
            &pool,
            &cookie(&session),
            "Upgraded",
            &[("upgrade", "websocket".to_owned())],
        )
        .await,
        StatusCode::FORBIDDEN,
        "an Upgrade header let a write through without the token"
    );
}
