// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The OAuth callbacks, driven through the assembled router.
//!
//! ORCID's address comes from configuration, so a local stand-in answers
//! the token exchange and the whole flow runs here: the start route, the
//! provider's redirect back, and what the callback writes and sets. A flow
//! starts with a POST from this instance's own pages and is finished with
//! the cookies its start set, as the browser that started it would send
//! them, unless the test is about another browser.
//!
//! The Mastodon callback builds its token address as `https://` plus the
//! instance's domain, which a plain local listener cannot answer. Both
//! callbacks sign in and register through `oauth_util::sign_in_or_register`,
//! which these reach through ORCID.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::oauth_orcid::OrcidConfig;
use noombat_identity::session::{SessionConfig, SessionContext, create_session};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";
/// The iD the stand-in ORCID authenticates every code as.
const ORCID: &str = "0000-0002-1825-0097";

// ..... Harness .....

fn session_config() -> SessionConfig {
    SessionConfig {
        jwt_secret: JWT_SECRET.to_owned(),
        domain: DOMAIN.to_owned(),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
    }
}

/// A stand-in ORCID whose token endpoint authenticates every code as
/// [`ORCID`]. Every other path answers 404, so the publication import a new
/// account starts in the background fails at once.
async fn stand_in_orcid() -> String {
    let app = axum::Router::new().route(
        "/oauth/token",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "access_token": "stand-in-access-token",
                "orcid": ORCID,
                "name": null,
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stand-in ORCID");
    let addr = listener.local_addr().expect("stand-in ORCID address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

async fn test_state(pool: PgPool) -> AppState {
    let orcid = stand_in_orcid().await;
    AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
        // A proxy named in the environment would be asked for the stand-in's
        // loopback address.
        http_client: reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("HTTP client built"),
        open_registrations: true,
        search: None,
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: Some(session_config()),
        orcid_config: Some(OrcidConfig {
            client_id: "stand-in-client".to_owned(),
            client_secret: "stand-in-secret".to_owned(),
            base_uri: orcid.clone(),
            pub_api_uri: orcid,
        }),
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
        deletion_grace_days: 30,
        allow_unsigned_fetch: false,
        media: noombat_api::media::MediaStore::local(
            std::env::temp_dir().join(format!("noombat-test-media-{}", Uuid::new_v4())),
        )
        .expect("temp media root"),
    }
}

async fn account(pool: &PgPool, username: &str, status: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             actor_status) \
         VALUES ('individual', $1, $2, $3, 'PEM', TRUE, $4) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("account fixture")
}

/// An account that signed up with, or has since linked, [`ORCID`].
async fn linked_account(pool: &PgPool, username: &str, status: &str) -> Uuid {
    let id = account(pool, username, status).await;
    noombat_identity::oauth_util::link_identity(pool, id, "orcid", ORCID)
        .await
        .expect("link fixture");
    id
}

/// The session cookie of a browser signed in as `actor`.
async fn signed_in_as(pool: &PgPool, actor: Uuid, username: &str) -> String {
    let tokens = create_session(
        pool,
        &session_config(),
        actor,
        username,
        noombat_core::actor::InstanceRole::User,
        SessionContext::sign_in(),
    )
    .await
    .expect("session fixture");
    format!("__Host-noombat_session={}", tokens.access_token)
}

async fn set_registration_mode(pool: &PgPool, mode: &str) {
    sqlx::query("UPDATE instance_settings SET registration_mode = $1")
        .bind(mode)
        .execute(pool)
        .await
        .expect("registration mode set");
}

/// A GET from a browser holding `cookies`.
async fn get(app: &AppState, uri: &str, cookies: &str) -> Response {
    let mut request = Request::builder().uri(uri);
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies);
    }
    build_router(app.clone())
        .oneshot(request.body(Body::empty()).expect("request built"))
        .await
        .expect("router responded")
}

/// The `name=value` pair of every cookie `response` sets.
fn cookies_set_by(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .map(|pair| pair.trim().to_owned())
        .collect()
}

/// The sign-in form's POST to `uri` with `body`, from a page `site` names
/// (`Sec-Fetch-Site`), in a browser holding `cookies`.
async fn post_start(app: &AppState, uri: &str, body: &str, site: &str, cookies: &str) -> Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("sec-fetch-site", site)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies);
    }
    build_router(app.clone())
        .oneshot(
            request
                .body(Body::from(body.to_owned()))
                .expect("request built"),
        )
        .await
        .expect("router responded")
}

/// The provider's address a start's page moves on to, and the cookies the
/// start set: the page answers 200 and refreshes to that address.
async fn moved_on(response: Response) -> (String, Vec<String>) {
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a start answers with its page"
    );
    let set = cookies_set_by(&response);
    let page = text(response).await;
    let url = page
        .split(r#"<meta http-equiv="refresh" content="0;url="#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the page moves on to the provider")
        .replace("&amp;", "&");
    (url, set)
}

/// The `state` an address to the provider carries.
fn state_of(url: &str) -> String {
    url.rsplit_once("state=")
        .and_then(|(_, rest)| rest.split('&').next())
        .map(str::to_owned)
        .expect("the address carries a state")
}

/// A response's body as text.
async fn text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body read");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Start a flow at `uri` from this instance's sign-in page, in a browser
/// holding `cookies`. Returns the `state` in the address it moves on to and
/// the cookies that browser holds afterwards.
async fn start(app: &AppState, uri: &str, cookies: &str) -> (String, String) {
    let response = post_start(app, uri, "", "same-origin", cookies).await;
    let (url, set) = moved_on(response).await;
    let state_token = state_of(&url);

    let mut held: Vec<String> = cookies
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect();
    held.extend(set);
    (state_token, held.join("; "))
}

/// The settings page's link form, posted by a browser holding `cookies`:
/// its token in the form's field, as the page sends it.
async fn start_link(app: &AppState, uri: &str, cookies: &str) -> (String, String) {
    let session = cookies
        .split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix("__Host-noombat_session="))
        .expect("a signed-in browser");
    let claims = noombat_identity::session::verify_access_token(session, &session_config())
        .expect("the session's token verifies");
    let sid = Uuid::parse_str(claims.sid.as_deref().expect("a session's token names it"))
        .expect("a session id");
    let token = noombat_identity::session::csrf_token(&app.pool, sid)
        .await
        .expect("sessions readable")
        .expect("the session has a token");
    let token = noombat_identity::session::mask_csrf_token(&token).expect("the token masks");
    let response = build_router(app.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookies)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={token}")))
                .expect("request built"),
        )
        .await
        .expect("router responded");
    let (url, set) = moved_on(response).await;
    let state_token = state_of(&url);
    let mut held: Vec<String> = cookies
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect();
    held.extend(set);
    (state_token, held.join("; "))
}

/// ORCID's redirect back, opened in a browser holding `cookies`.
async fn finish(app: &AppState, state_token: &str, cookies: &str) -> Response {
    let uri = format!("/api/v1/auth/orcid/callback?code=stand-in-code&state={state_token}");
    get(app, &uri, cookies).await
}

/// Whether `response` signs the browser in.
fn sets_a_session(response: &Response) -> bool {
    cookies_set_by(response).iter().any(|pair| {
        pair.strip_prefix("__Host-noombat_session=")
            .is_some_and(|token| !token.is_empty())
    })
}

async fn sessions_of(pool: &PgPool, actor: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM sessions WHERE actor_id = $1")
        .bind(actor)
        .fetch_one(pool)
        .await
        .expect("sessions readable")
}

async fn all_sessions(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(pool)
        .await
        .expect("sessions readable")
}

async fn unconsumed_flows(pool: &PgPool, state_token: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM oauth_states WHERE state = $1")
        .bind(state_token)
        .fetch_one(pool)
        .await
        .expect("flows readable")
}

async fn identities_for_the_orcid(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM oauth_identities WHERE provider = 'orcid' AND external_id = $1",
    )
    .bind(ORCID)
    .fetch_one(pool)
    .await
    .expect("identities readable")
}

async fn local_accounts(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM actors WHERE is_local")
        .fetch_one(pool)
        .await
        .expect("accounts readable")
}

async fn active_local_accounts(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM actors WHERE is_local AND actor_status = 'active'")
        .fetch_one(pool)
        .await
        .expect("accounts readable")
}

// ..... Where a sign-in starts .....

/// A sign-in starts only with a POST from this instance's own pages: one
/// another site starts could sign the visitor in as that site chose, so it
/// is refused, as is a GET any link could make, before a flow is stored or
/// its cookie set.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_sign_in_starts_only_from_this_instances_pages(pool: PgPool) {
    let app = test_state(pool.clone()).await;
    for (uri, body) in [
        ("/api/v1/auth/orcid", ""),
        ("/api/v1/auth/mastodon", "handle=mallory%40evil.invalid"),
    ] {
        let refused = post_start(&app, uri, body, "cross-site", "").await;
        assert_eq!(
            refused.status(),
            StatusCode::FORBIDDEN,
            "{uri} from another site"
        );
        assert!(
            cookies_set_by(&refused).is_empty(),
            "{uri}: no cookie is set"
        );
        let by_get = get(&app, uri, "").await;
        assert_eq!(
            by_get.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{uri} by GET"
        );
    }
    let flows: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_states")
        .fetch_one(&pool)
        .await
        .expect("flows countable");
    assert_eq!(flows, 0, "no flow is stored");
}

/// The sign-in page starts each sign-in with the POST those routes take.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_sign_in_page_starts_each_sign_in_with_a_post(pool: PgPool) {
    let app = test_state(pool.clone()).await;
    let page = text(get(&app, "/auth/login", "").await).await;
    for action in ["/api/v1/auth/mastodon", "/api/v1/auth/orcid"] {
        assert!(
            page.contains(&format!(r#"<form method="post" action="{action}""#)),
            "the sign-in page starts {action} with a POST"
        );
    }
}

/// A start answers with a page that moves on to the provider rather than a
/// redirect, which `form-action 'self'` refuses after a form's POST; the
/// page carries the flow's cookie and is kept by no cache.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_start_answers_with_a_page_that_moves_on(pool: PgPool) {
    let app = test_state(pool.clone()).await;
    let response = post_start(&app, "/api/v1/auth/orcid", "", "same-origin", "").await;
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let (url, set) = moved_on(response).await;
    assert!(url.contains("/oauth/authorize?"), "{url}");
    assert!(
        set.contains(&format!("__Host-noombat_oauth={}", state_of(&url))),
        "the flow's cookie holds its state: {set:?}"
    );
}

/// A start that says neither where it came from is refused: no session's
/// token backs a sign-in's start.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_start_saying_nothing_of_its_origin_is_refused(pool: PgPool) {
    let app = test_state(pool.clone()).await;
    for uri in ["/api/v1/auth/orcid", "/api/v1/auth/mastodon"] {
        let response = build_router(app.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("handle=mallory%40evil.invalid"))
                    .expect("request built"),
            )
            .await
            .expect("router responded");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }
}

/// A browser still holding a suspended account's session can sign in to
/// another account: a sign-in's start acts by no session.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_browser_holding_a_suspended_session_can_start_a_sign_in(pool: PgPool) {
    let mallory = account(&pool, "mallory", "suspended").await;
    let session = signed_in_as(&pool, mallory, "mallory").await;
    let app = test_state(pool.clone()).await;
    let response = post_start(&app, "/api/v1/auth/orcid", "", "same-origin", &session).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// A callback with no cookie for its flow and an empty state is refused
/// like any other: an absent cookie matches nothing.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_callback_with_no_cookie_and_no_state_is_refused(pool: PgPool) {
    let app = test_state(pool.clone()).await;
    let response = get(
        &app,
        "/api/v1/auth/orcid/callback?code=stand-in-code&state=",
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(text(response).await.contains("Not finished"));
}

// ..... One browser, start to finish .....

/// The flow the refusals below are measured against.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_browser_that_starts_an_orcid_sign_in_finishes_it(pool: PgPool) {
    let alice = linked_account(&pool, "alice", "active").await;
    let app = test_state(pool.clone()).await;

    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;
    let response = finish(&app, &state_token, &cookies).await;

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        sets_a_session(&response),
        "the callback signs the browser in"
    );
    assert_eq!(
        sessions_of(&pool, alice).await,
        1,
        "the session is the linked account's"
    );
    assert_eq!(
        unconsumed_flows(&pool, &state_token).await,
        0,
        "a finished flow cannot be replayed"
    );
    let cleared = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with("__Host-noombat_oauth=;") && v.contains("Max-Age=0"));
    assert!(
        cleared,
        "a finished flow clears the cookie tying it to the browser"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_browser_that_starts_an_orcid_link_finishes_it(pool: PgPool) {
    let alice = account(&pool, "alice", "active").await;
    let session = signed_in_as(&pool, alice, "alice").await;
    let app = test_state(pool.clone()).await;

    let (state_token, cookies) = start_link(&app, "/api/v1/auth/orcid/link", &session).await;
    let response = finish(&app, &state_token, &cookies).await;

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT actor_id FROM oauth_identities WHERE provider = 'orcid' AND external_id = $1",
    )
    .bind(ORCID)
    .fetch_optional(&pool)
    .await
    .expect("identity readable");
    assert_eq!(
        owner,
        Some(alice),
        "the iD is linked to the account that started the flow"
    );
}

/// A link started before a suspension and finished after it adds no way
/// in to the suspended account.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_finished_after_a_suspension_links_nothing(pool: PgPool) {
    let alice = account(&pool, "alice", "active").await;
    let session = signed_in_as(&pool, alice, "alice").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start_link(&app, "/api/v1/auth/orcid/link", &session).await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .expect("suspended meanwhile");
    finish(&app, &state_token, &cookies).await;
    let linked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oauth_identities WHERE provider = 'orcid' AND actor_id = $1)",
    )
    .bind(alice)
    .fetch_one(&pool)
    .await
    .expect("identities readable");
    assert!(!linked);
}

/// Linking an iD adds it to the actor document, so followers are sent it.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn linking_an_orcid_id_pushes_it_to_followers(pool: PgPool) {
    let alice = account(&pool, "alice", "active").await;
    let follower: Uuid = sqlx::query_scalar(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, inbox_url) \
         VALUES ('individual', 'https://elsewhere.example/users/dana', 'dana', \
                 'elsewhere.example', 'KEY', FALSE, 'https://elsewhere.example/inbox') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("remote follower");
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(follower)
        .bind(alice)
        .execute(&pool)
        .await
        .expect("follow");
    // What followers hold before the link.
    noombat_federation::update::push_actor_document(&pool, alice, DOMAIN).await;
    sqlx::query("DELETE FROM delivery_queue")
        .execute(&pool)
        .await
        .expect("sent");

    let session = signed_in_as(&pool, alice, "alice").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start_link(&app, "/api/v1/auth/orcid/link", &session).await;
    finish(&app, &state_token, &cookies).await;

    let pushed: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT payload FROM delivery_queue WHERE actor_id = $1")
            .bind(alice)
            .fetch_all(&pool)
            .await
            .expect("queue");
    assert_eq!(pushed.len(), 1, "one Update");
    assert_eq!(pushed[0]["type"], "Update");
    assert!(
        pushed[0]["object"].to_string().contains(ORCID),
        "carrying the iD"
    );
}

// ..... A flow finished in another browser .....

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn an_orcid_sign_in_finished_in_another_browser_is_refused(pool: PgPool) {
    // Mallory starts a sign-in to her own account and hands the callback
    // address, code and state included, to a browser holding none of her
    // cookies.
    let mallory = linked_account(&pool, "mallory", "active").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, "").await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !sets_a_session(&response),
        "an ORCID sign-in finished in another browser must not sign that browser in"
    );
    assert_eq!(sessions_of(&pool, mallory).await, 0, "no session is stored");
    assert_eq!(
        unconsumed_flows(&pool, &state_token).await,
        1,
        "a refused callback leaves the flow for the browser that started it"
    );
    let page = text(response).await;
    assert!(
        page.contains("This sign-in or account link was started in another browser"),
        "the refusal is a page saying why"
    );
    assert!(
        page.contains(r#"<a href="/auth/login" class="text-text-brand">Go to sign-in</a>"#),
        "and leading back to sign-in"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn an_orcid_sign_in_finished_with_another_flows_cookies_is_refused(pool: PgPool) {
    // The victim's browser starts its own sign-in first, so it holds whatever
    // cookies a flow sets: only a check that they match this state refuses it.
    let mallory = linked_account(&pool, "mallory", "active").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) = start(&app, "/api/v1/auth/orcid", "").await;
    let (_victims_state, victims_cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &victims_cookies).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !sets_a_session(&response),
        "a sign-in finished with another flow's cookies must not sign in"
    );
    assert_eq!(sessions_of(&pool, mallory).await, 0, "no session is stored");
    assert_eq!(
        unconsumed_flows(&pool, &state_token).await,
        1,
        "a refused callback leaves the flow for the browser that started it"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn an_orcid_link_finished_in_another_browser_links_nothing(pool: PgPool) {
    // Mallory starts a link to her own account and has the victim authorise
    // at ORCID, so the callback arrives with the victim's iD and none of
    // Mallory's cookies.
    let mallory = account(&pool, "mallory", "active").await;
    let session = signed_in_as(&pool, mallory, "mallory").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) =
        start_link(&app, "/api/v1/auth/orcid/link", &session).await;
    let sessions_before = sessions_of(&pool, mallory).await;

    let response = finish(&app, &state_token, "").await;

    assert_eq!(
        identities_for_the_orcid(&pool).await,
        0,
        "an ORCID link finished in another browser must not attach the iD"
    );
    assert!(!sets_a_session(&response), "no session is set");
    assert_eq!(
        sessions_of(&pool, mallory).await,
        sessions_before,
        "no session is stored"
    );
    assert_eq!(
        unconsumed_flows(&pool, &state_token).await,
        1,
        "a refused callback leaves the flow for the browser that started it"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn an_orcid_link_finished_with_another_flows_cookies_links_nothing(pool: PgPool) {
    // The victim, signed in, has started a link of their own, so their browser
    // holds a session and whatever cookies a flow sets.
    let mallory = account(&pool, "mallory", "active").await;
    let victim = account(&pool, "victim", "active").await;
    let mallorys_session = signed_in_as(&pool, mallory, "mallory").await;
    let victims_session = signed_in_as(&pool, victim, "victim").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) =
        start_link(&app, "/api/v1/auth/orcid/link", &mallorys_session).await;
    let (_victims_state, victims_cookies) =
        start_link(&app, "/api/v1/auth/orcid/link", &victims_session).await;

    finish(&app, &state_token, &victims_cookies).await;

    assert_eq!(
        identities_for_the_orcid(&pool).await,
        0,
        "a link finished with another flow's cookies must not attach the iD"
    );
    assert_eq!(
        unconsumed_flows(&pool, &state_token).await,
        1,
        "a refused callback leaves the flow for the browser that started it"
    );
}

// ..... Who a linked identity may sign in .....

// Known defect: a linked account signs in whatever its status; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a suspended account signs in through its linked ORCID iD")]
async fn a_suspended_account_is_refused_at_the_orcid_callback(pool: PgPool) {
    let suspended = linked_account(&pool, "suspended_user", "suspended").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    assert!(
        !sets_a_session(&response),
        "known defect: a suspended account signs in through its linked ORCID iD"
    );
    assert_eq!(
        sessions_of(&pool, suspended).await,
        0,
        "no session is stored"
    );
}

// Known defect: a linked account signs in whatever its status; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a pending account signs in through its linked ORCID iD")]
async fn a_pending_account_is_refused_at_the_orcid_callback(pool: PgPool) {
    // A check that refuses only suspended accounts would let an account still
    // awaiting approval in.
    let pending = linked_account(&pool, "pending_user", "pending").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    assert!(
        !sets_a_session(&response),
        "known defect: a pending account signs in through its linked ORCID iD"
    );
    assert_eq!(sessions_of(&pool, pending).await, 0, "no session is stored");
}

/// Silencing withholds reach, not access, as it does for password sign-in.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_silenced_account_still_signs_in_at_the_orcid_callback(pool: PgPool) {
    let silenced = linked_account(&pool, "silenced_user", "silenced").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    assert!(
        sets_a_session(&response),
        "a silenced account still signs in"
    );
    assert_eq!(sessions_of(&pool, silenced).await, 1);
}

// Known defect: the callback asks for no TOTP code; remove `should_panic` once it does.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: a TOTP-enrolled account signs in through ORCID without a code"
)]
async fn a_totp_enrolled_account_is_not_signed_in_without_a_code(pool: PgPool) {
    let alice = linked_account(&pool, "alice", "active").await;
    noombat_identity::totp::enrol_totp(&pool, alice, "alice", DOMAIN)
        .await
        .expect("TOTP enrolment");
    sqlx::query("UPDATE totp_secrets SET verified = TRUE WHERE actor_id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .expect("TOTP confirmed");
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    // What the challenge looks like is open; issuing no session before a
    // code is the property any form of it has. An outright refusal passes
    // too, and would lock out an account whose only way in is ORCID.
    assert!(
        !sets_a_session(&response),
        "known defect: a TOTP-enrolled account signs in through ORCID without a code"
    );
    assert!(
        !response.status().is_client_error(),
        "refused outright, which locks out an account whose only way in is ORCID"
    );
    assert_eq!(sessions_of(&pool, alice).await, 0, "no session is stored");
}

// ..... Sign-up against the administrator's registration mode .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_orcid_sign_up_on_an_open_instance_creates_an_active_account(pool: PgPool) {
    set_registration_mode(&pool, "open").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        sets_a_session(&response),
        "an open instance signs the new account in"
    );
    let status: String = sqlx::query_scalar(
        "SELECT a.actor_status FROM actors a \
         JOIN oauth_identities oi ON oi.actor_id = a.id \
         WHERE oi.provider = 'orcid' AND oi.external_id = $1",
    )
    .bind(ORCID)
    .fetch_one(&pool)
    .await
    .expect("the new account is linked to the iD");
    assert_eq!(status, "active");
}

// Known defect: OAuth sign-up ignores approval mode; remove `should_panic` once it obeys it.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: an ORCID sign-up in approval mode admits the account at once"
)]
async fn an_orcid_sign_up_in_approval_mode_admits_no_one(pool: PgPool) {
    set_registration_mode(&pool, "approval").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    // Pending or not created at all: either way nobody is in yet.
    assert_eq!(
        active_local_accounts(&pool).await,
        0,
        "known defect: an ORCID sign-up in approval mode admits the account at once"
    );
    assert!(!sets_a_session(&response), "no session is set");
    assert_eq!(all_sessions(&pool).await, 0, "no session is stored");
}

// Known defect: OAuth sign-up ignores closed mode; remove `should_panic` once it obeys it.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: an ORCID sign-up in closed mode creates an account")]
async fn an_orcid_sign_up_in_closed_mode_creates_nothing(pool: PgPool) {
    set_registration_mode(&pool, "closed").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    assert_eq!(
        local_accounts(&pool).await,
        0,
        "known defect: an ORCID sign-up in closed mode creates an account"
    );
    assert!(!sets_a_session(&response), "no session is set");
}

/// The configuration flag closes OAuth sign-up whatever the administrator's
/// mode, so a fix that reads the mode must keep reading the flag too.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_configuration_flag_still_closes_orcid_sign_up(pool: PgPool) {
    set_registration_mode(&pool, "open").await;
    let app = AppState {
        open_registrations: false,
        ..test_state(pool.clone()).await
    };
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    assert!(!sets_a_session(&response), "no session is set");
    assert_eq!(local_accounts(&pool).await, 0, "no account is created");
}

/// A Mastodon callback in a browser that holds no cookie for its flow is
/// refused before the state is spent, so the flow stays for its own browser.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn a_mastodon_callback_from_another_browser_spends_nothing(pool: PgPool) {
    sqlx::query(
        "INSERT INTO oauth_states (state, provider, instance_domain, expires_at) \
         VALUES ('mastodon-state', 'mastodon', 'mastodon.example', now() + interval '10 minutes')",
    )
    .execute(&pool)
    .await
    .expect("flow fixture");
    let app = test_state(pool.clone()).await;

    let response = get(
        &app,
        "/api/v1/auth/mastodon/callback?code=stand-in-code&state=mastodon-state",
        "",
    )
    .await;

    assert!(!sets_a_session(&response), "no session is set");
    assert_eq!(
        unconsumed_flows(&pool, "mastodon-state").await,
        1,
        "a Mastodon callback from another browser must not spend the flow"
    );
}

/// A Mastodon callback in the browser holding its flow's cookie gets past
/// the check and spends the flow; the exchange then fails, with no client
/// registered, which is not the refusal page.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_mastodon_callback_in_its_own_browser_spends_its_flow(pool: PgPool) {
    sqlx::query(
        "INSERT INTO oauth_states (state, provider, instance_domain, expires_at) \
         VALUES ('mastodon-state', 'mastodon', 'mastodon.example', now() + interval '10 minutes')",
    )
    .execute(&pool)
    .await
    .expect("flow fixture");
    let app = test_state(pool.clone()).await;

    let response = get(
        &app,
        "/api/v1/auth/mastodon/callback?code=stand-in-code&state=mastodon-state",
        "__Host-noombat_oauth=mastodon-state",
    )
    .await;

    assert!(!sets_a_session(&response), "no session is set");
    assert!(
        !text(response).await.contains("Not finished"),
        "not refused"
    );
    assert_eq!(
        unconsumed_flows(&pool, "mastodon-state").await,
        0,
        "the flow is spent"
    );
}

/// Closing registration turns new people away. An account made through
/// ORCID and never given a password has no other way in.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_closed_instance_still_signs_in_a_linked_orcid_account(pool: PgPool) {
    set_registration_mode(&pool, "closed").await;
    let alice = linked_account(&pool, "alice", "active").await;
    let app = test_state(pool.clone()).await;
    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &cookies).await;

    assert!(
        sets_a_session(&response),
        "closing registration must not lock out an existing account"
    );
    assert_eq!(sessions_of(&pool, alice).await, 1);
}
