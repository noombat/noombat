// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The OAuth callbacks, driven through the assembled router.
//!
//! ORCID's address comes from configuration, so a local stand-in answers
//! the token exchange and the whole flow runs here: the start route, the
//! provider's redirect back, and what the callback writes and sets. A flow
//! is finished with the cookies its start route set, as the browser that
//! started it would send them, unless the test is about another browser: a
//! refusal then comes from the check its test names, not from a missing
//! cookie once the state is bound to one.
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
    format!("noombat_session={}", tokens.access_token)
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

/// Start a flow at `uri` from a browser holding `cookies`. Returns the
/// `state` the redirect to ORCID carries and the cookies that browser holds
/// afterwards.
async fn start(app: &AppState, uri: &str, cookies: &str) -> (String, String) {
    let response = get(app, uri, cookies).await;
    assert_eq!(
        response.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "the start route redirects to ORCID"
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("the redirect names ORCID")
        .to_owned();
    let state_token = location
        .rsplit_once("state=")
        .and_then(|(_, rest)| rest.split('&').next())
        .map(str::to_owned)
        .expect("the redirect carries a state");

    let mut held: Vec<String> = cookies
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect();
    held.extend(cookies_set_by(&response));
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
        pair.strip_prefix("noombat_session=")
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
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_browser_that_starts_an_orcid_link_finishes_it(pool: PgPool) {
    let alice = account(&pool, "alice", "active").await;
    let session = signed_in_as(&pool, alice, "alice").await;
    let app = test_state(pool.clone()).await;

    let (state_token, cookies) = start(&app, "/api/v1/auth/orcid/link", &session).await;
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

// ..... A flow finished in another browser .....

// Known defect: the state is bound to no cookie; remove `should_panic` once the callback checks
// one.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: an ORCID sign-in finished in another browser signs that browser in"
)]
async fn an_orcid_sign_in_finished_in_another_browser_is_refused(pool: PgPool) {
    // Mallory starts a sign-in to her own account and hands the callback
    // address, code and state included, to a browser holding none of her
    // cookies.
    let mallory = linked_account(&pool, "mallory", "active").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, "").await;

    assert!(
        !response.status().is_server_error(),
        "the stand-in ORCID must answer the exchange"
    );
    assert!(
        !sets_a_session(&response),
        "known defect: an ORCID sign-in finished in another browser signs that browser in"
    );
    assert_eq!(sessions_of(&pool, mallory).await, 0, "no session is stored");
    assert_eq!(
        unconsumed_flows(&pool, &state_token).await,
        1,
        "a refused callback leaves the flow for the browser that started it"
    );
}

// Known defect: the state is bound to no cookie; remove `should_panic` once the callback checks
// one.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a sign-in finished with another flow's cookies signs in")]
async fn an_orcid_sign_in_finished_with_another_flows_cookies_is_refused(pool: PgPool) {
    // The victim's browser starts its own sign-in first, so it holds whatever
    // cookies a flow sets: only a check that they match this state refuses it.
    let mallory = linked_account(&pool, "mallory", "active").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) = start(&app, "/api/v1/auth/orcid", "").await;
    let (_victims_state, victims_cookies) = start(&app, "/api/v1/auth/orcid", "").await;

    let response = finish(&app, &state_token, &victims_cookies).await;

    assert!(
        !response.status().is_server_error(),
        "the stand-in ORCID must answer the exchange"
    );
    assert!(
        !sets_a_session(&response),
        "known defect: a sign-in finished with another flow's cookies signs in"
    );
    assert_eq!(sessions_of(&pool, mallory).await, 0, "no session is stored");
    assert_eq!(
        unconsumed_flows(&pool, &state_token).await,
        1,
        "a refused callback leaves the flow for the browser that started it"
    );
}

// Known defect: any browser can finish a link flow; remove `should_panic` once the callback checks
// the browser.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: an ORCID link finished in another browser attaches the iD"
)]
async fn an_orcid_link_finished_in_another_browser_links_nothing(pool: PgPool) {
    // Mallory starts a link to her own account and has the victim authorise
    // at ORCID, so the callback arrives with the victim's iD and none of
    // Mallory's cookies.
    let mallory = account(&pool, "mallory", "active").await;
    let session = signed_in_as(&pool, mallory, "mallory").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) = start(&app, "/api/v1/auth/orcid/link", &session).await;
    let sessions_before = sessions_of(&pool, mallory).await;

    let response = finish(&app, &state_token, "").await;

    assert_eq!(
        identities_for_the_orcid(&pool).await,
        0,
        "known defect: an ORCID link finished in another browser attaches the iD"
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

// Known defect: any browser can finish a link flow; remove `should_panic` once the callback checks
// the browser.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: a link finished with another flow's cookies attaches the iD"
)]
async fn an_orcid_link_finished_with_another_flows_cookies_links_nothing(pool: PgPool) {
    // The victim, signed in, has started a link of their own, so their browser
    // holds a session and whatever cookies a flow sets.
    let mallory = account(&pool, "mallory", "active").await;
    let victim = account(&pool, "victim", "active").await;
    let mallorys_session = signed_in_as(&pool, mallory, "mallory").await;
    let victims_session = signed_in_as(&pool, victim, "victim").await;
    let app = test_state(pool.clone()).await;
    let (state_token, _mallorys_cookies) =
        start(&app, "/api/v1/auth/orcid/link", &mallorys_session).await;
    let (_victims_state, victims_cookies) =
        start(&app, "/api/v1/auth/orcid/link", &victims_session).await;

    finish(&app, &state_token, &victims_cookies).await;

    assert_eq!(
        identities_for_the_orcid(&pool).await,
        0,
        "known defect: a link finished with another flow's cookies attaches the iD"
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

// Known defect: the callback deletes the state before anything else, so a callback from any
// browser spends the flow. With no client registered every callback fails after that, so this
// shows only that a refused callback leaves the state, not that the browser was checked. Remove
// `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a Mastodon callback from another browser spends the flow")]
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
        "known defect: a Mastodon callback from another browser spends the flow"
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
