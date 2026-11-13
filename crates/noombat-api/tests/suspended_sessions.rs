// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Sessions held by accounts that may not sign in, through the assembled
//! router.
//!
//! Sign-in admits active and silenced accounts only. A token issued before
//! a suspension, or held by an account still awaiting admission, must stop
//! acting for it: its writes are refused and its refresh token buys no new
//! session. A silenced account keeps both, since silencing withholds reach
//! and not access.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::actor::InstanceRole;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::session::{SessionConfig, SessionContext, SessionTokens};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

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

async fn insert_person(pool: &PgPool, username: &str, role: &str, status: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             instance_role, actor_status) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE, $4, $5) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(role)
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("person fixture")
}

/// A remote account already cached, so following it needs no fetch.
async fn insert_remote(pool: &PgPool, username: &str) -> String {
    let ap_id = format!("https://remote.example/users/{username}");
    sqlx::query(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             inbox_url) \
         VALUES ('individual', $1, $2, 'remote.example', 'KEY', FALSE, $3)",
    )
    .bind(&ap_id)
    .bind(username)
    .bind(format!("{ap_id}/inbox"))
    .execute(pool)
    .await
    .expect("remote fixture");
    ap_id
}

async fn sign_in(
    pool: &PgPool,
    actor_id: Uuid,
    username: &str,
    role: InstanceRole,
) -> SessionTokens {
    noombat_identity::session::create_session(
        pool,
        &session_config(),
        actor_id,
        username,
        role,
        SessionContext::sign_in(),
    )
    .await
    .expect("session created")
}

async fn post_json(pool: &PgPool, uri: &str, bearer: Option<&str>, body: Value) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    build_router(test_state(pool.clone()))
        .oneshot(builder.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("the router is infallible")
}

async fn publish(pool: &PgPool, username: &str, access_token: &str) -> StatusCode {
    post_json(
        pool,
        &format!("/users/{username}/outbox"),
        Some(access_token),
        json!({ "content": "still here" }),
    )
    .await
    .status()
}

async fn follow(pool: &PgPool, username: &str, access_token: &str, target: &str) -> StatusCode {
    post_json(
        pool,
        &format!("/users/{username}/following"),
        Some(access_token),
        json!({ "target_ap_id": target }),
    )
    .await
    .status()
}

/// The status of `POST /api/v1/auth/refresh`, and the rotated refresh token
/// when it succeeds.
async fn refresh(pool: &PgPool, refresh_token: &str) -> (StatusCode, Option<String>) {
    let response = post_json(
        pool,
        "/api/v1/auth/refresh",
        None,
        json!({ "refresh_token": refresh_token }),
    )
    .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("refresh body");
    let rotated = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|body| body["refresh_token"].as_str().map(str::to_owned));
    (status, rotated)
}

async fn posts_by(pool: &PgPool, actor_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM posts WHERE actor_id = $1")
        .bind(actor_id)
        .fetch_one(pool)
        .await
        .expect("posts countable")
}

async fn follows_row(pool: &PgPool, follower: Uuid, target_ap_id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM follows f JOIN actors a ON a.id = f.following_id \
                        WHERE f.follower_id = $1 AND a.ap_id = $2)",
    )
    .bind(follower)
    .bind(target_ap_id)
    .fetch_one(pool)
    .await
    .expect("follows readable")
}

/// Suspend `target` through the moderation route, as a moderator signed in
/// for the purpose.
async fn suspend(pool: &PgPool, target: Uuid) {
    let moderator = insert_person(pool, "moderator", "moderator", "active").await;
    let token = sign_in(pool, moderator, "moderator", InstanceRole::Moderator)
        .await
        .access_token;

    let response = post_json(
        pool,
        &format!("/api/v1/admin/actors/{target}/suspend"),
        Some(&token),
        json!({ "reason": "test" }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the moderation route must suspend the account"
    );

    let status: String = sqlx::query_scalar("SELECT actor_status FROM actors WHERE id = $1")
        .bind(target)
        .fetch_one(pool)
        .await
        .expect("status readable");
    assert_eq!(
        status, "suspended",
        "the suspension must reach the database"
    );
}

// Known defect: a suspended account's access token keeps writing; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a suspended account's access token still writes")]
async fn a_suspended_accounts_access_token_may_not_publish_or_follow(pool: PgPool) {
    let member = insert_person(&pool, "member", "user", "active").await;
    let before = insert_remote(&pool, "before").await;
    let after = insert_remote(&pool, "after").await;
    let tokens = sign_in(&pool, member, "member", InstanceRole::User).await;

    assert_eq!(
        publish(&pool, "member", &tokens.access_token).await,
        StatusCode::CREATED,
        "the token must publish before the suspension, or the refusal below proves nothing"
    );
    assert_eq!(
        follow(&pool, "member", &tokens.access_token, &before).await,
        StatusCode::ACCEPTED,
        "the token must follow before the suspension, or the refusal below proves nothing"
    );

    suspend(&pool, member).await;

    let writes = (
        publish(&pool, "member", &tokens.access_token).await,
        follow(&pool, "member", &tokens.access_token, &after).await,
    );
    assert!(
        !writes.0.is_success() && !writes.1.is_success(),
        "known defect: a suspended account's access token still writes"
    );
    assert_eq!(
        writes,
        (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN),
        "a suspended account's writes are refused as forbidden"
    );
    assert_eq!(
        posts_by(&pool, member).await,
        1,
        "a refused publish must not reach the database"
    );
    assert!(
        !follows_row(&pool, member, &after).await,
        "a refused follow must not reach the database"
    );
}

// Known defect: refresh ignores suspension and mints a session; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a suspended account's refresh token mints a session")]
async fn a_suspended_accounts_refresh_token_is_refused(pool: PgPool) {
    let member = insert_person(&pool, "member", "user", "active").await;
    let tokens = sign_in(&pool, member, "member", InstanceRole::User).await;

    let (status, rotated) = refresh(&pool, &tokens.refresh_token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refresh token must work before the suspension, or the refusal below proves nothing"
    );
    let rotated = rotated.expect("a refresh returns the next refresh token");

    suspend(&pool, member).await;

    let (status, _) = refresh(&pool, &rotated).await;
    assert!(
        !status.is_success(),
        "known defect: a suspended account's refresh token mints a session"
    );
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a suspended account's refresh is refused as forbidden"
    );
}

// Known defect, latent while no route issues a pending account a session: its token can write.
// OAuth sign-up creating pending accounts would end that, unless the callbacks refuse pending
// accounts first. Remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a pending account's access token writes")]
async fn a_pending_accounts_access_token_may_not_publish_or_follow(pool: PgPool) {
    // The twin is admitted and otherwise identical, so only the status
    // differs between its requests and the pending account's.
    let admitted = insert_person(&pool, "admitted", "user", "active").await;
    let waiting = insert_person(&pool, "waiting", "user", "pending").await;
    let target = insert_remote(&pool, "target").await;
    let admitted_token = sign_in(&pool, admitted, "admitted", InstanceRole::User)
        .await
        .access_token;
    let waiting_token = sign_in(&pool, waiting, "waiting", InstanceRole::User)
        .await
        .access_token;

    assert_eq!(
        (
            publish(&pool, "admitted", &admitted_token).await,
            follow(&pool, "admitted", &admitted_token, &target).await,
        ),
        (StatusCode::CREATED, StatusCode::ACCEPTED),
        "the admitted twin must write, or the refusal below proves nothing"
    );

    let writes = (
        publish(&pool, "waiting", &waiting_token).await,
        follow(&pool, "waiting", &waiting_token, &target).await,
    );
    assert!(
        !writes.0.is_success() && !writes.1.is_success(),
        "known defect: a pending account's access token writes"
    );
    assert_eq!(
        writes,
        (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN),
        "a pending account's writes are refused as forbidden"
    );
    assert_eq!(
        posts_by(&pool, waiting).await,
        0,
        "a refused publish must not reach the database"
    );
    assert!(
        !follows_row(&pool, waiting, &target).await,
        "a refused follow must not reach the database"
    );
}

// Known defect, latent while no route issues a pending account a session: refresh ignores the
// pending status; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a pending account's refresh token mints a session")]
async fn a_pending_accounts_refresh_token_is_refused(pool: PgPool) {
    let admitted = insert_person(&pool, "admitted", "user", "active").await;
    let waiting = insert_person(&pool, "waiting", "user", "pending").await;
    let admitted_tokens = sign_in(&pool, admitted, "admitted", InstanceRole::User).await;
    let waiting_tokens = sign_in(&pool, waiting, "waiting", InstanceRole::User).await;

    assert_eq!(
        refresh(&pool, &admitted_tokens.refresh_token).await.0,
        StatusCode::OK,
        "the admitted twin must refresh, or the refusal below proves nothing"
    );

    let (status, _) = refresh(&pool, &waiting_tokens.refresh_token).await;
    assert!(
        !status.is_success(),
        "known defect: a pending account's refresh token mints a session"
    );
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a pending account's refresh is refused as forbidden"
    );
}

/// Silencing withholds reach, not access: whatever refuses suspended and
/// pending sessions must still admit this one.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_silenced_accounts_session_still_publishes_and_refreshes(pool: PgPool) {
    let member = insert_person(&pool, "quiet", "user", "silenced").await;
    let target = insert_remote(&pool, "target").await;
    let tokens = sign_in(&pool, member, "quiet", InstanceRole::User).await;

    assert_eq!(
        publish(&pool, "quiet", &tokens.access_token).await,
        StatusCode::CREATED,
        "a silenced account must still publish"
    );
    assert_eq!(
        follow(&pool, "quiet", &tokens.access_token, &target).await,
        StatusCode::ACCEPTED,
        "a silenced account must still follow"
    );
    assert_eq!(
        refresh(&pool, &tokens.refresh_token).await.0,
        StatusCode::OK,
        "a silenced account must still refresh its session"
    );
}
