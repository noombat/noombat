// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Who may act for an account, through the assembled router.
//!
//! These routes used to accept one instance-wide bearer token and take
//! the account they acted on from the request path, so a single secret
//! could write to every profile on the instance. The property asserted
//! here is the one that replaced it: a session acts for its own account
//! and for organisations it belongs to, and for nothing else.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
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
        chatmail_admin_secret: None,
        chatmail_admin_client: None,
        contact_email: format!("admin@{DOMAIN}"),
        trending_cache: None,
        analytics: None,
        relay_verification_policy: None,
        envelope_key: None,
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

async fn token_for(pool: &PgPool, actor_id: Uuid, username: &str) -> String {
    noombat_identity::session::create_session(
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
    .access_token
}

/// `PATCH /users/{target}` as the holder of `bearer`, if any.
async fn patch_profile(pool: PgPool, target: &str, bearer: Option<&str>) -> StatusCode {
    let mut builder = Request::builder()
        .method("PATCH")
        .uri(format!("/users/{target}"))
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    build_router(test_state(pool))
        .oneshot(
            builder
                .body(Body::from(r#"{"headline":"edited"}"#.to_owned()))
                .expect("request"),
        )
        .await
        .expect("the router is infallible")
        .status()
}

async fn headline_of(pool: &PgPool, username: &str) -> Option<String> {
    sqlx::query_scalar("SELECT headline FROM actors WHERE username = $1")
        .bind(username)
        .fetch_one(pool)
        .await
        .expect("actor readable")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_session_may_edit_its_own_profile(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let token = token_for(&pool, alice, "alice").await;

    let status = patch_profile(pool.clone(), "alice", Some(&token)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headline_of(&pool, "alice").await.as_deref(), Some("edited"));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_session_may_not_edit_another_account(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    insert_person(&pool, "bob").await;
    let token = token_for(&pool, alice, "alice").await;

    // The old admin token took the account from the path, so this is
    // exactly the request that used to succeed.
    let status = patch_profile(pool.clone(), "bob", Some(&token)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        headline_of(&pool, "bob").await,
        None,
        "a refused edit must not reach the database"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_anonymous_request_may_edit_nothing(pool: PgPool) {
    insert_person(&pool, "alice").await;

    let status = patch_profile(pool.clone(), "alice", None).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(headline_of(&pool, "alice").await, None);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_account_is_refused_before_it_is_looked_up(pool: PgPool) {
    // An anonymous caller gets the same answer whether or not the
    // account exists, so the endpoint is not a username oracle.
    insert_person(&pool, "alice").await;

    let present = patch_profile(pool.clone(), "alice", None).await;
    let absent = patch_profile(pool.clone(), "nobody", None).await;

    assert_eq!(present, StatusCode::FORBIDDEN);
    assert_eq!(absent, StatusCode::FORBIDDEN);
}
