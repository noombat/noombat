// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The CV download gate, through the assembled router.
//!
//! The unit tests beside `resolve_cv_access` cover the decision itself,
//! for every requester against every `cv_download` value. They cannot
//! cover the part that actually failed here: the rule, the domain
//! method, and a follower-status helper naming this very handler all
//! existed and were correct, and the route called none of them. A test
//! at any level below the router would have passed throughout.
//!
//! So what is asserted here is narrow and deliberate: that a request
//! reaching the real route through the real middleware stack is refused,
//! and refused as `404` carrying the same body a missing username
//! produces. The body matters. An unmatched route also answers `404`,
//! and a test that only compared status codes would keep passing if the
//! path were renamed out from under it.
//!
//! Only denials are driven end to end. A permitted request would reach
//! `generate_cv_pdf`, which shells out to the `typst` CLI, and typst is
//! not installed on the CI runners.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::privacy::{ActorPrivacy, CvDownload};
use noombat_federation::nodeinfo::NodeInfoFeatures;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const OWNER: &str = "owner";

/// An `AppState` over the test pool, every optional subsystem disabled.
///
/// `redis: None` sends the rate limiter to its in-process fallback, and
/// the ceilings are high because throttling is not what these probe.
fn test_state(pool: PgPool) -> AppState {
    AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
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
        contact_email: format!("admin@{DOMAIN}"),
        trending_cache: None,
        analytics: None,
        relay_verification_policy: None,
        envelope_key: None,
        fallback_rate_limiter: FallbackRateLimiter::new(100_000, Duration::from_secs(60)),
        fallback_fed_rate_limiter: FallbackRateLimiter::new(100_000, Duration::from_secs(60)),
        rate_limit: 100_000,
        rate_limit_window_secs: 60,
        fed_rate_limit: 100_000,
        fed_rate_limit_window_secs: 60,
        allow_unsigned_fetch: false,
    }
}

async fn insert_actor(pool: &PgPool, username: &str, cv_download: CvDownload) {
    let privacy = ActorPrivacy {
        cv_download,
        ..ActorPrivacy::default()
    };

    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local, actor_privacy)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE, $5)"#,
    )
    .bind(Uuid::new_v4())
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(serde_json::to_value(&privacy).expect("privacy serialises"))
    .execute(pool)
    .await
    .expect("actor fixture inserted");
}

/// Anonymous `GET /users/{username}/cv` through the whole stack.
async fn get_cv(pool: PgPool, username: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .uri(format!("/users/{username}/cv"))
        .body(Body::empty())
        .expect("request construction");

    let response = build_router(test_state(pool))
        .oneshot(request)
        .await
        .expect("the router is infallible");

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body within limit");

    (status, String::from_utf8_lossy(&body).into_owned())
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn anonymous_download_of_a_self_only_cv_is_not_found(pool: PgPool) {
    insert_actor(&pool, OWNER, CvDownload::SelfOnly).await;

    let (status, body) = get_cv(pool, OWNER).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a `self` CV must not be downloadable anonymously, got {status} with {body}"
    );
    assert!(
        body.contains("ACTOR_NOT_FOUND"),
        "the refusal must come from the handler, not from an unmatched route; body was {body}"
    );
}

/// The refusal is indistinguishable from a profile that does not exist.
///
/// This is the reason the denial is `404` and not `403`: a `403` would
/// confirm that the username is taken.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_cv_looks_exactly_like_a_missing_one(pool: PgPool) {
    insert_actor(&pool, OWNER, CvDownload::SelfOnly).await;

    let (refused_status, refused_body) = get_cv(pool.clone(), OWNER).await;
    let (missing_status, missing_body) = get_cv(pool, "nobody").await;

    assert_eq!(refused_status, missing_status);
    assert_eq!(
        refused_body.replace(OWNER, "_"),
        missing_body.replace("nobody", "_"),
        "the two responses must differ only in the echoed username"
    );
}
