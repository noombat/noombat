// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! What the home feed serves to a visitor it cannot identify.
//!
//! `feed.html` requests `/feed` with a page number and nothing else, so
//! the anonymous branch is the only one the UI reaches. It serves the
//! public timeline; `unlisted` is the visibility that means "not on
//! public timelines" and stays out of it.
//!
//! The assertions count rendered posts rather than the status, because
//! the handler answers 200 with an empty body when it finds none.

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

// ..... Harness .....

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

async fn insert_actor(pool: &PgPool, username: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE)"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .execute(pool)
    .await
    .expect("actor fixture inserted");
    id
}

async fn insert_post(pool: &PgPool, actor_id: Uuid, visibility: &str, body: &str) {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO posts
               (id, actor_id, ap_id, content_html, visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, '{}'::jsonb)"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(format!("https://{DOMAIN}/users/author/posts/{id}"))
    .bind(body)
    .bind(visibility)
    .execute(pool)
    .await
    .expect("post fixture inserted");
}

/// The rendered feed partial, as the container would receive it.
async fn feed_body(state: AppState) -> String {
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/feed?page=1")
                .body(Body::empty())
                .expect("request built"),
        )
        .await
        .expect("router responded");

    assert_eq!(response.status(), StatusCode::OK, "the feed must serve");

    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body read");
    String::from_utf8(bytes.to_vec()).expect("the partial is UTF-8")
}

// ..... Tests .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn anonymous_feed_serves_public_posts(pool: PgPool) {
    let author = insert_actor(&pool, "author").await;
    insert_post(&pool, author, "public", "<p>a public note</p>").await;

    let body = feed_body(test_state(pool)).await;

    assert!(
        body.contains("a public note"),
        "the public timeline served no post: {body}"
    );
    assert_eq!(
        body.matches("<article").count(),
        1,
        "expected exactly one rendered post: {body}"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn anonymous_feed_omits_unlisted_posts(pool: PgPool) {
    let author = insert_actor(&pool, "author").await;
    insert_post(&pool, author, "unlisted", "<p>an unlisted note</p>").await;
    // Also a public one, so a feed that serves nothing at all cannot
    // satisfy the assertion below by being empty.
    insert_post(&pool, author, "public", "<p>a public note</p>").await;

    let body = feed_body(test_state(pool)).await;

    assert!(
        body.contains("a public note"),
        "the public timeline served no post, so nothing was tested: {body}"
    );
    assert!(
        !body.contains("an unlisted note"),
        "an unlisted post reached the public timeline: {body}"
    );
}
