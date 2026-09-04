// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Removing reported content removes its pictures from storage.
//!
//! Driven through the assembled router rather than against the helpers,
//! and that is the whole point of the file. `media_attachments.post_id`
//! cascades, so deleting the post drops the rows and leaves the bytes;
//! asserting on `post_object_keys` and `purge_objects` directly would
//! still pass if the route stopped calling them, which is the failure
//! this is written to catch.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::media::MediaStore;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

fn test_state(pool: PgPool, media: MediaStore) -> AppState {
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
        media,
        deletion_grace_days: 30,
        allow_unsigned_fetch: false,
    }
}

async fn insert_person(pool: &PgPool, username: &str, role: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             instance_role) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE, $4) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("person fixture")
}

async fn moderator_token(pool: &PgPool, actor_id: Uuid, username: &str) -> String {
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
        noombat_core::actor::InstanceRole::Moderator,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await
    .expect("session created")
    .access_token
}

/// A post with one stored image, returning the post and its object key.
async fn post_with_an_image(pool: &PgPool, media: &MediaStore, author: Uuid) -> (Uuid, String) {
    let post_id: Uuid = sqlx::query_scalar(
        "INSERT INTO posts (actor_id, ap_id, content_html, ap_object) \
         VALUES ($1, $2, '<p>hi</p>', '{}'::jsonb) RETURNING id",
    )
    .bind(author)
    .bind(format!("https://{DOMAIN}/posts/{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("post fixture");

    let key = Uuid::new_v4().simple().to_string();
    media.put(&key, b"bytes").await.expect("write object");
    sqlx::query(
        "INSERT INTO media_attachments \
             (actor_id, post_id, media_type, object_key, backend, purpose, url) \
         VALUES ($1, $2, 'image/png', $3, 'local', 'post', $4)",
    )
    .bind(author)
    .bind(post_id)
    .bind(&key)
    .bind(format!("https://{DOMAIN}/media/{key}"))
    .execute(pool)
    .await
    .expect("attachment fixture");

    (post_id, key)
}

async fn open_report(pool: &PgPool, reporter: Uuid, post_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO reports (reporter_id, target_post_id, reason) \
         VALUES ($1, $2, 'illegal') RETURNING id",
    )
    .bind(reporter)
    .bind(post_id)
    .fetch_one(pool)
    .await
    .expect("report fixture")
}

/// Resolving a report by removing the content takes the picture off the
/// disk as well as the post out of the database. Leaving it would keep
/// the reported image served to anyone who already had its URL.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn removing_reported_content_removes_its_images(pool: PgPool) {
    let root = tempfile::tempdir().expect("temp dir");
    let media = MediaStore::local(root.path()).expect("store");

    let author = insert_person(&pool, "author", "user").await;
    let reporter = insert_person(&pool, "reporter", "user").await;
    let moderator = insert_person(&pool, "mod", "moderator").await;
    let token = moderator_token(&pool, moderator, "mod").await;

    let (post_id, key) = post_with_an_image(&pool, &media, author).await;
    let report_id = open_report(&pool, reporter, post_id).await;

    assert!(media.get(&key).await.is_ok(), "the fixture must be stored");

    let app = build_router(test_state(pool.clone(), media.clone()));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/reports/{report_id}/resolve"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("action=remove_content"))
                .unwrap(),
        )
        .await
        .expect("resolve the report");

    assert_eq!(response.status(), StatusCode::OK);

    let posts: i64 = sqlx::query_scalar("SELECT count(*) FROM posts WHERE id = $1")
        .bind(post_id)
        .fetch_one(&pool)
        .await
        .expect("count posts");
    assert_eq!(posts, 0, "the reported post must be gone");

    assert!(
        media.get(&key).await.is_err(),
        "the reported post's image must not survive on disk"
    );
}
