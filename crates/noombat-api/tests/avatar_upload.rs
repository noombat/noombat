// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Avatar upload and serving, through the assembled router.
//!
//! Driven through `build_router` rather than by calling the handlers,
//! because the failure this feature has already had once was not in a
//! handler. The profile form posted an `avatar_url` at a route that
//! answered 415 for the encoding, would have answered 403 for the bearer
//! check, and discarded the field in the handler as a third line of
//! defence. Every piece existed; nothing connected. So these tests
//! assert what a request gets back.
//!
//! The properties worth stating:
//!
//! An unauthenticated upload must not store anything. The route takes no
//! username, so there is no other account to aim it at, and the only
//! question is whether a caller with no session is refused.
//!
//! A file that is not one of the two accepted formats must be refused on
//! its *content*. The route never reads the filename or the declared
//! content type, so a request that lies about both is the interesting
//! case.
//!
//! Serving must answer `304` to a matching `If-None-Match`. Without a
//! validator every avatar on a page is refetched in full on every view,
//! which is the cost that makes people reach for a bucket URL.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::error::Result;
use noombat_core::extension::SearchBackend;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::session::SessionConfig;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const USERNAME: &str = "alice";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";
const BOUNDARY: &str = "----noombattestboundary";

struct NoSearch;

#[async_trait::async_trait]
impl SearchBackend for NoSearch {
    async fn upsert(&self, _index: &str, _id: &str, _document: serde_json::Value) -> Result<()> {
        Ok(())
    }
    async fn delete(&self, _index: &str, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn search(
        &self,
        _index: &str,
        _query: &str,
        _filters: Option<&str>,
        _limit: usize,
        _offset: usize,
    ) -> Result<Vec<serde_json::Value>> {
        Ok(Vec::new())
    }
}

fn session_config() -> SessionConfig {
    SessionConfig {
        jwt_secret: JWT_SECRET.to_owned(),
        domain: DOMAIN.to_owned(),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
    }
}

/// A state whose media root is unique to the test that built it.
fn test_state(pool: PgPool) -> (AppState, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("noombat-avatar-test-{}", Uuid::new_v4()));
    let state = AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
        http_client: reqwest::Client::new(),
        open_registrations: true,
        admin_token: None,
        search: Some(Arc::new(NoSearch) as Arc<dyn SearchBackend>),
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: Some(session_config()),
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
        media: noombat_api::media::MediaStore::local(&root).expect("temp media root"),
    };
    (state, root)
}

async fn insert_actor(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE)"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{USERNAME}"))
    .bind(USERNAME)
    .bind(DOMAIN)
    .execute(pool)
    .await
    .expect("actor fixture inserted");
    id
}

async fn sign_in(pool: &PgPool, actor_id: Uuid) -> String {
    noombat_identity::session::create_session(
        pool,
        &session_config(),
        actor_id,
        USERNAME,
        noombat_core::actor::InstanceRole::User,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await
    .expect("session created")
    .access_token
}

/// A PNG of the given size, built rather than checked in.
fn png(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(image::RgbaImage::new(width, height))
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .expect("encoded");
    out
}

/// A multipart body whose declared filename and content type are both
/// lies. Nothing in the route reads either, and that is the point.
fn multipart(field: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field}\"; filename=\"avatar.gif\"\r\n\
             Content-Type: image/gif\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn upload(state: AppState, token: Option<&str>, bytes: &[u8]) -> StatusCode {
    let mut request = Request::builder()
        .method("POST")
        .uri("/settings/avatar")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    build_router(state)
        .oneshot(
            request
                .body(Body::from(multipart("avatar", bytes)))
                .expect("request"),
        )
        .await
        .expect("the router is infallible")
        .status()
}

// ..... Tests .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_upload_without_a_session_stores_nothing(pool: PgPool) {
    insert_actor(&pool).await;
    let (state, _root) = test_state(pool.clone());

    assert_eq!(
        upload(state, None, &png(64, 64)).await,
        StatusCode::UNAUTHORIZED
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM media_attachments")
        .fetch_one(&pool)
        .await
        .expect("counted");
    assert_eq!(rows, 0, "an unauthenticated upload created a row");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_signed_in_upload_is_stored_and_then_served(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = sign_in(&pool, actor_id).await;
    let (state, _root) = test_state(pool.clone());

    assert_eq!(
        upload(state.clone(), Some(&token), &png(64, 64)).await,
        StatusCode::SEE_OTHER,
        "a successful upload redirects back to the profile form"
    );

    // The row, the column and the object all agree.
    let (object_key, media_type, backend, url): (String, String, String, String) =
        sqlx::query_as("SELECT object_key, media_type, backend, url FROM media_attachments")
            .fetch_one(&pool)
            .await
            .expect("one row");
    assert_eq!(media_type, "image/png");
    assert_eq!(backend, "local");
    assert_eq!(url, format!("https://{DOMAIN}/media/{object_key}"));

    let stored: Option<String> = sqlx::query_scalar("SELECT avatar_url FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_one(&pool)
        .await
        .expect("actor readable");
    assert_eq!(
        stored.as_deref(),
        Some(url.as_str()),
        "the actor was not pointed at the new avatar, so `icon` stays dead"
    );

    // And the serve route returns it, to a caller with no session.
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri(format!("/media/{object_key}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("image/png")
    );
    assert_eq!(
        response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok()),
        Some(format!("\"{object_key}\"").as_str())
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_matching_validator_is_answered_with_not_modified(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = sign_in(&pool, actor_id).await;
    let (state, _root) = test_state(pool.clone());
    upload(state.clone(), Some(&token), &png(32, 32)).await;

    let object_key: String = sqlx::query_scalar("SELECT object_key FROM media_attachments")
        .fetch_one(&pool)
        .await
        .expect("one row");

    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri(format!("/media/{object_key}"))
                .header(header::IF_NONE_MATCH, format!("\"{object_key}\""))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_declared_type_is_not_believed(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = sign_in(&pool, actor_id).await;
    let (state, _root) = test_state(pool.clone());

    // The part claims `image/gif` and `avatar.gif` in both directions;
    // the bytes are a PNG. The upload succeeds and is recorded as PNG,
    // which is what "decided by decoding" means.
    assert_eq!(
        upload(state, Some(&token), &png(16, 16)).await,
        StatusCode::SEE_OTHER
    );
    let media_type: String = sqlx::query_scalar("SELECT media_type FROM media_attachments")
        .fetch_one(&pool)
        .await
        .expect("one row");
    assert_eq!(media_type, "image/png");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_file_that_is_not_an_accepted_image_is_refused(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = sign_in(&pool, actor_id).await;
    let (state, _root) = test_state(pool.clone());

    assert_eq!(
        upload(state, Some(&token), b"#!/bin/sh\necho not an image\n").await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM media_attachments")
        .fetch_one(&pool)
        .await
        .expect("counted");
    assert_eq!(rows, 0);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn uploading_again_replaces_rather_than_accumulates(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = sign_in(&pool, actor_id).await;
    let (state, root) = test_state(pool.clone());

    upload(state.clone(), Some(&token), &png(64, 64)).await;
    let first: String = sqlx::query_scalar("SELECT object_key FROM media_attachments")
        .fetch_one(&pool)
        .await
        .expect("one row");

    upload(state, Some(&token), &png(48, 48)).await;
    let keys: Vec<String> = sqlx::query_scalar("SELECT object_key FROM media_attachments")
        .fetch_all(&pool)
        .await
        .expect("rows");
    assert_eq!(keys.len(), 1, "a second upload accumulated a row");
    assert_ne!(keys[0], first);

    // The replaced object is gone from disk, not merely unreferenced.
    assert!(
        !root.join(&first).exists(),
        "the previous object was left behind"
    );
    assert!(root.join(&keys[0]).exists());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn erasure_removes_the_object_as_well_as_the_row(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = sign_in(&pool, actor_id).await;
    let (state, root) = test_state(pool.clone());
    upload(state.clone(), Some(&token), &png(64, 64)).await;

    let key: String = sqlx::query_scalar("SELECT object_key FROM media_attachments")
        .fetch_one(&pool)
        .await
        .expect("one row");
    assert!(root.join(&key).exists());

    noombat_api::erasure::erase_actor(&pool, &state.search, &state.media, actor_id)
        .await
        .expect("erased");

    // The row goes with the actor. The bytes are the half that a
    // database-only erasure leaves behind, unreferenced and permanent.
    assert!(
        !root.join(&key).exists(),
        "erasure left the image on disk: the row is gone and nothing knows the file exists"
    );
}
