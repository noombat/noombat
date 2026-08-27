// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The moderator route for reading one application, and the log row it
//! must write.
//!
//! Driven through the assembled router with a real session, because the
//! failure worth catching is a moderator read that succeeds and writes
//! no log row. A test below the router would pass on a handler that
//! never inserted anything.

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
        admin_token: None,
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

async fn insert_application(pool: &PgPool) -> Uuid {
    let applicant: Uuid = sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, 'alice', $2, 'KEY', TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/alice"))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("applicant fixture");

    sqlx::query_scalar(
        "INSERT INTO applications \
             (applicant_id, listing_title, listing_organization, ap_id, cover_letter_md) \
         VALUES ($1, 'Engineer', 'Acme', $2, 'please hire me') RETURNING id",
    )
    .bind(applicant)
    .bind(format!("https://{DOMAIN}/applications/1"))
    .fetch_one(pool)
    .await
    .expect("application fixture")
}

/// The middleware reads the role from the actor row, not from the token,
/// so the fixture has to carry it.
async fn insert_staff(pool: &PgPool, username: &str, instance_role: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, instance_role) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE, $4) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(instance_role)
    .fetch_one(pool)
    .await
    .expect("staff fixture")
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

async fn accesses(pool: PgPool, id: Uuid, bearer: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/me/applications/{id}/accesses"));
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = build_router(test_state(pool))
        .oneshot(builder.body(Body::empty()).expect("request construction"))
        .await
        .expect("the router is infallible");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body within limit");
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn review(pool: PgPool, id: Uuid, bearer: Option<&str>, body: &str) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/applications/{id}/review"))
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(body.to_owned()))
        .expect("request construction");

    build_router(test_state(pool))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_anonymous_request_is_refused(pool: PgPool) {
    let id = insert_application(&pool).await;

    let status = review(pool, id, None, r#"{"reason":"investigating a report"}"#).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_ordinary_user_is_refused(pool: PgPool) {
    let id = insert_application(&pool).await;
    let actor = insert_staff(&pool, "plain", "user").await;
    let token = token_for(&pool, actor, "plain").await;

    let status = review(
        pool,
        id,
        Some(&token),
        r#"{"reason":"investigating a report"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_moderator_without_a_reason_is_refused(pool: PgPool) {
    let id = insert_application(&pool).await;
    let actor = insert_staff(&pool, "mod", "moderator").await;
    let token = token_for(&pool, actor, "mod").await;

    let status = review(pool, id, Some(&token), r#"{"reason":"   "}"#).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_moderator_read_succeeds_and_is_logged(pool: PgPool) {
    let id = insert_application(&pool).await;
    let actor = insert_staff(&pool, "mod", "moderator").await;
    let token = token_for(&pool, actor, "mod").await;

    let status = review(
        pool.clone(),
        id,
        Some(&token),
        r#"{"reason":"report #12, alleged fraudulent listing"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The row is the point. A 200 with no log row is the failure this
    // whole route exists to prevent.
    let (reader, reason): (Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT reader_id, reason FROM application_accesses \
         WHERE application_id = $1 AND kind = 'moderator_review'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("exactly one moderator access row");

    assert_eq!(reader, Some(actor));
    assert_eq!(
        reason.as_deref(),
        Some("report #12, alleged fraudulent listing")
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_database_refuses_a_moderator_read_without_a_reason(pool: PgPool) {
    let id = insert_application(&pool).await;
    let reader: Uuid = sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, 'mod', $2, 'KEY', TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/mod"))
    .bind(DOMAIN)
    .fetch_one(&pool)
    .await
    .expect("moderator fixture");

    for (reader_id, reason) in [
        (Some(reader), None),
        (Some(reader), Some("   ")),
        (None, Some("investigating a report")),
    ] {
        let result = sqlx::query(
            "INSERT INTO application_accesses \
                 (application_id, reader_id, kind, outcome, reason) \
             VALUES ($1, $2, 'moderator_review', 'disclosed', $3)",
        )
        .bind(id)
        .bind(reader_id)
        .bind(reason)
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "accepted a moderator read with reader={reader_id:?} reason={reason:?}"
        );
    }

    // The same row with both present is accepted, so the rejections
    // above are the constraint and not a broken statement.
    sqlx::query(
        "INSERT INTO application_accesses \
             (application_id, reader_id, kind, outcome, reason) \
         VALUES ($1, $2, 'moderator_review', 'disclosed', 'investigating a report')",
    )
    .bind(id)
    .bind(reader)
    .execute(&pool)
    .await
    .expect("a reasoned moderator read is accepted");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_dereference_needs_no_reason(pool: PgPool) {
    // The constraint is on moderator reads alone. An employer following
    // a capability URL is authorised by the capability itself.
    let id = insert_application(&pool).await;

    sqlx::query(
        "INSERT INTO application_accesses (application_id, kind, outcome) \
         VALUES ($1, 'grant_dereference', 'disclosed')",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("a grant dereference is accepted without a reason");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_applicant_sees_the_moderator_read_and_its_reason(pool: PgPool) {
    let id = insert_application(&pool).await;
    let applicant: Uuid = sqlx::query_scalar("SELECT applicant_id FROM applications WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("applicant");
    let moderator = insert_staff(&pool, "mod", "moderator").await;
    let mod_token = token_for(&pool, moderator, "mod").await;
    review(
        pool.clone(),
        id,
        Some(&mod_token),
        r#"{"reason":"report #12"}"#,
    )
    .await;

    let token = token_for(&pool, applicant, "alice").await;
    let (status, body) = accesses(pool, id, Some(&token)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("moderator_review"), "{body}");
    assert!(body.contains("report #12"), "{body}");
    // The moderator is not named: the applicant learns that it happened
    // and why, not who to blame.
    assert!(!body.contains(&moderator.to_string()), "{body}");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn another_user_cannot_read_that_log(pool: PgPool) {
    let id = insert_application(&pool).await;
    let stranger = insert_staff(&pool, "eve", "user").await;
    let token = token_for(&pool, stranger, "eve").await;

    let (status, _) = accesses(pool, id, Some(&token)).await;

    // 404 rather than 403: a 403 would confirm the application exists.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_log_is_not_public(pool: PgPool) {
    let id = insert_application(&pool).await;

    let (status, _) = accesses(pool, id, None).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}
