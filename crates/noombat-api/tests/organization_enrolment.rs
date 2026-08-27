// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Self-serve organisation enrolment, through the assembled router.
//!
//! The property worth asserting is not that a row appears. It is that the
//! enroller comes out able to act for what they enrolled: an organisation
//! has no password and no session, so an actor with no owner row is
//! unreachable by anybody, for ever.

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

async fn enrol(pool: PgPool, bearer: Option<&str>, body: &str) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let response = build_router(test_state(pool))
        .oneshot(builder.body(Body::from(body.to_owned())).expect("request"))
        .await
        .expect("the router is infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body within limit");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn enrolling_makes_the_enroller_an_owner(pool: PgPool) {
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;

    let (status, body) = enrol(
        pool.clone(),
        Some(&token),
        r#"{"username":"acme","display_name":"Acme Ltd","claimed_domain":"acme.example"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body.contains("organization"), "{body}");

    let (org, role): (Uuid, String) = sqlx::query_as(
        "SELECT a.id, m.role FROM actors a \
         JOIN organization_members m ON m.organization_id = a.id \
         WHERE a.username = 'acme' AND a.actor_type = 'organization'",
    )
    .fetch_one(&pool)
    .await
    .expect("the organisation and its owner row exist");

    assert_eq!(role, "owner");

    // It is an actor in its own right: its own id, and its own key, or it
    // cannot be addressed or sign anything.
    let (ap_id, has_key): (String, bool) =
        sqlx::query_as("SELECT ap_id, private_key_pem IS NOT NULL FROM actors WHERE id = $1")
            .bind(org)
            .fetch_one(&pool)
            .await
            .expect("actor readable");
    assert_eq!(ap_id, format!("https://{DOMAIN}/users/acme"));
    assert!(has_key, "an organisation with no key can sign nothing");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn enrolment_requires_a_session(pool: PgPool) {
    // No owner could be recorded for an anonymous enroller, so the
    // organisation would be unreachable the moment it existed.
    let (status, _) = enrol(pool.clone(), None, r#"{"username":"acme"}"#).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actors WHERE username = 'acme'")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "a refused enrolment must leave nothing behind");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_taken_username_is_refused_and_leaves_nothing(pool: PgPool) {
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;
    insert_person(&pool, "acme").await;

    let (status, _) = enrol(pool.clone(), Some(&token), r#"{"username":"acme"}"#).await;

    assert_ne!(status, StatusCode::CREATED);
    let orgs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM actors WHERE actor_type = 'organization'")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(orgs, 0);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_can_read_applications_to_a_listing_it_publishes(pool: PgPool) {
    // Enrolment is only useful if it grants standing. This is the join
    // between the member set and the authorisation decision.
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;
    enrol(pool.clone(), Some(&token), r#"{"username":"acme"}"#).await;

    let org: Uuid = sqlx::query_scalar("SELECT id FROM actors WHERE username = 'acme'")
        .fetch_one(&pool)
        .await
        .expect("org");
    let listing: Uuid = sqlx::query_scalar(
        "INSERT INTO job_listings (actor_id, ap_id, title, description_md, description_html) \
         VALUES ($1, $2, 'Engineer', 'md', '<p>md</p>') RETURNING id",
    )
    .bind(org)
    .bind(format!("https://{DOMAIN}/jobs/1"))
    .fetch_one(&pool)
    .await
    .expect("listing");

    let request = Request::builder()
        .uri(format!("/api/v1/jobs/{listing}/applications"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let status = build_router(test_state(pool))
        .oneshot(request)
        .await
        .expect("infallible")
        .status();

    assert_eq!(status, StatusCode::OK, "the owner must be admitted");
}

// ..... The rel="me" publish gate .....

/// Enrol `acme` claiming `acme.example`, returning its actor id.
async fn enrolled_org(pool: &PgPool, token: &str) -> Uuid {
    enrol(
        pool.clone(),
        Some(token),
        r#"{"username":"acme","claimed_domain":"acme.example"}"#,
    )
    .await;
    sqlx::query_scalar("SELECT id FROM actors WHERE username = 'acme'")
        .fetch_one(pool)
        .await
        .expect("org")
}

async fn post_job(pool: PgPool, username: &str) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/users/{username}/jobs"))
        .header("content-type", "application/json")
        .header("authorization", "Bearer admin-token")
        .body(Body::from(
            r#"{"title":"Engineer","description_md":"md"}"#.to_owned(),
        ))
        .expect("request");
    let mut state = test_state(pool);
    state.admin_token = Some("admin-token".to_owned());
    build_router(state)
        .oneshot(request)
        .await
        .expect("infallible")
        .status()
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_organisation_cannot_publish_before_proving_domain_control(pool: PgPool) {
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;
    enrolled_org(&pool, &token).await;

    assert_eq!(post_job(pool, "acme").await, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_verified_link_to_the_claimed_domain_opens_the_gate(pool: PgPool) {
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;
    let org = enrolled_org(&pool, &token).await;

    // A subdomain of the claim, to prove the comparison is registrable
    // domain and not string equality.
    sqlx::query(
        "INSERT INTO verified_links (actor_id, url, verified_at) \
         VALUES ($1, 'https://careers.acme.example/about', now())",
    )
    .bind(org)
    .execute(&pool)
    .await
    .expect("verified link");

    assert_eq!(post_job(pool, "acme").await, StatusCode::CREATED);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_verified_link_to_another_domain_does_not(pool: PgPool) {
    // Controlling some domain is not controlling the one claimed. Without
    // this an organisation could verify a personal blog and publish as an
    // employer.
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;
    let org = enrolled_org(&pool, &token).await;

    for url in [
        "https://someone-elses-blog.example/me",
        // The lookalike: the claim as a label under a domain the attacker
        // registered.
        "https://acme.example.evil.test/",
    ] {
        sqlx::query(
            "INSERT INTO verified_links (actor_id, url, verified_at) VALUES ($1, $2, now())",
        )
        .bind(org)
        .bind(url)
        .execute(&pool)
        .await
        .expect("link");
    }

    assert_eq!(post_job(pool, "acme").await, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_unverified_link_does_not_open_the_gate(pool: PgPool) {
    // Added but never verified: `verified_at` is what `verify_link` writes
    // only when the back-link was actually found.
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;
    let org = enrolled_org(&pool, &token).await;

    sqlx::query(
        "INSERT INTO verified_links (actor_id, url, verified_at) \
         VALUES ($1, 'https://acme.example/', NULL)",
    )
    .bind(org)
    .execute(&pool)
    .await
    .expect("link");

    assert_eq!(post_job(pool, "acme").await, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_lapsed_domain_unpublishes_existing_listings(pool: PgPool) {
    let person = insert_person(&pool, "alice").await;
    let token = token_for(&pool, person, "alice").await;
    let org = enrolled_org(&pool, &token).await;
    let link: Uuid = sqlx::query_scalar(
        "INSERT INTO verified_links (actor_id, url, verified_at) \
         VALUES ($1, 'https://acme.example/', now()) RETURNING id",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .expect("link");

    assert_eq!(post_job(pool.clone(), "acme").await, StatusCode::CREATED);
    let published: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM job_listings WHERE actor_id = $1 AND published_at IS NOT NULL",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(published, 1, "a published listing is the precondition");

    // The domain lapses: re-verification clears `verified_at`.
    sqlx::query("UPDATE verified_links SET verified_at = NULL WHERE id = $1")
        .bind(link)
        .execute(&pool)
        .await
        .expect("lapse");

    let demoted = noombat_identity::verification::demote_lapsed_organizations(&pool)
        .await
        .expect("sweep ran");

    assert_eq!(demoted, 1);
    let still_published: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM job_listings WHERE actor_id = $1 AND published_at IS NOT NULL",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(still_published, 0, "the listing must not still be running");
}
