// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The job write path, applying, and the capability grant.
//!
//! Every table exercised here already existed and had no writer outside
//! the test files: four routes read applications, the grant revocation
//! path was built, and nothing had ever created an application or minted
//! a grant. These assert the write half, and the properties that make
//! the capability worth having rather than a copy handed over.

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

async fn insert_actor(pool: &PgPool, username: &str, actor_type: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ($1, $2, $3, $4, 'KEY', TRUE) RETURNING id",
    )
    .bind(actor_type)
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("actor fixture")
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

fn posting() -> noombat_jobs::NewJobPosting {
    noombat_jobs::NewJobPosting {
        title: "Rust Engineer".to_owned(),
        description_md: "Write Rust.".to_owned(),
        location: Some("Berlin".to_owned()),
        remote: Some(true),
        salary_min: None,
        salary_max: None,
        currency: None,
        requirements: None,
        expires_at: None,
        publish: true,
    }
}

async fn send(
    pool: PgPool,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(t) = bearer {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let request = builder
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_owned())))
        .expect("request");

    let response = build_router(test_state(pool))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body read");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ..... The write path .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_posting_records_the_member_who_created_it(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let recruiter = insert_actor(&pool, "rita", "individual").await;
    sqlx::query(
        "INSERT INTO organization_members (organization_id, member_id, role) \
         VALUES ($1, $2, 'recruiter')",
    )
    .bind(org)
    .bind(recruiter)
    .execute(&pool)
    .await
    .expect("membership");

    let job = noombat_jobs::create_job(&pool, org, Some(recruiter), DOMAIN, &posting())
        .await
        .expect("posting created");

    let created_by: Option<Uuid> =
        sqlx::query_scalar("SELECT created_by FROM job_postings WHERE id = $1")
            .bind(job.id)
            .fetch_one(&pool)
            .await
            .expect("readable");

    // Without this the whole PostingAccess model is inert: `is_creator`
    // is false for every posting, so a recruiter cannot reach even their
    // own applications.
    assert_eq!(created_by, Some(recruiter));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_actor_posting_as_itself_records_no_creator(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;

    let job = noombat_jobs::create_job(&pool, org, Some(org), DOMAIN, &posting())
        .await
        .expect("posting created");

    let created_by: Option<Uuid> =
        sqlx::query_scalar("SELECT created_by FROM job_postings WHERE id = $1")
            .bind(job.id)
            .fetch_one(&pool)
            .await
            .expect("readable");

    assert_eq!(created_by, None, "the schema specifies NULL for this case");
}

// ..... Applying .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn applying_creates_an_application_and_mints_one_grant(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");
    let token = token_for(&pool, applicant, "alice").await;

    let (status, body) = send(
        pool.clone(),
        "POST",
        &format!("/jobs/{}/apply", job.id),
        Some(&token),
        Some(r#"{"cover_letter_md":"I would like to apply.","include_cv":false}"#),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
    let grant_token = parsed["grant_token"].as_str().expect("a token is returned");

    let applications: i64 = sqlx::query_scalar("SELECT count(*) FROM job_applications")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(applications, 1);

    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM job_application_grants")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(grants, 1, "an application without a grant is unreadable");

    // The token is not stored. What is stored is its hash, so a read of
    // the table is not a read of every live capability.
    let stored: String = sqlx::query_scalar("SELECT token_hash FROM job_application_grants")
        .fetch_one(&pool)
        .await
        .expect("readable");
    assert_ne!(stored, grant_token);
    assert!(!stored.contains(grant_token));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_unpublished_posting_is_not_open(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let mut params = posting();
    params.publish = false;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &params)
        .await
        .expect("posting created");
    let token = token_for(&pool, applicant, "alice").await;

    let (status, _) = send(
        pool.clone(),
        "POST",
        &format!("/jobs/{}/apply", job.id),
        Some(&token),
        Some(r#"{"include_cv":false}"#),
    )
    .await;

    // `published_at` is the verification gate as well as the publication
    // flag, so this also refuses a posting whose organisation has lost
    // its domain.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn applying_twice_is_refused(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");
    let token = token_for(&pool, applicant, "alice").await;

    let body = r#"{"include_cv":false}"#;
    let uri = format!("/jobs/{}/apply", job.id);
    let (first, _) = send(pool.clone(), "POST", &uri, Some(&token), Some(body)).await;
    let (second, _) = send(pool.clone(), "POST", &uri, Some(&token), Some(body)).await;

    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(second, StatusCode::BAD_REQUEST);
    let applications: i64 = sqlx::query_scalar("SELECT count(*) FROM job_applications")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(applications, 1);
}

// ..... The capability .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_dereference_spends_a_use_and_is_logged_against_its_grant(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");
    let token = token_for(&pool, applicant, "alice").await;

    let (_, body) = send(
        pool.clone(),
        "POST",
        &format!("/jobs/{}/apply", job.id),
        Some(&token),
        Some(r#"{"include_cv":false}"#),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
    let application_id = parsed["id"].as_str().expect("an id");
    let grant_token = parsed["grant_token"].as_str().expect("a token");

    let before: i32 =
        sqlx::query_scalar("SELECT document_uses_remaining FROM job_application_grants")
            .fetch_one(&pool)
            .await
            .expect("readable");

    let (status, _) = send(
        pool.clone(),
        "GET",
        &format!("/applications/{application_id}?token={grant_token}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the grant is the authorisation");

    let after: i32 =
        sqlx::query_scalar("SELECT document_uses_remaining FROM job_application_grants")
            .fetch_one(&pool)
            .await
            .expect("readable");
    assert_eq!(after, before - 1, "a capability with no budget is a copy");

    // `grant_id` had no writer at all, so the disclosure log could
    // record a moderator's read and structurally could not record the
    // one it was designed for.
    let logged: Option<Uuid> = sqlx::query_scalar(
        "SELECT grant_id FROM job_application_accesses WHERE outcome = 'disclosed'",
    )
    .fetch_one(&pool)
    .await
    .expect("readable");
    assert!(
        logged.is_some(),
        "the dereference was logged without a grant"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_cannot_be_walked_onto_another_application(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let alice = insert_actor(&pool, "alice", "individual").await;
    let bob = insert_actor(&pool, "bob", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");

    let alice_token = token_for(&pool, alice, "alice").await;
    let bob_token = token_for(&pool, bob, "bob").await;
    let uri = format!("/jobs/{}/apply", job.id);
    let body = r#"{"include_cv":false}"#;

    let (_, alice_body) = send(pool.clone(), "POST", &uri, Some(&alice_token), Some(body)).await;
    let (_, bob_body) = send(pool.clone(), "POST", &uri, Some(&bob_token), Some(body)).await;

    let alice_json: serde_json::Value = serde_json::from_str(&alice_body).expect("JSON");
    let bob_json: serde_json::Value = serde_json::from_str(&bob_body).expect("JSON");

    // Alice's live token, pointed at Bob's application by editing the URL.
    let (status, _) = send(
        pool.clone(),
        "GET",
        &format!(
            "/applications/{}?token={}",
            bob_json["id"].as_str().expect("id"),
            alice_json["grant_token"].as_str().expect("token")
        ),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_is_bound_to_one_audience_origin(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");
    let session = token_for(&pool, applicant, "alice").await;

    let (_, body) = send(
        pool.clone(),
        "POST",
        &format!("/jobs/{}/apply", job.id),
        Some(&session),
        Some(r#"{"include_cv":false}"#),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let application_id = parsed["id"].as_str().expect("id");
    let grant_token = parsed["grant_token"].as_str().expect("token");
    let dereference = format!("/applications/{application_id}?token={grant_token}");

    let (before, _) = send(pool.clone(), "GET", &dereference, None, None).await;
    assert_eq!(before, StatusCode::OK);

    // Re-point the grant at another host, standing in for a token that
    // leaked to one. The audience is immutable after minting precisely
    // so a capability cannot be walked; this asserts the check exists.
    sqlx::query("UPDATE job_application_grants SET audience_origin = 'https://elsewhere.example'")
        .execute(&pool)
        .await
        .expect("re-pointed");

    let (after, _) = send(pool.clone(), "GET", &dereference, None, None).await;
    assert_eq!(
        after,
        StatusCode::FORBIDDEN,
        "a token addressed elsewhere must dereference nowhere"
    );

    // And a refused attempt spends nothing.
    let remaining: i32 =
        sqlx::query_scalar("SELECT document_uses_remaining FROM job_application_grants")
            .fetch_one(&pool)
            .await
            .expect("readable");
    assert_eq!(remaining, 49, "a refusal must not charge the budget");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_exhausted_grant_stops_working(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");
    let session = token_for(&pool, applicant, "alice").await;

    let (_, body) = send(
        pool.clone(),
        "POST",
        &format!("/jobs/{}/apply", job.id),
        Some(&session),
        Some(r#"{"include_cv":false}"#),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let dereference = format!(
        "/applications/{}?token={}",
        parsed["id"].as_str().expect("id"),
        parsed["grant_token"].as_str().expect("token")
    );

    sqlx::query("UPDATE job_application_grants SET document_uses_remaining = 1")
        .execute(&pool)
        .await
        .expect("budget set");

    let (last, _) = send(pool.clone(), "GET", &dereference, None, None).await;
    assert_eq!(last, StatusCode::OK);

    let (spent, _) = send(pool.clone(), "GET", &dereference, None, None).await;
    assert_eq!(
        spent,
        StatusCode::FORBIDDEN,
        "a budget that never runs out is not a budget"
    );

    let remaining: i32 =
        sqlx::query_scalar("SELECT document_uses_remaining FROM job_application_grants")
            .fetch_one(&pool)
            .await
            .expect("readable");
    assert_eq!(remaining, 0, "the budget must not go negative");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn withdrawing_ends_the_employers_access(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");
    let session = token_for(&pool, applicant, "alice").await;

    let (_, body) = send(
        pool.clone(),
        "POST",
        &format!("/jobs/{}/apply", job.id),
        Some(&session),
        Some(r#"{"include_cv":false}"#),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let application_id = parsed["id"].as_str().expect("id");
    let grant_token = parsed["grant_token"].as_str().expect("token");
    let dereference = format!("/applications/{application_id}?token={grant_token}");

    let (before, _) = send(pool.clone(), "GET", &dereference, None, None).await;
    assert_eq!(before, StatusCode::OK);

    let (withdrawn, _) = send(
        pool.clone(),
        "DELETE",
        &format!("/applications/{application_id}"),
        Some(&session),
        None,
    )
    .await;
    assert_eq!(withdrawn, StatusCode::NO_CONTENT);

    // This is what makes withdrawal mean something. Handing the employer
    // a copy of the document could never have achieved it.
    let (after, _) = send(pool.clone(), "GET", &dereference, None, None).await;
    assert_eq!(after, StatusCode::FORBIDDEN);

    // The applicant keeps their own record of having applied.
    let status: String = sqlx::query_scalar("SELECT status FROM job_applications")
        .fetch_one(&pool)
        .await
        .expect("readable");
    assert_eq!(status, "withdrawn");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_dereference_is_logged_too(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let applicant = insert_actor(&pool, "alice", "individual").await;
    let job = noombat_jobs::create_job(&pool, org, None, DOMAIN, &posting())
        .await
        .expect("posting created");
    let session = token_for(&pool, applicant, "alice").await;

    let (_, body) = send(
        pool.clone(),
        "POST",
        &format!("/jobs/{}/apply", job.id),
        Some(&session),
        Some(r#"{"include_cv":false}"#),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let application_id = parsed["id"].as_str().expect("id");
    let grant_token = parsed["grant_token"].as_str().expect("token");

    sqlx::query(
        "UPDATE job_application_grants SET revoked_at = now(), \
         revoked_reason = 'applicant_revoked', state = 'revoked'",
    )
    .execute(&pool)
    .await
    .expect("revoked");

    let (status, _) = send(
        pool.clone(),
        "GET",
        &format!("/applications/{application_id}?token={grant_token}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An applicant is owed the attempt as much as the success.
    let denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM job_application_accesses WHERE outcome = 'denied'",
    )
    .fetch_one(&pool)
    .await
    .expect("countable");
    assert_eq!(denied, 1);
}

// ..... The reader set .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn only_an_owner_or_the_creator_may_open_a_posting(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let creator = insert_actor(&pool, "rita", "individual").await;
    let other = insert_actor(&pool, "ravi", "individual").await;
    for member in [creator, other] {
        sqlx::query(
            "INSERT INTO organization_members (organization_id, member_id, role) \
             VALUES ($1, $2, 'recruiter')",
        )
        .bind(org)
        .bind(member)
        .execute(&pool)
        .await
        .expect("membership");
    }

    let job = noombat_jobs::create_job(&pool, org, Some(creator), DOMAIN, &posting())
        .await
        .expect("posting created");

    let creator_session = token_for(&pool, creator, "rita").await;
    let other_session = token_for(&pool, other, "ravi").await;
    let uri = format!("/api/v1/jobs/{}/readers", job.id);
    let body = format!(r#"{{"access":"listed","members":["{other}"]}}"#);

    // A recruiter cannot widen a colleague's posting.
    let (refused, _) = send(pool.clone(), "PUT", &uri, Some(&other_session), Some(&body)).await;
    assert_eq!(refused, StatusCode::FORBIDDEN);

    let (allowed, text) = send(
        pool.clone(),
        "PUT",
        &uri,
        Some(&creator_session),
        Some(&body),
    )
    .await;
    assert_eq!(allowed, StatusCode::NO_CONTENT, "{text}");

    // The first writer this table has ever had.
    let listed: i64 = sqlx::query_scalar("SELECT count(*) FROM job_posting_readers")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(listed, 1);

    // And being listed is what now admits them.
    let (now_allowed, _) = send(
        pool.clone(),
        "GET",
        &format!("/api/v1/jobs/{}/applications", job.id),
        Some(&other_session),
        None,
    )
    .await;
    assert_eq!(now_allowed, StatusCode::OK);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn naming_an_outsider_is_refused_rather_than_stored(pool: PgPool) {
    let org = insert_actor(&pool, "acme", "organization").await;
    let creator = insert_actor(&pool, "rita", "individual").await;
    let outsider = insert_actor(&pool, "mallory", "individual").await;
    sqlx::query(
        "INSERT INTO organization_members (organization_id, member_id, role) \
         VALUES ($1, $2, 'owner')",
    )
    .bind(org)
    .bind(creator)
    .execute(&pool)
    .await
    .expect("membership");

    let job = noombat_jobs::create_job(&pool, org, Some(creator), DOMAIN, &posting())
        .await
        .expect("posting created");
    let session = token_for(&pool, creator, "rita").await;

    let (status, _) = send(
        pool.clone(),
        "PUT",
        &format!("/api/v1/jobs/{}/readers", job.id),
        Some(&session),
        Some(&format!(
            r#"{{"access":"listed","members":["{outsider}"]}}"#
        )),
    )
    .await;

    // The predicate would refuse them anyway, so storing the row would
    // be a control that reports success and grants nothing.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let listed: i64 = sqlx::query_scalar("SELECT count(*) FROM job_posting_readers")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(listed, 0);
}
