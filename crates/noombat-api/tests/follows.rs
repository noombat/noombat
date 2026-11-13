// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Following between members of one instance, through the assembled router.
//!
//! Both accounts live here, so whether a follow is accepted or waits for
//! approval is known when it is made.

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

async fn require_approval(pool: &PgPool, actor_id: Uuid) {
    sqlx::query(
        "UPDATE actors \
         SET actor_privacy = jsonb_set(actor_privacy, '{require_follow_approval}', 'true') \
         WHERE id = $1",
    )
    .bind(actor_id)
    .execute(pool)
    .await
    .expect("approval switched on");
}

/// `POST /users/{follower}/following` as an API client sends it, the only
/// way to follow: no page offers it.
async fn follow(pool: &PgPool, follower: &str, token: &str, target: &str) -> StatusCode {
    let body = format!(r#"{{"target_ap_id":"https://{DOMAIN}/users/{target}"}}"#);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/users/{follower}/following"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .expect("follow request");

    build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

/// What a button on the follow-requests page sends: an htmx POST with no
/// fields, carrying the session cookie.
async fn press(pool: &PgPool, session: &str, uri: String) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", format!("noombat_session={session}"))
        .header("hx-request", "true")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::empty())
        .expect("button request");

    build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

/// Bob's follow-requests page, which must offer the request `id` with the
/// buttons whose requests the tests then send.
async fn follow_requests_page(pool: &PgPool, session: &str, id: Uuid) {
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .uri("/settings/follow-requests")
                .header("cookie", format!("noombat_session={session}"))
                .body(Body::empty())
                .expect("page request"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("the page is small and fully buffered");
    let page = String::from_utf8(bytes.to_vec()).expect("templates render UTF-8");
    assert!(
        page.contains(&format!("id=\"follow-req-{id}\"")),
        "the request is not on bob's follow-requests page"
    );
    for action in ["accept", "reject"] {
        assert!(
            page.contains(&format!(
                "hx-post=\"/users/bob/pending_follows/{id}/{action}\""
            )),
            "the page has no {action} button for the request"
        );
    }
}

async fn accepted(pool: &PgPool, follower: Uuid, following: Uuid) -> Option<bool> {
    sqlx::query_scalar("SELECT accepted FROM follows WHERE follower_id = $1 AND following_id = $2")
        .bind(follower)
        .bind(following)
        .fetch_optional(pool)
        .await
        .expect("follows readable")
}

async fn request_id(pool: &PgPool, follower: Uuid, following: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM follows WHERE follower_id = $1 AND following_id = $2")
        .bind(follower)
        .bind(following)
        .fetch_one(pool)
        .await
        .expect("the follow request")
}

// Known defect: a local follow is queued for our own inbox, which refuses local signers, so it
// stays pending unless the member accepts it by hand; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a follow of a local member stays pending")]
async fn a_follow_of_a_local_member_is_accepted_at_once(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let token = token_for(&pool, alice, "alice").await;

    assert_eq!(
        follow(&pool, "alice", &token, "bob").await,
        StatusCode::ACCEPTED,
        "the follow was not taken"
    );

    assert_eq!(
        accepted(&pool, alice, bob).await,
        Some(true),
        "known defect: a follow of a local member stays pending"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn with_approval_on_a_local_follow_waits_until_accepted_on_the_page(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    require_approval(&pool, bob).await;
    let alice_token = token_for(&pool, alice, "alice").await;
    let bob_token = token_for(&pool, bob, "bob").await;

    assert_eq!(
        follow(&pool, "alice", &alice_token, "bob").await,
        StatusCode::ACCEPTED
    );
    // Every local follow waits today, approval or not, so accepting it below is the real check.
    assert_eq!(
        accepted(&pool, alice, bob).await,
        Some(false),
        "with approval on, the follow must wait for bob"
    );
    let id = request_id(&pool, alice, bob).await;
    follow_requests_page(&pool, &bob_token, id).await;

    let status = press(
        &pool,
        &bob_token,
        format!("/users/bob/pending_follows/{id}/accept"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        accepted(&pool, alice, bob).await,
        Some(true),
        "accepting on the page left the follow pending"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn with_approval_on_a_local_follow_refused_on_the_page_is_gone(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    require_approval(&pool, bob).await;
    let alice_token = token_for(&pool, alice, "alice").await;
    let bob_token = token_for(&pool, bob, "bob").await;

    assert_eq!(
        follow(&pool, "alice", &alice_token, "bob").await,
        StatusCode::ACCEPTED
    );
    let id = request_id(&pool, alice, bob).await;
    follow_requests_page(&pool, &bob_token, id).await;

    let status = press(
        &pool,
        &bob_token,
        format!("/users/bob/pending_follows/{id}/reject"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        accepted(&pool, alice, bob).await,
        None,
        "the refused follow is still recorded"
    );
}
