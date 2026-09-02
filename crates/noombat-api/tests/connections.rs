// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The connection lifecycle and the relationship lists, through the
//! assembled router.
//!
//! Two properties are asserted here rather than against the repository,
//! because the repository was never the part that was missing:
//!
//! 1. **The nesting rule holds end to end.** A connection who does not
//!    follow reaches followers-tier content, and a follower who is not a
//!    connection does not reach connections-tier content.
//! 2. **The lists are private until their owner says otherwise.** The
//!    columns default to private, and the collection handlers read them,
//!    so an outsider cannot map the graph by walking `/followers`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::authorisation::{ConnectionState, FollowStatus};
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

async fn send(
    pool: PgPool,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> StatusCode {
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

    build_router(test_state(pool))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

// ..... Lifecycle .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_invitation_is_pending_until_the_addressee_accepts(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let alice_token = token_for(&pool, alice, "alice").await;
    let bob_token = token_for(&pool, bob, "bob").await;

    let status = send(
        pool.clone(),
        "POST",
        "/users/alice/connections",
        Some(&alice_token),
        Some(r#"{"username":"bob"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Pending grants nothing on either side.
    let before = noombat_identity::connections::relationship(&pool, Some(bob), alice)
        .await
        .expect("relationship readable");
    assert_eq!(before.connection, ConnectionState::Pending);
    assert!(
        !before.is_connection(),
        "a pending invitation is not a connection"
    );
    assert!(
        !before.is_follower(),
        "a pending invitation is not a follow"
    );

    let status = send(
        pool.clone(),
        "POST",
        &format!("/users/bob/pending_connections/{alice}/accept"),
        Some(&bob_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let after = noombat_identity::connections::relationship(&pool, Some(bob), alice)
        .await
        .expect("relationship readable");
    assert_eq!(after.connection, ConnectionState::Accepted);
    // The nesting rule, end to end: no follow row exists.
    assert_eq!(after.follow, FollowStatus::None);
    assert!(
        after.is_follower(),
        "an accepted connection counts as a follower"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_addressee_may_accept(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let carol = insert_person(&pool, "carol").await;
    let alice_token = token_for(&pool, alice, "alice").await;
    let carol_token = token_for(&pool, carol, "carol").await;

    noombat_identity::connections::invite(&pool, alice, bob, None)
        .await
        .expect("invitation stored");

    // The requester cannot accept their own invitation.
    let status = send(
        pool.clone(),
        "POST",
        &format!("/users/alice/pending_connections/{alice}/accept"),
        Some(&alice_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Nor can an unrelated account.
    let status = send(
        pool.clone(),
        "POST",
        &format!("/users/carol/pending_connections/{alice}/accept"),
        Some(&carol_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let state = noombat_identity::connections::state(&pool, alice, bob)
        .await
        .expect("state readable");
    assert_eq!(
        state,
        ConnectionState::Pending,
        "the invitation must still be unanswered"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_rejected_invitation_leaves_no_record_of_who_asked(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let bob_token = token_for(&pool, bob, "bob").await;

    noombat_identity::connections::invite(&pool, alice, bob, None)
        .await
        .expect("invitation stored");

    let status = send(
        pool.clone(),
        "POST",
        &format!("/users/bob/pending_connections/{alice}/reject"),
        Some(&bob_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM connections")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(rows, 0, "a refused invitation must not linger as a row");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_reversed_pair_does_not_create_a_second_row(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let bob_token = token_for(&pool, bob, "bob").await;

    noombat_identity::connections::invite(&pool, alice, bob, None)
        .await
        .expect("invitation stored");

    // Bob invites Alice back rather than accepting. The route answers
    // the same 204 either way, so it does not report that Alice asked
    // first, and the pair index keeps it to one row.
    let status = send(
        pool.clone(),
        "POST",
        "/users/bob/connections",
        Some(&bob_token),
        Some(r#"{"username":"alice"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM connections")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(rows, 1, "the unordered pair must hold exactly one row");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn withdrawing_and_disconnecting_are_one_route(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let alice_token = token_for(&pool, alice, "alice").await;

    // Withdrawn before it is answered.
    noombat_identity::connections::invite(&pool, alice, bob, None)
        .await
        .expect("invitation stored");
    let status = send(
        pool.clone(),
        "DELETE",
        &format!("/users/alice/connections/{bob}"),
        Some(&alice_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        noombat_identity::connections::state(&pool, alice, bob)
            .await
            .expect("state readable"),
        ConnectionState::None
    );

    // And ended after it is accepted, through the same route.
    noombat_identity::connections::invite(&pool, alice, bob, None)
        .await
        .expect("invitation stored");
    noombat_identity::connections::accept(&pool, bob, alice)
        .await
        .expect("accepted");
    let status = send(
        pool.clone(),
        "DELETE",
        &format!("/users/alice/connections/{bob}"),
        Some(&alice_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        noombat_identity::connections::state(&pool, alice, bob)
            .await
            .expect("state readable"),
        ConnectionState::None
    );
}

// ..... List visibility .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_lists_are_private_until_their_owner_opens_them(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let _bob = insert_person(&pool, "bob").await;

    // Default. A stranger walking the graph gets the same answer as for
    // an account that does not exist.
    for path in [
        "/users/alice/followers",
        "/users/alice/following",
        "/users/alice/connections",
    ] {
        let status = send(pool.clone(), "GET", path, None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} leaked by default");
    }

    // The owner always reads their own.
    let alice_token = token_for(&pool, alice, "alice").await;
    for path in [
        "/users/alice/followers",
        "/users/alice/following",
        "/users/alice/connections",
    ] {
        let status = send(pool.clone(), "GET", path, Some(&alice_token), None).await;
        assert_eq!(status, StatusCode::OK, "{path} refused its own owner");
    }

    // Opened to the public, an anonymous caller is admitted.
    sqlx::query("UPDATE actors SET followers_visibility = 'public' WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .expect("setting saved");
    let status = send(pool.clone(), "GET", "/users/alice/followers", None, None).await;
    assert_eq!(status, StatusCode::OK);
    // The other two are untouched by that change.
    let status = send(pool.clone(), "GET", "/users/alice/following", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_connections_tier_list_admits_a_connection_and_not_a_follower(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let carol = insert_person(&pool, "carol").await;

    sqlx::query("UPDATE actors SET followers_visibility = 'connections' WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .expect("setting saved");

    // Bob connects; Carol merely follows.
    noombat_identity::connections::invite(&pool, bob, alice, None)
        .await
        .expect("invitation stored");
    noombat_identity::connections::accept(&pool, alice, bob)
        .await
        .expect("accepted");
    noombat_identity::repo::create_follow(&pool, carol, alice, true)
        .await
        .expect("follow stored");

    let bob_token = token_for(&pool, bob, "bob").await;
    let carol_token = token_for(&pool, carol, "carol").await;

    let status = send(
        pool.clone(),
        "GET",
        "/users/alice/followers",
        Some(&bob_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a connection must be admitted");

    let status = send(
        pool.clone(),
        "GET",
        "/users/alice/followers",
        Some(&carol_token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the nesting runs one way: a follower is not a connection"
    );
}
