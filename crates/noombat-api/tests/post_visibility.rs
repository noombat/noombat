// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Who may open a restricted post at its permalink.
//!
//! Driven through the assembled router with real sessions. The rule has
//! unit tests of its own, and those pass whether or not the route calls
//! it. A refusal is a 404 rather than a 403, so the answer does not
//! confirm that the post exists.

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

async fn insert_post(pool: &PgPool, author: Uuid, username: &str, visibility: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO posts (actor_id, ap_id, content_html, visibility, ap_object) \
         VALUES ($1, $2, '<p>restricted</p>', $3, '{}'::jsonb) RETURNING id",
    )
    .bind(author)
    .bind(format!(
        "https://{DOMAIN}/users/{username}/posts/{}",
        Uuid::new_v4()
    ))
    .bind(visibility)
    .fetch_one(pool)
    .await
    .expect("post fixture")
}

/// What the permalink answers. No bearer is a visitor.
async fn permalink_status(
    pool: &PgPool,
    username: &str,
    post_id: Uuid,
    bearer: Option<&str>,
    accept: Option<&str>,
) -> StatusCode {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/users/{username}/posts/{post_id}"));
    if let Some(t) = bearer {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    if let Some(a) = accept {
        builder = builder.header("accept", a);
    }
    build_router(test_state(pool.clone()))
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("the router is infallible")
        .status()
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_followers_only_post_is_found_only_by_followers_and_its_author(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let carol = insert_person(&pool, "carol").await;
    let dave = insert_person(&pool, "dave").await;

    // Bob follows Alice; Dave has asked and not been accepted; Carol has
    // done neither.
    noombat_identity::repo::create_follow(&pool, bob, alice, true)
        .await
        .expect("follow");
    noombat_identity::repo::create_follow(&pool, dave, alice, false)
        .await
        .expect("pending follow");

    let post = insert_post(&pool, alice, "alice", "followers").await;

    assert_eq!(
        permalink_status(&pool, "alice", post, None, None).await,
        StatusCode::NOT_FOUND,
        "a visitor opened a followers-only post"
    );
    assert_eq!(
        permalink_status(
            &pool,
            "alice",
            post,
            None,
            Some("application/activity+json")
        )
        .await,
        StatusCode::NOT_FOUND,
        "an anonymous ActivityPub fetch read a followers-only post"
    );

    let carol_token = token_for(&pool, carol, "carol").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&carol_token), None).await,
        StatusCode::NOT_FOUND,
        "a signed-in member who does not follow the author opened a followers-only post"
    );

    let dave_token = token_for(&pool, dave, "dave").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&dave_token), None).await,
        StatusCode::NOT_FOUND,
        "a follow request nobody accepted opened a followers-only post"
    );

    let bob_token = token_for(&pool, bob, "bob").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&bob_token), None).await,
        StatusCode::OK,
        "a follower was refused a followers-only post"
    );

    let alice_token = token_for(&pool, alice, "alice").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&alice_token), None).await,
        StatusCode::OK,
        "the author was refused their own post"
    );
}

// `connections` is the narrowest tier a post can carry.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_connections_only_post_is_found_only_by_connections_and_its_author(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let carol = insert_person(&pool, "carol").await;
    let dave = insert_person(&pool, "dave").await;

    // Bob connects with Alice; Carol merely follows her; Dave does neither.
    noombat_identity::connections::invite(&pool, bob, alice, None)
        .await
        .expect("invite");
    noombat_identity::connections::accept(&pool, alice, bob)
        .await
        .expect("accept");
    noombat_identity::repo::create_follow(&pool, carol, alice, true)
        .await
        .expect("follow");

    let post = insert_post(&pool, alice, "alice", "connections").await;

    assert_eq!(
        permalink_status(&pool, "alice", post, None, None).await,
        StatusCode::NOT_FOUND,
        "a visitor opened a connections-only post"
    );

    let dave_token = token_for(&pool, dave, "dave").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&dave_token), None).await,
        StatusCode::NOT_FOUND,
        "a signed-in stranger opened a connections-only post"
    );

    let carol_token = token_for(&pool, carol, "carol").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&carol_token), None).await,
        StatusCode::NOT_FOUND,
        "a follower who is not a connection opened a connections-only post"
    );

    let bob_token = token_for(&pool, bob, "bob").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&bob_token), None).await,
        StatusCode::OK,
        "a connection was refused a connections-only post"
    );

    let alice_token = token_for(&pool, alice, "alice").await;
    assert_eq!(
        permalink_status(&pool, "alice", post, Some(&alice_token), None).await,
        StatusCode::OK,
        "the author was refused their own post"
    );
}
