// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Which timeline the home feed serves, and to whom.
//!
//! A visitor it cannot identify gets the public timeline, from which
//! `unlisted` is excluded by definition. A signed-in viewer gets their
//! own feed, and falls back to the public one only on the first page,
//! only when they follow nobody.
//!
//! Both halves matter: the page decides which timeline to ask for and
//! the partial serves it, so a test of either alone can pass while the
//! feature is broken.
//!
//! The assertions count rendered posts rather than the status, because
//! the handler answers 200 with an empty body when it finds none.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::middleware::Principal;
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

/// Record an accepted follow, which is the only kind the feed reads.
async fn insert_follow(pool: &PgPool, follower: Uuid, following: Uuid) {
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(follower)
        .bind(following)
        .execute(pool)
        .await
        .expect("follow fixture inserted");
}

/// The feed page itself, as `viewer` would be served it. `None` is an
/// anonymous visitor.
///
/// The principal goes in as a request extension because that is how the
/// auth middleware supplies it, and the middleware does not run here.
async fn feed_page_body(state: AppState, viewer: Option<&str>) -> String {
    let mut request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("request built");

    if let Some(username) = viewer {
        request.extensions_mut().insert(Principal {
            username: Some(username.to_owned()),
            actor_uuid: None,
            instance_role: None,
            is_follower_of_target: None,
        });
    }

    let response = build_router(state)
        .oneshot(request)
        .await
        .expect("router responded");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the feed page must serve"
    );

    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body read");
    String::from_utf8(bytes.to_vec()).expect("the page is UTF-8")
}

/// The rendered feed partial, as the container would receive it.
async fn feed_body(state: AppState) -> String {
    feed_body_at(state, "/feed?page=1").await
}

/// The same, for a URL the page itself would request: `feed.html` puts
/// the viewer in the query string, and `feed_page.html` carries it into
/// the next page.
async fn feed_body_at(state: AppState, uri: &str) -> String {
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri(uri)
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

// The page is what decides which timeline the container asks for, so
// the partial answering correctly proves nothing on its own: the whole
// defect was a page that never sent a viewer.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_page_asks_for_the_viewers_own_feed(pool: PgPool) {
    let state = test_state(pool);

    // The query separator comes back escaped, and which form the
    // template engine picks is not the behaviour under test: a browser
    // decodes either before htmx sees the URL.
    let signed_in = feed_page_body(state.clone(), Some("viewer"))
        .await
        .replace("&#38;", "&")
        .replace("&amp;", "&");
    let anonymous = feed_page_body(state, None).await;

    assert!(
        signed_in.contains(r#"hx-get="/feed?page=1&user=viewer""#),
        "the page did not ask for the viewer's own feed: {signed_in}"
    );
    assert!(
        anonymous.contains(r#"hx-get="/feed?page=1""#),
        "an anonymous visitor was not sent to the public timeline: {anonymous}"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_signed_in_viewer_sees_the_actors_they_follow(pool: PgPool) {
    let viewer = insert_actor(&pool, "viewer").await;
    let followed = insert_actor(&pool, "followed").await;
    let stranger = insert_actor(&pool, "stranger").await;

    insert_follow(&pool, viewer, followed).await;
    insert_post(&pool, followed, "public", "<p>from someone followed</p>").await;
    insert_post(&pool, stranger, "public", "<p>from a stranger</p>").await;

    let body = feed_body_at(test_state(pool), "/feed?page=1&user=viewer").await;

    assert!(
        body.contains("from someone followed"),
        "a followed actor's post is missing: {body}"
    );
    // The stranger's post is public, so its absence is what separates a
    // personalised feed from the public timeline.
    assert!(
        !body.contains("from a stranger"),
        "the personalised feed served the public timeline instead: {body}"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_who_follows_nobody_gets_the_public_timeline(pool: PgPool) {
    insert_actor(&pool, "viewer").await;
    let stranger = insert_actor(&pool, "stranger").await;
    insert_post(&pool, stranger, "public", "<p>from a stranger</p>").await;

    let body = feed_body_at(test_state(pool), "/feed?page=1&user=viewer").await;

    assert!(
        body.contains("from a stranger"),
        "a viewer following nobody was left with an empty feed: {body}"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_public_fallback_stops_after_the_first_page(pool: PgPool) {
    insert_actor(&pool, "viewer").await;
    let stranger = insert_actor(&pool, "stranger").await;
    // More than a page of them. With fewer, the `OFFSET` on page two
    // returns nothing whether or not the guard is there, and the test
    // passes without exercising it.
    for n in 1..=25 {
        insert_post(
            &pool,
            stranger,
            "public",
            &format!("<p>public note {n}</p>"),
        )
        .await;
    }

    let state = test_state(pool);
    let first = feed_body_at(state.clone(), "/feed?page=1&user=viewer").await;
    let second = feed_body_at(state, "/feed?page=2&user=viewer").await;

    assert_eq!(
        first.matches("<article").count(),
        20,
        "page one should be a full page of the public timeline: {first}"
    );
    // Page two is the viewer's own feed, which is empty. Serving the
    // rest of the public timeline here would splice one timeline onto
    // the end of another mid-scroll.
    assert_eq!(
        second.matches("<article").count(),
        0,
        "the fallback continued past page one: {second}"
    );
}
