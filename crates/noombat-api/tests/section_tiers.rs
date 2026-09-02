// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Three surfaces that disagreed about the same rows.
//!
//! Each of these was found while wiring something else, and each is the
//! kind of fault a passing suite does not notice, because every part
//! worked and the parts disagreed:
//!
//! 1. The profile page asked for public sections whatever the viewer
//!    was, so an owner could not see their own restricted sections on
//!    their own profile while the CV showed them.
//! 2. `list_skills` took a two-way boolean where its five siblings take
//!    a tier, so one CV mixed followers-tier experience with
//!    public-only skills.
//! 3. Blocking severed the follow locally and told the peer nothing, so
//!    the peer kept delivering posts from the blocked account.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::privacy::SectionVisibility;
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

async fn insert_remote(pool: &PgPool, username: &str, host: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             inbox_url) \
         VALUES ('individual', $1, $2, $3, 'KEY', FALSE, $4) RETURNING id",
    )
    .bind(format!("https://{host}/users/{username}"))
    .bind(username)
    .bind(host)
    .bind(format!("https://{host}/users/{username}/inbox"))
    .fetch_one(pool)
    .await
    .expect("remote fixture")
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

async fn add_skill(pool: &PgPool, actor: Uuid, name: &str, visibility: &str) {
    sqlx::query("INSERT INTO skills (actor_id, name, visibility) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(name)
        .bind(visibility)
        .execute(pool)
        .await
        .expect("skill fixture");
}

async fn profile_body(pool: PgPool, username: &str, bearer: Option<&str>) -> String {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/users/{username}"));
    if let Some(t) = bearer {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let response = build_router(test_state(pool))
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::OK, "the profile must serve");
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body read");
    String::from_utf8_lossy(&bytes).into_owned()
}

// ..... The profile page and the viewer's tier .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_owner_sees_their_own_restricted_sections(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    add_skill(&pool, alice, "PublicSkill", "public").await;
    add_skill(&pool, alice, "PrivateSkill", "private").await;

    let anonymous = profile_body(pool.clone(), "alice", None).await;
    assert!(anonymous.contains("PublicSkill"));
    assert!(
        !anonymous.contains("PrivateSkill"),
        "a stranger must not reach a private section"
    );

    let token = token_for(&pool, alice, "alice").await;
    let own = profile_body(pool.clone(), "alice", Some(&token)).await;
    assert!(
        own.contains("PrivateSkill"),
        "the page asked for public sections whatever the viewer was, so an \
         owner could not see their own restricted sections on their own profile"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_connection_reaches_the_connections_tier_and_a_follower_does_not(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let bob = insert_person(&pool, "bob").await;
    let carol = insert_person(&pool, "carol").await;

    add_skill(&pool, alice, "FollowersSkill", "followers").await;
    add_skill(&pool, alice, "ConnectionsSkill", "connections").await;

    // Bob connects; Carol merely follows.
    noombat_identity::connections::invite(&pool, bob, alice, None)
        .await
        .expect("invite");
    noombat_identity::connections::accept(&pool, alice, bob)
        .await
        .expect("accept");
    noombat_identity::repo::create_follow(&pool, carol, alice, true)
        .await
        .expect("follow");

    let bob_view = profile_body(
        pool.clone(),
        "alice",
        Some(&token_for(&pool, bob, "bob").await),
    )
    .await;
    // The nesting rule, on a rendered page: a connection is admitted
    // wherever followers are, and to the narrower tier as well.
    assert!(bob_view.contains("FollowersSkill"));
    assert!(bob_view.contains("ConnectionsSkill"));

    let carol_view = profile_body(
        pool.clone(),
        "alice",
        Some(&token_for(&pool, carol, "carol").await),
    )
    .await;
    assert!(carol_view.contains("FollowersSkill"));
    assert!(
        !carol_view.contains("ConnectionsSkill"),
        "the nesting runs one way: a follower is not a connection"
    );
}

// ..... Skills take a tier, like every other section .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn skills_answer_the_same_tier_question_as_every_other_section(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    for (name, visibility) in [
        ("P", "public"),
        ("F", "followers"),
        ("C", "connections"),
        ("X", "private"),
    ] {
        add_skill(&pool, alice, name, visibility).await;
    }

    // A two-way boolean could express only the first and last of these.
    // The middle two are what a follower or a connection reading a CV
    // gets, and what the boolean silently withheld from them.
    let cases = [
        (SectionVisibility::Public, vec!["P"]),
        (SectionVisibility::Followers, vec!["P", "F"]),
        (SectionVisibility::Connections, vec!["P", "F", "C"]),
        (SectionVisibility::Private, vec!["P", "F", "C", "X"]),
    ];

    for (tier, expected) in cases {
        let skills = noombat_identity::profile::list_skills(&pool, alice, &tier)
            .await
            .expect("skills readable");
        let mut names: Vec<String> = skills.into_iter().map(|s| s.name).collect();
        names.sort();
        let mut want: Vec<String> = expected.into_iter().map(str::to_owned).collect();
        want.sort();
        assert_eq!(names, want, "tier {tier:?}");
    }
}

// ..... Blocking tells the peer .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn blocking_a_remote_actor_undoes_the_follow_on_their_instance(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    let remote = insert_remote(&pool, "mallory", "peer.example").await;

    // Alice follows the remote account, and that Follow carries an id
    // the peer accepted it under.
    noombat_identity::repo::create_follow_with_ap_id(
        &pool,
        alice,
        remote,
        true,
        Some("https://noombat.example/users/alice#follow-1"),
    )
    .await
    .expect("follow stored");

    let token = token_for(&pool, alice, "alice").await;
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users/alice/blocks")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"target_ap_id":"https://peer.example/users/mallory"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::CREATED);

    let queued: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT payload FROM delivery_queue ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("queue readable");

    let kinds: Vec<&str> = queued
        .iter()
        .filter_map(|a| a.get("type").and_then(|t| t.as_str()))
        .collect();

    assert!(kinds.contains(&"Block"), "{kinds:?}");
    assert!(
        kinds.contains(&"Undo"),
        "the Block travelled and the Undo did not, so the peer still \
         believes this account follows theirs and keeps delivering: {kinds:?}"
    );

    // The Undo has to name the Follow the peer accepted, or the peer
    // cannot match it to anything.
    let undo = queued
        .iter()
        .find(|a| a.get("type").and_then(|t| t.as_str()) == Some("Undo"))
        .expect("an Undo was queued");
    assert_eq!(undo["object"]["type"], "Follow");
    assert_eq!(
        undo["object"]["id"],
        "https://noombat.example/users/alice#follow-1"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn blocking_without_a_follow_sends_no_undo(pool: PgPool) {
    let alice = insert_person(&pool, "alice").await;
    insert_remote(&pool, "mallory", "peer.example").await;

    let token = token_for(&pool, alice, "alice").await;
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users/alice/blocks")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"target_ap_id":"https://peer.example/users/mallory"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::CREATED);

    let undos: i64 =
        sqlx::query_scalar("SELECT count(*) FROM delivery_queue WHERE payload->>'type' = 'Undo'")
            .fetch_one(&pool)
            .await
            .expect("countable");

    // Undoing a follow that never existed would have the peer looking
    // for an activity it never saw.
    assert_eq!(undos, 0);
}
