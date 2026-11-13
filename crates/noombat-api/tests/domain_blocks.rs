// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Instance domain blocks, enforced on signed deliveries to an inbox.
//!
//! Each test first shows the peer's signed Follow handled as expected
//! before the step under test, so a fault in the signature the test builds
//! cannot pass for a refusal.

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_signature_normalization::Config as SigConfig;
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const DOMAIN: &str = "noombat.example";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";
const BLOCKED: &str = "blocked.example";
const MALLORY: &str = "https://blocked.example/users/mallory";
const MASTODON_KEY_ID: &str = "https://blocked.example/users/mallory#main-key";

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

async fn insert_person(pool: &PgPool, username: &str) {
    sqlx::query(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE)",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .execute(pool)
    .await
    .expect("person fixture");
}

/// The key `MALLORY` signs with, and the key id its deliveries name.
struct Peer {
    key_id: String,
    private_pem: String,
}

/// Caches `MALLORY` as the inbox does after fetching an actor document that
/// publishes its key under `key_id`, which is stored as published.
async fn insert_mallory(pool: &PgPool, key_id: &str) -> Peer {
    let keys = noombat_identity::keys::generate_rsa_keypair().expect("a test key pair");
    sqlx::query(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, \
                             public_key_id, is_local, inbox_url) \
         VALUES ('individual', $1, 'mallory', $2, $3, $4, FALSE, $5)",
    )
    .bind(MALLORY)
    .bind(BLOCKED)
    .bind(&keys.public_pem)
    .bind(key_id)
    .bind(format!("{MALLORY}/inbox"))
    .execute(pool)
    .await
    .expect("peer fixture");

    Peer {
        key_id: key_id.to_owned(),
        private_pem: keys.private_pem,
    }
}

async fn block(pool: &PgPool) {
    sqlx::query("INSERT INTO domain_restrictions (domain, restriction) VALUES ($1, 'block')")
        .bind(BLOCKED)
        .execute(pool)
        .await
        .expect("domain block");
}

/// A Follow of a local member from `MALLORY`, signed as this instance's
/// delivery worker signs a delivery to that member's inbox.
fn signed_follow(peer: &Peer, username: &str) -> Request<Body> {
    let path = format!("/users/{username}/inbox");
    let body = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{BLOCKED}/follows/{username}"),
        "type": "Follow",
        "actor": MALLORY,
        "object": format!("https://{DOMAIN}/users/{username}"),
    })
    .to_string();
    let digest = format!(
        "SHA-256={}",
        noombat_federation::digest::sha256(body.as_bytes())
    );
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();

    let signed = BTreeMap::from([
        ("host".to_owned(), DOMAIN.to_owned()),
        ("date".to_owned(), date.clone()),
        ("digest".to_owned(), digest.clone()),
    ]);
    let signature = SigConfig::default()
        .mastodon_compat()
        .require_digest()
        .begin_sign("POST", &path, signed)
        .expect("every signed header is present")
        .sign(peer.key_id.clone(), |signing_string| {
            noombat_federation::delivery::rsa_sha256_sign(signing_string, &peer.private_pem)
        })
        .expect("the peer's key signs")
        .signature_header();

    Request::builder()
        .method("POST")
        .uri(path)
        .header("host", DOMAIN)
        .header("date", date)
        .header("digest", digest)
        .header("signature", signature)
        .header("content-type", "application/activity+json")
        .body(Body::from(body))
        .expect("inbox request")
}

/// Sends one request to the inbox and returns its status.
///
/// The inbox checks a signature inside `block_in_place`, which panics on
/// the current-thread runtime `sqlx::test` provides, so the request runs on
/// a multi-thread runtime in a thread of its own, over a second pool on the
/// test's database.
fn deliver(pool: &PgPool, request: Request<Body>) -> StatusCode {
    let options = (*pool.connect_options()).clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a multi-thread runtime")
            .block_on(async move {
                let second = PgPoolOptions::new()
                    .max_connections(4)
                    .connect_with(options)
                    .await
                    .expect("a second pool on the test database");
                let status = build_router(test_state(second.clone()))
                    .oneshot(request)
                    .await
                    .expect("the router is infallible")
                    .status();
                second.close().await;
                status
            })
    })
    .join()
    .expect("the delivery thread finished")
}

async fn mallory_follows(pool: &PgPool, username: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM follows f \
                        JOIN actors a ON a.id = f.follower_id \
                        JOIN actors t ON t.id = f.following_id \
                        WHERE a.ap_id = $1 AND t.username = $2 AND t.is_local)",
    )
    .bind(MALLORY)
    .bind(username)
    .fetch_one(pool)
    .await
    .expect("follows readable")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_blocked_domain_cannot_follow_a_member(pool: PgPool) {
    insert_person(&pool, "alice").await;
    insert_person(&pool, "bob").await;
    let peer = insert_mallory(&pool, MASTODON_KEY_ID).await;

    assert_eq!(
        deliver(&pool, signed_follow(&peer, "alice")),
        StatusCode::ACCEPTED,
        "the peer's delivery was refused before any block"
    );
    assert!(mallory_follows(&pool, "alice").await);

    block(&pool).await;
    let status = deliver(&pool, signed_follow(&peer, "bob"));

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        !mallory_follows(&pool, "bob").await,
        "a follow from a blocked domain was recorded"
    );
}

// Known defect: a key id on another host evades the domain block; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: a blocked domain gets through with a key id on another host"
)]
async fn a_blocked_domain_cannot_follow_with_a_key_id_on_another_host(pool: PgPool) {
    insert_person(&pool, "alice").await;
    insert_person(&pool, "bob").await;
    let peer = insert_mallory(&pool, "https://keys.example/mallory").await;

    assert_eq!(
        deliver(&pool, signed_follow(&peer, "alice")),
        StatusCode::ACCEPTED,
        "a key id on another host did not verify before any block"
    );

    block(&pool).await;
    let status = deliver(&pool, signed_follow(&peer, "bob"));
    let admitted = status.is_success() || mallory_follows(&pool, "bob").await;

    assert!(
        !admitted,
        "known defect: a blocked domain gets through with a key id on another host"
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "refused as blocked");
}

// Known defect: the block lookup compares hosts case-sensitively; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: a blocked domain gets through when its key id capitalises the host"
)]
async fn a_domain_block_holds_whatever_the_case_of_the_host(pool: PgPool) {
    insert_person(&pool, "alice").await;
    insert_person(&pool, "bob").await;
    let peer = insert_mallory(&pool, "https://BLOCKED.EXAMPLE/users/mallory#main-key").await;

    assert_eq!(
        deliver(&pool, signed_follow(&peer, "alice")),
        StatusCode::ACCEPTED,
        "a key id with a capitalised host did not verify before any block"
    );

    block(&pool).await;
    let status = deliver(&pool, signed_follow(&peer, "bob"));
    let admitted = status.is_success() || mallory_follows(&pool, "bob").await;

    assert!(
        !admitted,
        "known defect: a blocked domain gets through when its key id capitalises the host"
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "refused as blocked");
}

// Known defect: the block lookup ignores a port in the key id; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: a blocked domain gets through when its key id names the port"
)]
async fn a_domain_block_holds_when_the_key_id_names_the_port(pool: PgPool) {
    insert_person(&pool, "alice").await;
    insert_person(&pool, "bob").await;
    let peer = insert_mallory(&pool, "https://blocked.example:443/users/mallory#main-key").await;

    assert_eq!(
        deliver(&pool, signed_follow(&peer, "alice")),
        StatusCode::ACCEPTED,
        "a key id naming the port did not verify before any block"
    );

    block(&pool).await;
    let status = deliver(&pool, signed_follow(&peer, "bob"));
    let admitted = status.is_success() || mallory_follows(&pool, "bob").await;

    assert!(
        !admitted,
        "known defect: a blocked domain gets through when its key id names the port"
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "refused as blocked");
}

// Known defect: a failed block lookup is read as "not blocked"; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: a blocked domain gets through when the block lookup fails"
)]
async fn a_failed_block_lookup_refuses_the_delivery(pool: PgPool) {
    insert_person(&pool, "alice").await;
    insert_person(&pool, "bob").await;
    insert_person(&pool, "carol").await;
    let peer = insert_mallory(&pool, MASTODON_KEY_ID).await;

    // The block check runs before the signature is verified, so the refusals
    // below say nothing about the signature: this delivery does.
    assert_eq!(
        deliver(&pool, signed_follow(&peer, "carol")),
        StatusCode::ACCEPTED,
        "the peer's delivery was refused before any block"
    );
    block(&pool).await;

    assert_eq!(
        deliver(&pool, signed_follow(&peer, "alice")),
        StatusCode::FORBIDDEN,
        "the block did not refuse while its lookup worked"
    );

    // Any error from the lookup will do; a missing table is one a test can cause.
    sqlx::query("ALTER TABLE domain_restrictions RENAME TO domain_restrictions_unreachable")
        .execute(&pool)
        .await
        .expect("block table renamed");
    let status = deliver(&pool, signed_follow(&peer, "bob"));
    let admitted = status.is_success() || mallory_follows(&pool, "bob").await;

    assert!(
        !admitted,
        "known defect: a blocked domain gets through when the block lookup fails"
    );
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "refused for the lookup, not for the signature"
    );
}
