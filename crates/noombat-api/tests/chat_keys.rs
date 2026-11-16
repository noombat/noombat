// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Published chat keys, through the assembled router: a member publishes
//! the key their client made, and another member who may see their chat
//! address reads back the same bytes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::privacy::ActorPrivacy;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

// Made by OpenPGP.js 6.3.2 as the web client makes a member's key, for
// alice@ and bob@chat.noombat.example, bob's private key, and a second
// key for bob.
const ALICE_KEY: &str = concat!(
    "xjMEavjtdBYJKwYBBAHaRw8BAQdAObtQ9w/jRu94RYkXGd66R8p1UVhKjwN6oX8Y",
    "cDaZsu/NHDxhbGljZUBjaGF0Lm5vb21iYXQuZXhhbXBsZT7CwBMEExYKAIUFgmr4",
    "7XQDCwkHCRCOi2cFi3Lq2UUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdw",
    "anMub3JnoXQbf38tyMgl/oXnZpTIm/UEnOWS9Y7ec9unnTr6dDMFFQoIDgwEFgAC",
    "AQIZAQKbAwIeARYhBKZ0ogCEQn2Ro9vuLI6LZwWLcurZAACk8gEApeHCUDxC16j7",
    "H4zauxnT0ZUqIiyHPfo48oNVKNClY70BAOMiKoMEA5ESWbqllejxKkvLxeFsaade",
    "wb5B8XTlCbAKzjgEavjtdBIKKwYBBAGXVQEFAQEHQDD+ItNMWx8yy2U2CZJzEmOS",
    "0cRxskly1FVZp/HOZkxqAwEIB8K+BBgWCgBwBYJq+O10CRCOi2cFi3Lq2UUUAAAA",
    "AAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3Jn5M4KMHr7OU1e/ArnQyNf",
    "/Jz5MJ/TYGcdL//kqy1IzRECmwwWIQSmdKIAhEJ9kaPb7iyOi2cFi3Lq2QAA77IB",
    "APQJKEhIX3uJTz8X4GRklKEQKxVmtkbfOMECYgkh0bhXAPoDyIFtihoNZqThLvDq",
    "lr7uwZoyfj54sX9eg8FmHGXmDA==",
);
const BOB_KEY: &str = concat!(
    "xjMEavjtdBYJKwYBBAHaRw8BAQdAVBDZ6DY1WESjaQWgM4Phe0xM1VT5Yz0HE+F+",
    "I4PWff7NGjxib2JAY2hhdC5ub29tYmF0LmV4YW1wbGU+wsATBBMWCgCFBYJq+O10",
    "AwsJBwkQ5WHqhdqwtPBFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpz",
    "Lm9yZ0RSLt3471vX2e1+0gDANf8ML3pHQHPMJPUXWxWpSHosBRUKCA4MBBYAAgEC",
    "GQECmwMCHgEWIQQ6X6Ug0IYFf/qmEJHlYeqF2rC08AAAhocBAKeP3Ka7gA2hGMuc",
    "M1DWlRH90K3cUJhfD2ctdERqIpntAQCuvaP5BiX6IlAuU+SLjkDDmUIdV9vYdlIm",
    "Sg4pybshD844BGr47XQSCisGAQQBl1UBBQEBB0AGYyPiPlb77qfQ5Zv6lSuQaMWG",
    "q8G67JaFYPBUAMEBJwMBCAfCvgQYFgoAcAWCavjtdAkQ5WHqhdqwtPBFFAAAAAAA",
    "HAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ0kNT/rJts74fmzqPpIxJiFq",
    "23CO5eYTX+fmxJIo52YDApsMFiEEOl+lINCGBX/6phCR5WHqhdqwtPAAAH8sAP9V",
    "9EKKYbLmgTx+REbzNdwCrZBgVZdBTr4K4vWpcZj92wEA0nldF3D9Rd0M1MBliQLt",
    "mklGx11D1SgF26szNUzKtQ4=",
);
const BOB_SECRET_KEY: &str = concat!(
    "xVgEavjtdBYJKwYBBAHaRw8BAQdAVBDZ6DY1WESjaQWgM4Phe0xM1VT5Yz0HE+F+",
    "I4PWff4AAP9Wr5qKCuArJR25iZ8kogCUY/SpkmkeNUpxf9kbBhp+wQ6VzRo8Ym9i",
    "QGNoYXQubm9vbWJhdC5leGFtcGxlPsLAEwQTFgoAhQWCavjtdAMLCQcJEOVh6oXa",
    "sLTwRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmdEUi7d+O9b",
    "19ntftIAwDX/DC96R0BzzCT1F1sVqUh6LAUVCggODAQWAAIBAhkBApsDAh4BFiEE",
    "Ol+lINCGBX/6phCR5WHqhdqwtPAAAIaHAQCnj9ymu4ANoRjLnDNQ1pUR/dCt3FCY",
    "Xw9nLXREaiKZ7QEArr2j+QYl+iJQLlPki45Aw5lCHVfb2HZSJkoOKcm7IQ/HXQRq",
    "+O10EgorBgEEAZdVAQUBAQdABmMj4j5W++6n0OWb+pUrkGjFhqvBuuyWhWDwVADB",
    "AScDAQgHAAD/au/5ujEtD0y27w4z0aZBsq5ANzm3Ez7c6cCS3EhBYAgQXsK+BBgW",
    "CgBwBYJq+O10CRDlYeqF2rC08EUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVu",
    "cGdwanMub3JnSQ1P+sm2zvh+bOo+kjEmIWrbcI7l5hNf5+bEkijnZgMCmwwWIQQ6",
    "X6Ug0IYFf/qmEJHlYeqF2rC08AAAfywA/1X0QophsuaBPH5ERvM13AKtkGBVl0FO",
    "vgri9alxmP3bAQDSeV0XcP1F3QzUwGWJAu2aSUbHXUPVKAXbqzM1TMq1Dg==",
);
const BOB_NEW_KEY: &str = concat!(
    "xjMEavjttBYJKwYBBAHaRw8BAQdAA8w2dFucwmKeYoY91JWG7SXI4wIVQMm7237+",
    "TEfZBrbNGjxib2JAY2hhdC5ub29tYmF0LmV4YW1wbGU+wsATBBMWCgCFBYJq+O20",
    "AwsJBwkQonjiP+KLr9RFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpz",
    "Lm9yZwz5/Vg6ZlAD68qV4deVNOkk9GVoPE7ZTitY7ztdAkEMBRUKCA4MBBYAAgEC",
    "GQECmwMCHgEWIQShIZAKQg5s8PHFFu2ieOI/4ouv1AAA110A/1IioiRas5hozhmH",
    "wnx1T+4BnPj7Fms9EtjqMEvyVrFYAQDqN/i3ZHmhHIdWpsbv5yzcTSfVm7EJSstg",
    "DAvL6UN6C844BGr47bQSCisGAQQBl1UBBQEBB0C6Ecx0zKOGcveWmvNCMFiTFnfH",
    "SdIGKdGpCt5J3tN2SAMBCAfCvgQYFgoAcAWCavjttAkQonjiP+KLr9RFFAAAAAAA",
    "HAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ0harDCRue9IeQ/Tq7U+P8qC",
    "P2mOPQnmlBd7JwliY2QIApsMFiEEoSGQCkIObPDxxRbtonjiP+KLr9QAAHUdAP91",
    "+OTCXAKL7Uvvjxq6Y9x0pMSucEFsakFCwTDBz4716gD9Gl5m7B07yT/nMF+RXck/",
    "+K0HYgcX3JZYiiMVcwq5GA0=",
);

// A key for kim@chat.noombat.example, whose name has a letter the Kelvin
// sign folds into.
const KIM_KEY: &str = concat!(
    "xjMEavkGhhYJKwYBBAHaRw8BAQdADGKrVPZKV1UCNu6Hy0leRhMAFIxy4xRU5B1z",
    "UMWCKMvNGjxraW1AY2hhdC5ub29tYmF0LmV4YW1wbGU+wsATBBMWCgCFBYJq+QaG",
    "AwsJBwkQ40Q2C9IvtUJFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpz",
    "Lm9yZ7SEhDfueae9bVY/Ndrt/CQ37VJJ5jQsOYtv+jTdx148BRUKCA4MBBYAAgEC",
    "GQECmwMCHgEWIQSc4XOUN2vvFtHp9hXjRDYL0i+1QgAAVKQA/Ap37vCIXUsj3anV",
    "LCH/2N8pJ/nM8Bld/aaxnOrhffTGAQCxLjPw1Zq0Da1W8IpO0BQc+q/Tw1t8uiXw",
    "hQbFYzS+A844BGr5BoYSCisGAQQBl1UBBQEBB0D3AEZSsH5mSM/yXHGGO+LQv5af",
    "o624EcbX3RQ8hl0ObQMBCAfCvgQYFgoAcAWCavkGhgkQ40Q2C9IvtUJFFAAAAAAA",
    "HAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ5Y8GF4vHc1JPoVX+3imOwgY",
    "9+vfG4WhNmNP2cg5tpgqApsMFiEEnOFzlDdr7xbR6fYV40Q2C9IvtUIAAJQbAQCu",
    "MFf3TaLKUgAmJiFR/YZ1K28x/SKPrGEJbM8Z9B+SLQEAiA+AQlI6JNwXYP4vTnKF",
    "XWAtxmKbDoeInBeGrN2blQo=",
);

fn key(b64: &str) -> Vec<u8> {
    STANDARD.decode(b64).expect("a fixture")
}

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

/// A local member, with chat provisioned at `username@chat.noombat.example`
/// when `chat` holds, and their address visible to anyone or not.
async fn insert_member(pool: &PgPool, username: &str, chat: bool, visible: bool) -> Uuid {
    let privacy = ActorPrivacy {
        chatmail_visible: visible,
        ..ActorPrivacy::default()
    };
    sqlx::query_scalar(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, chatmail_addr, \
              actor_privacy) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE, $4, $5) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(chat.then(|| format!("{username}@chat.noombat.example")))
    .bind(serde_json::to_value(&privacy).expect("privacy serialises"))
    .fetch_one(pool)
    .await
    .expect("member fixture")
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

struct Reply {
    status: StatusCode,
    cache_control: Option<String>,
    body: Vec<u8>,
}

async fn send(pool: &PgPool, method: &str, uri: &str, bearer: Option<&str>, body: &[u8]) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder.body(Body::from(body.to_vec())).expect("request");
    let response = build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let cache_control = response
        .headers()
        .get("cache-control")
        .map(|value| value.to_str().expect("ASCII").to_owned());
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body within limit")
        .to_vec();
    Reply {
        status,
        cache_control,
        body,
    }
}

async fn publish(pool: &PgPool, token: &str, key: &[u8]) -> Reply {
    send(pool, "PUT", "/api/v1/me/chat_key", Some(token), key).await
}

async fn lookup(pool: &PgPool, token: Option<&str>, address: &str) -> Reply {
    let uri = format!("/api/v1/chat/keys/{address}");
    send(pool, "GET", &uri, token, &[]).await
}

/// The key bytes in a lookup's answer.
fn served_key(reply: &Reply) -> Vec<u8> {
    let json: serde_json::Value = serde_json::from_slice(&reply.body).expect("a JSON body");
    STANDARD
        .decode(json["key"].as_str().expect("a key field"))
        .expect("base64")
}

/// Bob has published his key; alice, a member without chat, is signed in.
struct Pair {
    bob: Uuid,
    alice: Uuid,
    alice_token: String,
}

async fn bob_publishes(pool: &PgPool, visible: bool) -> Pair {
    let bob = insert_member(pool, "bob", true, visible).await;
    let alice = insert_member(pool, "alice", false, true).await;
    let bob_token = token_for(pool, bob, "bob").await;
    let reply = publish(pool, &bob_token, &key(BOB_KEY)).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    Pair {
        bob,
        alice,
        alice_token: token_for(pool, alice, "alice").await,
    }
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn another_member_reads_back_the_bytes_published(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let reply = lookup(&pool, Some(&pair.alice_token), "bob@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(served_key(&reply), key(BOB_KEY));
    let json: serde_json::Value = serde_json::from_slice(&reply.body).expect("JSON");
    assert_eq!(json["address"], "bob@chat.noombat.example");
    assert_eq!(reply.cache_control.as_deref(), Some("private, no-store"));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_address_is_found_in_any_case(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let reply = lookup(&pool, Some(&pair.alice_token), "Bob@CHAT.noombat.example").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(served_key(&reply), key(BOB_KEY));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_key_replaces_the_old(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    let reply = publish(&pool, &bob_token, &key(BOB_NEW_KEY)).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let reply = lookup(&pool, Some(&pair.alice_token), "bob@chat.noombat.example").await;
    assert_eq!(served_key(&reply), key(BOB_NEW_KEY));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn publishing_needs_chat_set_up_and_a_session(pool: PgPool) {
    let alice = insert_member(&pool, "alice", false, true).await;
    let alice_token = token_for(&pool, alice, "alice").await;
    let reply = publish(&pool, &alice_token, &key(ALICE_KEY)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&reply.body).contains("chat is not set up"));
    let reply = send(&pool, "PUT", "/api/v1/me/chat_key", None, &key(ALICE_KEY)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_key_for_another_address_or_a_secret_key_is_refused(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let bob_token = token_for(&pool, bob, "bob").await;
    for (refused, reason) in [
        (key(ALICE_KEY), "names another address"),
        (key(BOB_SECRET_KEY), "secret key material"),
        (vec![0xA5; 8192], "not well-formed"),
    ] {
        let reply = publish(&pool, &bob_token, &refused).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{reason}");
        assert!(
            String::from_utf8_lossy(&reply.body).contains(reason),
            "{reason}"
        );
    }
    // Larger than any key: refused by the route before the body is read.
    let reply = publish(&pool, &bob_token, &[0xA5; 8193]).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_keys")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(stored, 0);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_address_hides_the_key_from_strangers_only(pool: PgPool) {
    let pair = bob_publishes(&pool, false).await;
    let address = "bob@chat.noombat.example";
    let stranger = lookup(&pool, Some(&pair.alice_token), address).await;
    assert_eq!(stranger.status, StatusCode::NOT_FOUND);
    let missing = lookup(
        &pool,
        Some(&pair.alice_token),
        "nobody@chat.noombat.example",
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(stranger.body, missing.body, "a hidden key reads as none");

    let bob_token = token_for(&pool, pair.bob, "bob").await;
    assert_eq!(
        lookup(&pool, Some(&bob_token), address).await.status,
        StatusCode::OK
    );

    // A follow counts once accepted.
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, FALSE)")
        .bind(pair.alice)
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("follow request");
    let requested = lookup(&pool, Some(&pair.alice_token), address).await;
    assert_eq!(requested.status, StatusCode::NOT_FOUND, "a follow request");
    sqlx::query("UPDATE follows SET accepted = TRUE")
        .execute(&pool)
        .await
        .expect("accepted");
    let follower = lookup(&pool, Some(&pair.alice_token), address).await;
    assert_eq!(follower.status, StatusCode::OK);

    // A connection counts once accepted, whoever asked.
    for (name, bob_asked) in [("carol", true), ("dave", false)] {
        let other = insert_member(&pool, name, false, true).await;
        let token = token_for(&pool, other, name).await;
        let (requester, addressee) = if bob_asked {
            (pair.bob, other)
        } else {
            (other, pair.bob)
        };
        sqlx::query("INSERT INTO connections (requester_id, addressee_id) VALUES ($1, $2)")
            .bind(requester)
            .bind(addressee)
            .execute(&pool)
            .await
            .expect("connection request");
        let requested = lookup(&pool, Some(&token), address).await;
        assert_eq!(requested.status, StatusCode::NOT_FOUND, "{name}: requested");
        sqlx::query("UPDATE connections SET accepted_at = now() WHERE requester_id = $1")
            .bind(requester)
            .execute(&pool)
            .await
            .expect("accepted");
        let connected = lookup(&pool, Some(&token), address).await;
        assert_eq!(connected.status, StatusCode::OK, "{name}: connected");
    }
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_who_blocked_the_viewer_reads_as_having_no_key(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let address = "bob@chat.noombat.example";
    sqlx::query("INSERT INTO blocks (actor_id, target_id) VALUES ($1, $2)")
        .bind(pair.bob)
        .bind(pair.alice)
        .execute(&pool)
        .await
        .expect("block");
    let blocked = lookup(&pool, Some(&pair.alice_token), address).await;
    let missing = lookup(
        &pool,
        Some(&pair.alice_token),
        "nobody@chat.noombat.example",
    )
    .await;
    assert_eq!(blocked.status, StatusCode::NOT_FOUND);
    assert_eq!(blocked.body, missing.body);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_suspended_member_or_a_changed_address_has_no_key(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let address = "bob@chat.noombat.example";
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("suspend");
    assert_eq!(
        lookup(&pool, Some(&pair.alice_token), address).await.status,
        StatusCode::NOT_FOUND
    );

    // The key names the old address, so it is not served for the new one.
    sqlx::query(
        "UPDATE actors SET actor_status = 'active', chatmail_addr = 'robert@chat.noombat.example' \
         WHERE id = $1",
    )
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("readdress");
    let reply = lookup(
        &pool,
        Some(&pair.alice_token),
        "robert@chat.noombat.example",
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

/// A remote actor's document can claim any address, a local member's
/// included, so a lookup by address serves local members only.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_remote_actors_key_is_never_served_by_address(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let remote: Uuid = sqlx::query_scalar(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, chatmail_addr) \
         VALUES ('individual', 'https://elsewhere.example/users/carol', 'carol', \
                 'elsewhere.example', 'KEY', FALSE, 'carol@chat.noombat.example') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("remote actor");
    sqlx::query(
        "INSERT INTO chat_keys (actor_id, address, key_data) \
         VALUES ($1, 'carol@chat.noombat.example', $2)",
    )
    .bind(remote)
    .bind(key(BOB_KEY))
    .execute(&pool)
    .await
    .expect("remote key");
    let reply = lookup(&pool, Some(&pair.alice_token), "carol@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

/// `username`'s actor document, as a peer dereferences it.
async fn actor_document(pool: &PgPool, username: &str) -> serde_json::Value {
    let request = Request::builder()
        .uri(format!("/users/{username}"))
        .header("accept", "application/activity+json")
        .body(Body::empty())
        .expect("request");
    let response = build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("body within limit");
    serde_json::from_slice(&body).expect("a JSON document")
}

/// The key in an actor document or an `Update`'s object, if any.
fn published_key(document: &serde_json::Value) -> Option<Vec<u8>> {
    let data = document["noombat:chatKey"]["noombat:keyData"].as_str()?;
    Some(STANDARD.decode(data).expect("base64"))
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_actor_document_carries_the_key_while_it_names_the_address(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let document = actor_document(&pool, "bob").await;
    assert_eq!(published_key(&document), Some(key(BOB_KEY)));
    assert_eq!(
        document["noombat:chatKey"]["noombat:address"],
        "bob@chat.noombat.example"
    );

    // Not while the account may not sign in, which the local lookup refuses
    // too; a silenced one keeps it.
    for (status, published) in [("suspended", false), ("pending", false), ("silenced", true)] {
        sqlx::query("UPDATE actors SET actor_status = $2 WHERE id = $1")
            .bind(pair.bob)
            .bind(status)
            .execute(&pool)
            .await
            .expect("status");
        let served = published_key(&actor_document(&pool, "bob").await);
        assert_eq!(served.is_some(), published, "{status}");
    }

    // Not while the member must set chat up again, nor once the key names
    // an address that is no longer theirs.
    sqlx::query("UPDATE actors SET chat_requires_reprovisioning = TRUE WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("flag");
    assert_eq!(published_key(&actor_document(&pool, "bob").await), None);
    sqlx::query(
        "UPDATE actors SET chat_requires_reprovisioning = FALSE, \
         chatmail_addr = 'robert@chat.noombat.example' WHERE id = $1",
    )
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("readdress");
    assert_eq!(published_key(&actor_document(&pool, "bob").await), None);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_changed_key_is_pushed_to_followers_and_the_same_key_is_not(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let bob_token = token_for(&pool, bob, "bob").await;
    let follower: Uuid = sqlx::query_scalar(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, inbox_url) \
         VALUES ('individual', 'https://elsewhere.example/users/carol', 'carol', \
                 'elsewhere.example', 'KEY', FALSE, 'https://elsewhere.example/users/carol/inbox') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("remote follower");
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(follower)
        .bind(bob)
        .execute(&pool)
        .await
        .expect("follow");

    let queued = || async {
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT payload FROM delivery_queue \
             WHERE actor_id = $1 AND target_inbox = 'https://elsewhere.example/users/carol/inbox' \
             ORDER BY id",
        )
        .bind(bob)
        .fetch_all(&pool)
        .await
        .expect("queue")
    };

    for (sent, expected) in [
        (BOB_KEY, vec![BOB_KEY]),
        (BOB_KEY, vec![BOB_KEY]),
        (BOB_NEW_KEY, vec![BOB_KEY, BOB_NEW_KEY]),
    ] {
        assert_eq!(
            publish(&pool, &bob_token, &key(sent)).await.status,
            StatusCode::NO_CONTENT
        );
        let updates = queued().await;
        let keys: Vec<Option<Vec<u8>>> = updates
            .iter()
            .map(|update| {
                assert_eq!(update["type"], "Update");
                published_key(&update["object"])
            })
            .collect();
        let expected: Vec<Option<Vec<u8>>> =
            expected.into_iter().map(|b64| Some(key(b64))).collect();
        assert_eq!(keys, expected);
    }
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn looking_up_needs_a_session(pool: PgPool) {
    bob_publishes(&pool, true).await;
    let reply = lookup(&pool, None, "bob@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_table_holds_up_to_8_kib_and_refuses_empty_or_more(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let limit = sqlx::query(
        "INSERT INTO chat_keys (actor_id, address, key_data) \
         VALUES ($1, 'bob@chat.noombat.example', $2)",
    )
    .bind(bob)
    .bind(vec![0u8; 8192])
    .execute(&pool)
    .await;
    assert!(limit.is_ok(), "8192 bytes: {limit:?}");
    sqlx::query("DELETE FROM chat_keys")
        .execute(&pool)
        .await
        .expect("cleared");
    for len in [0, 8193] {
        let result = sqlx::query(
            "INSERT INTO chat_keys (actor_id, address, key_data) \
             VALUES ($1, 'bob@chat.noombat.example', $2)",
        )
        .bind(bob)
        .bind(vec![0u8; len])
        .execute(&pool)
        .await;
        assert!(result.is_err(), "{len} bytes");
    }
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn two_local_members_cannot_share_an_address_in_any_case(pool: PgPool) {
    insert_member(&pool, "bob", true, true).await;
    let result = sqlx::query(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, chatmail_addr) \
         VALUES ('individual', $1, 'bob2', $2, 'KEY', TRUE, 'BOB@chat.noombat.example')",
    )
    .bind(format!("https://{DOMAIN}/users/bob2"))
    .bind(DOMAIN)
    .execute(&pool)
    .await;
    assert!(result.is_err());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_who_must_set_chat_up_again_has_no_key_and_cannot_publish(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    sqlx::query("UPDATE actors SET chat_requires_reprovisioning = TRUE WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("flag");
    let reply = lookup(&pool, Some(&pair.alice_token), "bob@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let reply = publish(&pool, &bob_token, &key(BOB_NEW_KEY)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&reply.body).contains("set up again"));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_pending_member_has_no_key(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    sqlx::query("UPDATE actors SET actor_status = 'pending' WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("pending");
    let reply = lookup(&pool, Some(&pair.alice_token), "bob@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_suspended_member_can_neither_read_nor_publish(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id IN ($1, $2)")
        .bind(pair.alice)
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("suspend");
    let reply = lookup(&pool, Some(&pair.alice_token), "bob@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        publish(&pool, &bob_token, &key(BOB_NEW_KEY)).await.status,
        StatusCode::FORBIDDEN
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_address_is_matched_in_ascii_case_only(pool: PgPool) {
    let kim = insert_member(&pool, "kim", true, true).await;
    let kim_token = token_for(&pool, kim, "kim").await;
    assert_eq!(
        publish(&pool, &kim_token, &key(KIM_KEY)).await.status,
        StatusCode::NO_CONTENT
    );
    let alice = insert_member(&pool, "alice", false, true).await;
    let alice_token = token_for(&pool, alice, "alice").await;
    let upper = lookup(&pool, Some(&alice_token), "KIM@chat.noombat.example").await;
    assert_eq!(upper.status, StatusCode::OK);
    // The Kelvin sign, which the database folds into `k`.
    let kelvin = lookup(
        &pool,
        Some(&alice_token),
        "%E2%84%AAim@chat.noombat.example",
    )
    .await;
    assert_eq!(kelvin.status, StatusCode::NOT_FOUND);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_key_is_not_stored_for_an_address_the_member_no_longer_has(pool: PgPool) {
    // The address already gone; the race itself is the test below.
    let bob = insert_member(&pool, "bob", true, true).await;
    sqlx::query("UPDATE actors SET chatmail_addr = NULL WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("cleared");
    let result =
        noombat_chat::keys::publish(&pool, bob, "bob@chat.noombat.example", &key(BOB_KEY)).await;
    assert!(result.is_err());
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_keys")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(stored, 0);
}

/// Blocking ends a follow but not a connection, and neither may see the
/// key of a member who has blocked them.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_blocked_follower_or_connection_reads_as_having_no_key(pool: PgPool) {
    let pair = bob_publishes(&pool, false).await;
    let address = "bob@chat.noombat.example";
    sqlx::query(
        "INSERT INTO connections (requester_id, addressee_id, accepted_at) VALUES ($1, $2, now())",
    )
    .bind(pair.alice)
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("connection");
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(pair.alice)
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("follow");
    let before = lookup(&pool, Some(&pair.alice_token), address).await;
    assert_eq!(before.status, StatusCode::OK);
    sqlx::query("INSERT INTO blocks (actor_id, target_id) VALUES ($1, $2)")
        .bind(pair.bob)
        .bind(pair.alice)
        .execute(&pool)
        .await
        .expect("block");
    let blocked = lookup(&pool, Some(&pair.alice_token), address).await;
    assert_eq!(blocked.status, StatusCode::NOT_FOUND);
}

/// An erasure holds the member's row while it clears the address and the
/// key. A publish that starts meanwhile must wait, then find the address
/// gone, rather than write the key back after the erasure removed it.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_publish_racing_an_erasure_stores_nothing(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let mut erasure = pool.begin().await.expect("transaction");
    sqlx::query("SELECT 1 FROM actors WHERE id = $1 FOR UPDATE")
        .bind(bob)
        .execute(&mut *erasure)
        .await
        .expect("row lock");
    let publishing = tokio::spawn({
        let pool = pool.clone();
        async move {
            noombat_chat::keys::publish(&pool, bob, "bob@chat.noombat.example", &key(BOB_KEY)).await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !publishing.is_finished(),
        "the publish did not wait for the row"
    );
    sqlx::query("UPDATE actors SET chatmail_addr = NULL WHERE id = $1")
        .bind(bob)
        .execute(&mut *erasure)
        .await
        .expect("cleared");
    sqlx::query("DELETE FROM chat_keys WHERE actor_id = $1")
        .bind(bob)
        .execute(&mut *erasure)
        .await
        .expect("deleted");
    erasure.commit().await.expect("committed");
    assert!(publishing.await.expect("joined").is_err());
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_keys")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(stored, 0);
}

/// Silencing limits what a member publishes to timelines, not their chat.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_silenced_member_keeps_their_key(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    sqlx::query("UPDATE actors SET actor_status = 'silenced' WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("silenced");
    let reply = lookup(&pool, Some(&pair.alice_token), "bob@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::OK);
}

/// A privacy record written before the setting existed lacks it, and the
/// setting's default is on.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_privacy_record_without_the_setting_shows_the_key(pool: PgPool) {
    let pair = bob_publishes(&pool, false).await;
    sqlx::query(
        "UPDATE actors SET actor_privacy = actor_privacy - 'chatmail_visible' WHERE id = $1",
    )
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("an older record");
    let reply = lookup(&pool, Some(&pair.alice_token), "bob@chat.noombat.example").await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_remote_actor_may_claim_a_local_members_address(pool: PgPool) {
    // The unique index covers local members only.
    insert_member(&pool, "bob", true, true).await;
    sqlx::query(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, chatmail_addr) \
         VALUES ('individual', 'https://elsewhere.example/users/bob', 'bob', \
                 'elsewhere.example', 'KEY', FALSE, 'bob@chat.noombat.example')",
    )
    .execute(&pool)
    .await
    .expect("a remote row with the same address");
}
