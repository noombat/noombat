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

// Bob's key on another instance, for bob@chat.localhost.
const REMOTE_BOB_KEY: &str = concat!(
    "xjMEavkK0xYJKwYBBAHaRw8BAQdArCfO2ihUnxdP5cL6xG2aL2kf+SLU1Ba0Kpe6",
    "0gktkqPNFDxib2JAY2hhdC5sb2NhbGhvc3Q+wsATBBMWCgCFBYJq+QrTAwsJBwkQ",
    "i6LdMpIKXq9FFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ5JP",
    "oWxhqCcTMLzIS/4l0vTwlBh4Xt9rUDLsrfdrR1h1BRUKCA4MBBYAAgECGQECmwMC",
    "HgEWIQSKjPcbJ5vahYqHoseLot0ykgperwAAqacBAPVaJpByPkww4hGD5XVKwz2l",
    "Y+2Aqbp5xufhJJSU89BMAQCvSXjDtSinFpODLSPOYFnSnGFSUIY39xVdqj8vVB/d",
    "Ac44BGr5CtMSCisGAQQBl1UBBQEBB0DpD0IfwW29vAItgDxrgdNi/vr5Uu1OBWYZ",
    "lP0tMAaZfgMBCAfCvgQYFgoAcAWCavkK0wkQi6LdMpIKXq9FFAAAAAAAHAAgc2Fs",
    "dEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ88GSV4klDNXPyvUdT/8VpSPUuTRwKpD",
    "Kxm2M03x+DgBApsMFiEEioz3Gyeb2oWKh6LHi6LdMpIKXq8AAC6FAP9MxJBvNa4R",
    "xMvQCBkv8TCqgc9T4mxHTVwWURKm3Td1QQD9GiyAsmYO4g2kXIy2dB2cuckCw0JN",
    "F2uZgo+e4tOZHQY=",
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

/// The auth key the password of a member set up with [`give_password`]
/// gives.
const AUTH_KEY: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

/// Give `id` a password, whose auth key is [`AUTH_KEY`].
async fn give_password(pool: &PgPool, id: Uuid) {
    let hash = noombat_identity::registration::hash_auth_key(AUTH_KEY).expect("hash");
    sqlx::query("UPDATE actors SET auth_key_hash = $1 WHERE id = $2")
        .bind(hash)
        .bind(id)
        .execute(pool)
        .await
        .expect("a password");
}

/// The body that sets chat up with [`AUTH_KEY`].
fn with_password() -> Vec<u8> {
    format!(r#"{{"auth_key":"{AUTH_KEY}"}}"#).into_bytes()
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
    setup: Option<String>,
    body: Vec<u8>,
}

async fn send(pool: &PgPool, method: &str, uri: &str, bearer: Option<&str>, body: &[u8]) -> Reply {
    send_with(pool, method, uri, bearer, &[], body).await
}

async fn send_with(
    pool: &PgPool,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Body::from(body.to_vec())).expect("request");
    let response = build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .map(|value| value.to_str().expect("ASCII").to_owned())
    };
    let cache_control = header("cache-control");
    let setup = header("noombat-chat-setup");
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body within limit")
        .to_vec();
    Reply {
        status,
        cache_control,
        setup,
        body,
    }
}

/// A signed-in form post's status.
async fn send_form(pool: &PgPool, uri: &str, token: &str, body: &[u8]) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_vec()))
        .expect("request");
    build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

/// Publish as a member still on their first setup, number 0 for a fixture.
async fn publish(pool: &PgPool, token: &str, key: &[u8]) -> Reply {
    let setup = [("noombat-chat-setup", "0")];
    send_with(pool, "PUT", "/api/v1/me/chat_key", Some(token), &setup, key).await
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

    // A push replaces the `Update` still queued, so one pushed again would
    // leave a row that looks the same: its id tells them apart.
    let mut first_id = None;
    for (sent, expected) in [
        (BOB_KEY, vec![BOB_KEY]),
        (BOB_KEY, vec![BOB_KEY]),
        (BOB_NEW_KEY, vec![BOB_NEW_KEY]),
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
        let id = updates[0]["id"].clone();
        if sent == BOB_KEY {
            assert_eq!(first_id.get_or_insert(id.clone()), &id, "pushed again");
        } else {
            assert_ne!(first_id.as_ref(), Some(&id), "the new key's own Update");
        }
    }
}

/// A remote actor following `followed`; their inbox.
async fn follow_from_elsewhere(pool: &PgPool, followed: Uuid) -> &'static str {
    const INBOX: &str = "https://elsewhere.example/users/dana/inbox";
    let follower: Uuid = sqlx::query_scalar(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, inbox_url) \
         VALUES ('individual', 'https://elsewhere.example/users/dana', 'dana', \
                 'elsewhere.example', 'KEY', FALSE, $1) \
         RETURNING id",
    )
    .bind(INBOX)
    .fetch_one(pool)
    .await
    .expect("remote follower");
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(follower)
        .bind(followed)
        .execute(pool)
        .await
        .expect("follow");
    INBOX
}

/// The objects of the `Update`s queued from `actor` to `inbox`, oldest first.
async fn updates_to(pool: &PgPool, actor: Uuid, inbox: &str) -> Vec<serde_json::Value> {
    let payloads: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM delivery_queue WHERE actor_id = $1 AND target_inbox = $2 ORDER BY id",
    )
    .bind(actor)
    .bind(inbox)
    .fetch_all(pool)
    .await
    .expect("queue");
    payloads
        .into_iter()
        .map(|payload| {
            assert_eq!(payload["type"], "Update");
            payload["object"].clone()
        })
        .collect()
}

/// Whether an actor document carries the chat address.
fn names_a_chat_address(document: &serde_json::Value) -> bool {
    document["attachment"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["name"] == "Chat"))
}

/// Followers drop a kept key on an `Update` without one, so turning the
/// address off must send them one; saving again with nothing changed
/// sends nothing.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn withdrawing_the_address_pushes_an_update_without_it_or_the_key(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    for _ in 0..2 {
        let reply = send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
        assert_eq!(reply, StatusCode::NO_CONTENT);
        let updates = updates_to(&pool, pair.bob, inbox).await;
        assert_eq!(
            updates.len(),
            1,
            "one Update, and none for the same settings"
        );
        assert_eq!(published_key(&updates[0]), None);
        assert!(!names_a_chat_address(&updates[0]));
    }
}

/// A lifted suspension leaves the member to set chat up again, which
/// withdraws the key followers were last sent.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn lifting_a_suspension_pushes_an_update_without_the_key(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("suspension");
    let moderator = insert_member(&pool, "moderator", false, true).await;
    sqlx::query("UPDATE actors SET instance_role = 'moderator' WHERE id = $1")
        .bind(moderator)
        .execute(&pool)
        .await
        .expect("role");
    let token = token_for(&pool, moderator, "moderator").await;

    let uri = format!("/api/v1/admin/actors/{}/unsuspend", pair.bob);
    for _ in 0..2 {
        let reply = send(&pool, "POST", &uri, Some(&token), &[]).await;
        assert_eq!(reply.status, StatusCode::OK);
        let updates = updates_to(&pool, pair.bob, inbox).await;
        assert_eq!(
            updates.len(),
            1,
            "one Update, and none when nothing changed"
        );
        assert_eq!(published_key(&updates[0]), None);
        assert!(names_a_chat_address(&updates[0]), "the address stays");
    }
}

/// Every default but the chat address, as a browser sends the form.
const HIDDEN: &[u8] = b"discoverable=true&indexable=true&federate_profile=true\
                        &show_followers_count=true&cv_download=public";

/// What followers were last sent is compared, not the state before a
/// request: a change whose push was lost reaches them at the next push,
/// here a save that itself changes nothing.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_change_nobody_pushed_reaches_followers_at_the_next_push(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    sqlx::query(
        "UPDATE actors SET actor_privacy = jsonb_set(actor_privacy, '{chatmail_visible}', 'false') \
         WHERE id = $1",
    )
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("hidden, and pushed by nobody");
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    let reply = send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    assert_eq!(reply, StatusCode::NO_CONTENT);
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1);
    assert!(!names_a_chat_address(&updates[0]));
}

/// Every default, the chat address shown, as a browser sends the form.
const VISIBLE: &[u8] = b"discoverable=true&indexable=true&federate_profile=true\
                         &show_followers_count=true&chatmail_visible=true&cv_download=public";

/// Delivery is concurrent and retried, so an older document left queued
/// could reach a follower after a newer one: each push replaces those
/// still queued for the follower, a claimed one included, so its retry
/// is never made.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_push_replaces_the_updates_still_queued_for_a_follower(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    let first_id = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT min(id) FROM delivery_queue WHERE target_inbox = $1")
            .bind(inbox)
            .fetch_one(&pool)
            .await
            .expect("a row")
    };

    send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    // Claimed as the delivery worker claims a row, so in flight.
    let claimed = first_id(pool.clone()).await;
    sqlx::query("UPDATE delivery_queue SET next_retry = now() + interval '1 hour' WHERE id = $1")
        .bind(claimed)
        .execute(&pool)
        .await
        .expect("claimed");
    send_form(&pool, "/settings/privacy", &bob_token, VISIBLE).await;
    send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;

    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1, "only the newest stays queued");
    assert!(!names_a_chat_address(&updates[0]), "and it is the newest");
    assert!(
        first_id(pool.clone()).await > claimed,
        "the claimed one is gone, so a failed delivery of it finds nothing to retry"
    );
}

/// Each follower's inbox has its own queue: a push replaces the `Update`s
/// still queued for one inbox, never another's.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_push_replaces_only_its_own_followers_updates(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let first = follow_from_elsewhere(&pool, pair.bob).await;
    let second_follower: Uuid = sqlx::query_scalar(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, is_local, inbox_url) \
         VALUES ('individual', 'https://third.example/users/erin', 'erin', \
                 'third.example', 'KEY', FALSE, 'https://third.example/inbox') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("a second follower");
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(second_follower)
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("follow");
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    for inbox in [first, "https://third.example/inbox"] {
        let updates = updates_to(&pool, pair.bob, inbox).await;
        assert_eq!(updates.len(), 1, "{inbox}");
        assert!(!names_a_chat_address(&updates[0]));
    }
}

/// The stamp only moves on, even where the clock is behind the last one.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_documents_stamp_never_goes_back(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let ahead: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "UPDATE actors SET document_updated = date_trunc('milliseconds', now()) + interval '1 hour' \
         WHERE id = $1 RETURNING document_updated",
    )
    .bind(pair.bob)
    .fetch_one(&pool)
    .await
    .expect("a stamp ahead of the clock");
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    let updates = updates_to(&pool, pair.bob, inbox).await;
    let stamp = updates[0]["updated"].as_str().expect("stamped");
    let stamp = chrono::DateTime::parse_from_rfc3339(stamp).expect("RFC 3339");
    assert_eq!(stamp, ahead + chrono::TimeDelta::milliseconds(1));
}

/// A peer keeps the newer of two documents by their `updated`: moved on
/// with each change pushed, the same in the `Update` and when the actor is
/// fetched, and left alone by a save that changes nothing.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn each_document_pushed_is_stamped_later_and_served_with_its_stamp(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    let pushed = |pool: PgPool| async move {
        let updates = updates_to(&pool, pair.bob, inbox).await;
        assert_eq!(updates.len(), 1);
        let stamp = updates[0]["updated"].as_str().expect("stamped").to_owned();
        let served = actor_document(&pool, "bob").await;
        assert_eq!(served["updated"], stamp.as_str(), "served as pushed");
        chrono::DateTime::parse_from_rfc3339(&stamp).expect("RFC 3339")
    };

    send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    let first = pushed(pool.clone()).await;
    send_form(&pool, "/settings/privacy", &bob_token, VISIBLE).await;
    let second = pushed(pool.clone()).await;
    assert!(second > first, "{second} after {first}");
    send_form(&pool, "/settings/privacy", &bob_token, VISIBLE).await;
    assert_eq!(pushed(pool.clone()).await, second, "nothing changed");
}

/// A suspension sent followers a `Delete`; nothing may push an `Update` in
/// the account's name after it: a session from before it is refused the
/// save, and a push from anywhere else sends nothing.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn nothing_is_pushed_for_a_suspended_account(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("suspended");
    let reply = send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    assert_eq!(reply, StatusCode::FORBIDDEN);
    sqlx::query(
        "UPDATE actors SET actor_privacy = jsonb_set(actor_privacy, '{chatmail_visible}', 'false') \
         WHERE id = $1",
    )
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("a change to push");
    noombat_federation::update::push_actor_document(&pool, pair.bob, DOMAIN).await;
    assert!(updates_to(&pool, pair.bob, inbox).await.is_empty());
}

/// A refusal of the second half of the form leaves the first half saved,
/// and pushed.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_save_refused_halfway_still_pushes_what_was_saved(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    let half = [HIDDEN, b"&default_visibility=nonsense".as_slice()].concat();
    let reply = send_form(&pool, "/settings/privacy", &bob_token, &half).await;
    assert_eq!(reply, StatusCode::BAD_REQUEST);
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1);
    assert!(!names_a_chat_address(&updates[0]));
}

/// The member's digest of the last document pushed.
async fn digest_of(pool: &PgPool, id: Uuid) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT federated_digest FROM actors WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("digest")
}

/// A push whose `Update`s could not be queued records nothing, and forgets
/// what was last pushed, so the next push sends whatever it builds.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_push_that_could_not_be_queued_is_made_up_by_the_next(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    for statement in [
        "CREATE FUNCTION refuse_delivery() RETURNS trigger LANGUAGE plpgsql \
         AS $$ BEGIN RAISE EXCEPTION 'the queue is down'; END $$",
        "CREATE TRIGGER refuse_delivery BEFORE INSERT ON delivery_queue \
         FOR EACH ROW EXECUTE FUNCTION refuse_delivery()",
    ] {
        sqlx::query(statement)
            .execute(&pool)
            .await
            .expect("the queue down");
    }
    send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    assert!(updates_to(&pool, pair.bob, inbox).await.is_empty());
    assert_eq!(digest_of(&pool, pair.bob).await, None, "nothing recorded");

    sqlx::query("DROP TRIGGER refuse_delivery ON delivery_queue")
        .execute(&pool)
        .await
        .expect("the queue back");
    // The same settings again: nothing changes, but the withdrawal goes out.
    send_form(&pool, "/settings/privacy", &bob_token, HIDDEN).await;
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1);
    assert!(!names_a_chat_address(&updates[0]));
}

/// A document one of whose reads failed is not pushed: followers would
/// take the smaller document as the member withdrawing what it left out.
/// Dereferencing still serves it, smaller.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_document_that_could_not_be_read_whole_is_not_pushed(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    sqlx::query("UPDATE actors SET federated_digest = NULL WHERE id = $1")
        .bind(pair.bob)
        .execute(&pool)
        .await
        .expect("nothing pushed yet");
    sqlx::query("ALTER TABLE chat_keys RENAME TO chat_keys_away")
        .execute(&pool)
        .await
        .expect("the keys unreadable");
    noombat_federation::update::push_actor_document(&pool, pair.bob, DOMAIN).await;
    assert!(updates_to(&pool, pair.bob, inbox).await.is_empty());
    assert_eq!(published_key(&actor_document(&pool, "bob").await), None);

    sqlx::query("ALTER TABLE chat_keys_away RENAME TO chat_keys")
        .execute(&pool)
        .await
        .expect("the keys back");
    noombat_federation::update::push_actor_document(&pool, pair.bob, DOMAIN).await;
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1);
    assert_eq!(published_key(&updates[0]), Some(key(BOB_KEY)));
}

/// Pushes at once hold no connection while building, so they cannot
/// starve a pool between them, and only one sends: the others find the
/// document already recorded, or look again after losing the race.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn pushes_at_once_neither_starve_the_pool_nor_send_twice(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    sqlx::query(
        "UPDATE actors SET actor_privacy = jsonb_set(actor_privacy, '{chatmail_visible}', 'false') \
         WHERE id = $1",
    )
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("a change to push");
    let small = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect_with((*pool.connect_options()).clone())
        .await
        .expect("a small pool");
    let mut pushes = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let small = small.clone();
        let bob = pair.bob;
        pushes.spawn(async move {
            noombat_federation::update::push_actor_document(&small, bob, DOMAIN).await;
        });
    }
    while let Some(push) = pushes.join_next().await {
        push.expect("a push");
    }
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1, "one Update");
    assert!(!names_a_chat_address(&updates[0]));
    assert!(digest_of(&pool, pair.bob).await.is_some(), "and recorded");
    // Queued once, not queued again over itself: nothing was queued before.
    let next: i64 = sqlx::query_scalar("SELECT nextval('delivery_queue_id_seq')")
        .fetch_one(&pool)
        .await
        .expect("sequence");
    assert_eq!(next, 2, "one Update queued in all");
}

/// Sections that tie on how they are sorted keep one order, so a row
/// stored somewhere else, the same in every value, does not reorder the
/// document and push it again.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn sections_that_tie_keep_one_order(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let mut rows = Vec::new();
    for title in ["first", "second", "third"] {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO work_experiences \
                 (actor_id, title, organization, start_date, ap_object) \
             VALUES ($1, $2, 'Acme', '2020-01-01', jsonb_build_object('name', $2::text)) \
             RETURNING id",
        )
        .bind(pair.bob)
        .bind(title)
        .fetch_one(&pool)
        .await
        .expect("a section");
        rows.push(id);
    }
    // The newest queued row, which any push raises, replacing or not.
    let newest = |pool: PgPool| async move {
        sqlx::query_scalar::<_, Option<i64>>("SELECT max(id) FROM delivery_queue")
            .fetch_one(&pool)
            .await
            .expect("queue")
    };
    noombat_federation::update::push_actor_document(&pool, pair.bob, DOMAIN).await;
    assert!(!updates_to(&pool, pair.bob, inbox).await.is_empty());
    let pushed = newest(pool.clone()).await;
    for id in rows {
        // Deleted and stored again, unchanged: an update in place can keep
        // the row where it was, which proves nothing.
        let row: serde_json::Value = sqlx::query_scalar(
            "DELETE FROM work_experiences WHERE id = $1 RETURNING to_jsonb(work_experiences)",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("taken out");
        sqlx::query(
            "INSERT INTO work_experiences \
             SELECT * FROM jsonb_populate_record(NULL::work_experiences, $1)",
        )
        .bind(row)
        .execute(&pool)
        .await
        .expect("stored again");
        noombat_federation::update::push_actor_document(&pool, pair.bob, DOMAIN).await;
        assert_eq!(newest(pool.clone()).await, pushed, "pushed again");
    }
}

/// The document lists the member's aliases, as `alsoKnownAs`.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn adding_an_alias_pushes_it(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    let request = Request::builder()
        .method("POST")
        .uri("/users/bob/aliases")
        .header("authorization", format!("Bearer {bob_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"alias":"https://elsewhere.example/users/bob"}"#,
        ))
        .expect("request");
    let reply = build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    assert!(reply.status().is_success(), "{}", reply.status());
    let updates = updates_to(&pool, pair.bob, inbox).await;
    let newest = updates.last().expect("an Update");
    assert_eq!(
        newest["alsoKnownAs"],
        serde_json::json!(["https://elsewhere.example/users/bob"])
    );
}

/// A suspension sends followers a `Delete`, so lifting it pushes the
/// document even where nothing in it changed.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_lifted_suspension_is_pushed_even_unchanged(pool: PgPool) {
    let carol = insert_member(&pool, "carol", false, true).await;
    let inbox = follow_from_elsewhere(&pool, carol).await;
    let carol_token = token_for(&pool, carol, "carol").await;
    let form = b"discoverable=true&indexable=true&federate_profile=true\
                 &show_followers_count=true&chatmail_visible=true&cv_download=public";
    send_form(&pool, "/settings/privacy", &carol_token, form).await;
    assert_eq!(
        updates_to(&pool, carol, inbox).await.len(),
        1,
        "the first push"
    );
    let moderator = insert_member(&pool, "moderator", false, true).await;
    sqlx::query("UPDATE actors SET instance_role = 'moderator' WHERE id = $1")
        .bind(moderator)
        .execute(&pool)
        .await
        .expect("role");
    let token = token_for(&pool, moderator, "moderator").await;
    for action in ["suspend", "unsuspend"] {
        let uri = format!("/api/v1/admin/actors/{carol}/{action}");
        let body = if action == "suspend" {
            br#"{"reason":"test"}"#.as_slice()
        } else {
            b""
        };
        let headers = [("content-type", "application/json")];
        let reply = send_with(&pool, "POST", &uri, Some(&token), &headers, body).await;
        assert_eq!(reply.status, StatusCode::OK, "{action}");
    }
    let kinds: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload->'type' FROM delivery_queue WHERE target_inbox = $1 ORDER BY id",
    )
    .bind(inbox)
    .fetch_all(&pool)
    .await
    .expect("queue");
    // The lift's `Update` replaced the first, still queued.
    assert_eq!(kinds, ["Delete", "Update"]);
}

/// The relationship lists are saved after the privacy record, and a public
/// one is in the document followers hold.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn making_the_connections_list_public_pushes_it(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    let public = b"discoverable=true&indexable=true&federate_profile=true\
                   &show_followers_count=true&chatmail_visible=true&cv_download=public\
                   &connections_visibility=public";
    let reply = send_form(&pool, "/settings/privacy", &bob_token, public).await;
    assert_eq!(reply, StatusCode::NO_CONTENT);
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1);
    assert!(updates[0].get("schema:knows").is_some(), "{}", updates[0]);
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
        noombat_chat::keys::publish(&pool, bob, "bob@chat.noombat.example", &key(BOB_KEY), 0).await;
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
            noombat_chat::keys::publish(&pool, bob, "bob@chat.noombat.example", &key(BOB_KEY), 0)
                .await
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

async fn lookup_handle(pool: &PgPool, token: Option<&str>, handle: &str) -> Reply {
    let uri = format!("/api/v1/chat/keys/by-handle/{handle}");
    send(pool, "GET", &uri, token, &[]).await
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_local_member_is_found_by_handle_under_the_same_rules(pool: PgPool) {
    let pair = bob_publishes(&pool, false).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;
    for handle in ["@bob@noombat.example", "bob@NOOMBAT.example"] {
        let reply = lookup_handle(&pool, Some(&bob_token), handle).await;
        assert_eq!(reply.status, StatusCode::OK, "{handle}");
        assert_eq!(served_key(&reply), key(BOB_KEY));
        assert_eq!(reply.cache_control.as_deref(), Some("private, no-store"));
    }
    // Hidden from a stranger, as by address, and read as no key at all.
    let hidden = lookup_handle(&pool, Some(&pair.alice_token), "@bob@noombat.example").await;
    let missing = lookup_handle(&pool, Some(&pair.alice_token), "@nobody@noombat.example").await;
    let without_chat =
        lookup_handle(&pool, Some(&pair.alice_token), "@alice@noombat.example").await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    assert_eq!(hidden.body, missing.body);
    assert_eq!(without_chat.body, missing.body);

    assert_eq!(
        lookup_handle(&pool, Some(&bob_token), "bob").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        lookup_handle(&pool, None, "@bob@noombat.example")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
}

/// Another noombat instance on a local port: WebFinger names Bob, his
/// actor document carries his key, and NodeInfo names its chat domain.
async fn other_instance() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Named `localhost`, so that its chat domain can sit under its host.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let authority = format!(
        "localhost:{}",
        listener.local_addr().expect("address").port()
    );
    let base = format!("http://{authority}");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]).into_owned();
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            let body = if path.starts_with("/.well-known/webfinger") {
                serde_json::json!({
                    "subject": "acct:bob@other.example",
                    "links": [{
                        "rel": "self",
                        "type": "application/activity+json",
                        "href": format!("{base}/users/bob"),
                    }],
                })
            } else if path == "/users/bob" {
                serde_json::json!({
                    "id": format!("{base}/users/bob"),
                    "type": "Person",
                    "preferredUsername": "bob",
                    "inbox": format!("{base}/users/bob/inbox"),
                    "outbox": format!("{base}/users/bob/outbox"),
                    "publicKey": {
                        "id": format!("{base}/users/bob#main-key"),
                        "owner": format!("{base}/users/bob"),
                        "publicKeyPem": "KEY",
                    },
                    "noombat:chatKey": {
                        "noombat:address": "bob@chat.localhost",
                        "noombat:keyData": REMOTE_BOB_KEY,
                    },
                })
            } else if path == "/.well-known/nodeinfo" {
                serde_json::json!({ "links": [{
                    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                    "href": format!("{base}/nodeinfo/2.1"),
                }] })
            } else {
                let metadata = serde_json::json!({ "noombat:chatmailDomain": "chat.localhost" });
                serde_json::json!({ "metadata": metadata })
            };
            let body = body.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    authority
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_elsewhere_is_not_offered_without_the_relay(pool: PgPool) {
    noombat_federation::http::set_allow_local_targets(true);
    let alice = insert_member(&pool, "alice", true, true).await;
    let alice_token = token_for(&pool, alice, "alice").await;
    let authority = other_instance().await;

    // The key is bindable: the lookup this route makes would keep it.
    let client = reqwest::Client::new();
    let allowlist = vec!["chat.localhost".to_owned()];
    let found = noombat_federation::remote_chat_key::find_by_handle(
        &pool, &client, "bob", &authority, &allowlist,
    )
    .await
    .expect("looked up");
    assert!(
        found.is_some(),
        "the stand-in instance serves a bindable key"
    );

    // This instance has no relay configured, so nothing is offered.
    let reply = lookup_handle(&pool, Some(&alice_token), &format!("@bob@{authority}")).await;
    let missing = lookup_handle(&pool, Some(&alice_token), "@nobody@noombat.example").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.body, missing.body);
}

// ..... Setting chat up again .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn no_blob_reads_as_chat_to_set_up(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let bob_token = token_for(&pool, bob, "bob").await;
    let reply = send(
        &pool,
        "GET",
        "/api/v1/me/chatmail_cred",
        Some(&bob_token),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn only_an_unusable_setup_is_set_up_again(pool: PgPool) {
    // This instance has no relay sidecar, so a setup the server would
    // redo stops at 503, where a working one stops earlier, at 409.
    let bob = insert_member(&pool, "bob", true, true).await;
    give_password(&pool, bob).await;
    let bob_token = token_for(&pool, bob, "bob").await;
    let body = with_password();
    let provision = || {
        send(
            &pool,
            "POST",
            "/api/v1/me/provision_chat",
            Some(&bob_token),
            &body,
        )
    };

    assert_eq!(
        provision().await.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "no blob"
    );

    sqlx::query("UPDATE actors SET chatmail_cred = '\\x01' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("a blob");
    let reply = provision().await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "a working setup");
    assert!(String::from_utf8_lossy(&reply.body).contains("already set up"));

    sqlx::query("UPDATE actors SET chat_requires_reprovisioning = TRUE WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("flag");
    assert_eq!(
        provision().await.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "after a suspension"
    );
}

/// A setup the relay failed still pushes: its claim had already forgotten
/// the key followers were last sent.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_setup_the_relay_failed_still_withdraws_the_key_from_followers(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;

    let failed = noombat_api::routes::auth::set_up_chat(&pool, DOMAIN, pair.bob, |_| async {
        Err(noombat_core::error::NoombatError::ServiceUnavailable(
            "the relay is down".into(),
        ))
    })
    .await;
    assert!(failed.is_err());
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1, "followers were not told");
    assert_eq!(published_key(&updates[0]), None);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn setting_chat_up_again_withdraws_the_old_key_from_followers(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;

    let setup = noombat_api::routes::auth::set_up_chat(&pool, DOMAIN, pair.bob, |address| async {
        Ok((address.expect("bob's address"), "a new password".to_owned()))
    })
    .await
    .expect("set up again");
    assert_eq!(setup.address, "bob@chat.noombat.example");
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1, "followers were not told");
    assert_eq!(published_key(&updates[0]), None);
}

/// The route sets chat up through [`noombat_api::routes::auth::set_up_chat`]:
/// with no relay sidecar here, its setup fails after the claim, and
/// followers still lose the key.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_setup_route_pushes_even_a_failed_setup(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    give_password(&pool, pair.bob).await;
    let inbox = follow_from_elsewhere(&pool, pair.bob).await;
    let bob_token = token_for(&pool, pair.bob, "bob").await;

    let reply = send(
        &pool,
        "POST",
        "/api/v1/me/provision_chat",
        Some(&bob_token),
        &with_password(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    let updates = updates_to(&pool, pair.bob, inbox).await;
    assert_eq!(updates.len(), 1, "followers were not told");
    assert_eq!(published_key(&updates[0]), None);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn setting_up_needs_the_password_and_a_member_who_may_chat(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let auth_key = "b0".repeat(32);
    let hash = noombat_identity::registration::hash_auth_key(&auth_key).expect("hash");
    sqlx::query("UPDATE actors SET auth_key_hash = $1 WHERE id = $2")
        .bind(hash)
        .bind(bob)
        .execute(&pool)
        .await
        .expect("a password");
    let bob_token = token_for(&pool, bob, "bob").await;
    let provision = |key: Option<&str>| {
        let body = key
            .map(|k| format!(r#"{{"auth_key":"{k}"}}"#))
            .unwrap_or_default();
        let pool = pool.clone();
        let token = bob_token.clone();
        async move {
            send(
                &pool,
                "POST",
                "/api/v1/me/provision_chat",
                Some(&token),
                body.as_bytes(),
            )
            .await
        }
    };

    let without = provision(None).await;
    assert_eq!(without.status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&without.body).contains("auth_key required"));
    let wrong = provision(Some(&"0f".repeat(32))).await;
    assert!(
        wrong.status.is_client_error(),
        "a wrong password: {}",
        wrong.status
    );
    assert_ne!(wrong.status, StatusCode::SERVICE_UNAVAILABLE);
    // The right one gets as far as the missing sidecar.
    let right = provision(Some(&auth_key)).await;
    assert_eq!(right.status, StatusCode::SERVICE_UNAVAILABLE);

    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("suspend");
    assert_eq!(
        provision(Some(&auth_key)).await.status,
        StatusCode::FORBIDDEN
    );

    // An account without a password has none to prove, whatever key it
    // sends: it sets one first, since chat's credentials are kept under it.
    let carol = insert_member(&pool, "carol", true, true).await;
    let carol_token = token_for(&pool, carol, "carol").await;
    let reply = send(
        &pool,
        "POST",
        "/api/v1/me/provision_chat",
        Some(&carol_token),
        &with_password(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

/// The session met the second factor at sign-in, so setting chat up, and
/// changing the password, ask for the password alone.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_with_a_second_factor_needs_only_the_password_again(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    give_password(&pool, bob).await;
    noombat_identity::totp::enrol_totp(&pool, bob, "bob", DOMAIN)
        .await
        .expect("TOTP enrolment");
    sqlx::query("UPDATE totp_secrets SET verified = TRUE WHERE actor_id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("TOTP confirmed");
    let token = token_for(&pool, bob, "bob").await;

    let reply = send(
        &pool,
        "POST",
        "/api/v1/me/provision_chat",
        Some(&token),
        &with_password(),
    )
    .await;
    // As far as the missing sidecar.
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);

    let new_key = "c0".repeat(32);
    let change = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/password")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"old_auth_key":"{AUTH_KEY}","auth_key":"{new_key}"}}"#
        )))
        .expect("request");
    let changed = build_router(test_state(pool.clone()))
        .oneshot(change)
        .await
        .expect("the router is infallible");
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
}

/// What the chat page tells its island: whether chat must be set up
/// again and whether there is a password to do it with; and on an
/// instance without Chatmail, that there is no chat at all.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_chat_page_says_what_setting_up_needs(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let token = token_for(&pool, bob, "bob").await;
    let page = |chat: bool| {
        let state = AppState {
            chatmail_domain: chat.then(|| "chat.noombat.example".to_owned()),
            ..test_state(pool.clone())
        };
        let request = Request::builder()
            .uri("/chat")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request");
        async move {
            let response = build_router(state)
                .oneshot(request)
                .await
                .expect("the router is infallible");
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("page");
            String::from_utf8(body.to_vec()).expect("UTF-8")
        }
    };

    let no_blob = page(true).await;
    assert!(no_blob.contains(r#"data-needs-setup="true""#), "no blob");
    assert!(no_blob.contains(r#"data-has-password="false""#));
    sqlx::query("UPDATE actors SET chatmail_cred = '\\x01' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("a blob");
    give_password(&pool, bob).await;
    let usable = page(true).await;
    assert!(usable.contains(r#"data-needs-setup="false""#), "usable");
    assert!(usable.contains(r#"data-has-password="true""#));
    sqlx::query("UPDATE actors SET chat_requires_reprovisioning = TRUE WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("flag");
    assert!(
        page(true).await.contains(r#"data-needs-setup="true""#),
        "after a suspension"
    );

    let none = page(false).await;
    assert!(none.contains("Chat is not available on this instance."));
    assert!(!none.contains("data-needs-setup"));
}

/// Short, so a test that waits out the relay does not wait long.
const RELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// The member's chat columns: address, credentials, setup number, lease.
async fn chat_row(pool: &PgPool, id: Uuid) -> (Option<String>, Option<Vec<u8>>, i64, bool) {
    sqlx::query_as(
        "SELECT chatmail_addr, chatmail_cred, chat_setup_generation, \
                COALESCE(chat_setup_until > now(), FALSE) \
         FROM actors WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("row")
}

/// Two tabs or devices set chat up at the same moment. The relay is asked
/// once: the second is refused while the first is under way, so the relay
/// keeps the password of the one setup whose credentials can be stored.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn two_setups_at_once_ask_the_relay_once(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let setting_up = || {
        let pool = pool.clone();
        let asked = asked.clone();
        async move {
            noombat_chat::keys::set_up(&pool, bob, RELAY, |address| async move {
                asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                Ok((address.expect("an address"), "the password".to_owned()))
            })
            .await
        }
    };
    let (first, second) = tokio::join!(setting_up(), setting_up());
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    let (made, refused) = match (first, second) {
        (Ok(made), Err(refused)) | (Err(refused), Ok(made)) => (made, refused),
        other => panic!("not one setup and one refusal: {other:?}"),
    };
    assert!(
        matches!(&refused, noombat_core::error::NoombatError::Conflict(detail) if detail.contains("being set up")),
        "{refused:?}"
    );
    noombat_chat::keys::store_credentials(&pool, bob, made.generation, b"credentials")
        .await
        .expect("stored");
    assert_eq!(
        chat_row(&pool, bob).await,
        (
            Some("bob@chat.noombat.example".to_owned()),
            Some(b"credentials".to_vec()),
            1,
            false
        )
    );
}

/// The minute after a setup that got its password from the relay, gone.
async fn a_minute_on(pool: &PgPool, id: Uuid) {
    sqlx::query("UPDATE actors SET chat_set_up_at = now() - interval '61 seconds' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("a minute on");
}

/// Each setup rotates the relay password, so a member sets chat up at
/// most once a minute; a relay call that failed holds nothing, so a retry
/// is free.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_sets_chat_up_at_most_once_a_minute(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let relay = |address: Option<String>| async move {
        Ok((address.expect("an address"), "rotated".to_owned()))
    };
    noombat_chat::keys::set_up(&pool, bob, RELAY, relay)
        .await
        .expect("set up");
    // Nothing stored, so still unusable, but held.
    let again = noombat_chat::keys::set_up(&pool, bob, RELAY, relay).await;
    assert!(
        matches!(
            again,
            Err(noombat_core::error::NoombatError::QuotaExceeded(_))
        ),
        "{again:?}"
    );
    a_minute_on(&pool, bob).await;
    let failed = noombat_chat::keys::set_up(&pool, bob, RELAY, |_| async move {
        Err(noombat_core::error::NoombatError::ServiceUnavailable(
            "the relay is down".into(),
        ))
    })
    .await;
    assert!(matches!(
        failed,
        Err(noombat_core::error::NoombatError::ServiceUnavailable(_))
    ));
    noombat_chat::keys::set_up(&pool, bob, RELAY, relay)
        .await
        .expect("a retry after a failure");
}

/// A first setup asks the relay for an account, and keeps its address.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_first_setup_keeps_the_address_the_relay_made(pool: PgPool) {
    let bob = insert_member(&pool, "bob", false, true).await;
    let setup = noombat_chat::keys::set_up(&pool, bob, RELAY, |address| async move {
        assert_eq!(address, None, "a first setup has no address yet");
        Ok(("bob@chat.noombat.example".to_owned(), "new".to_owned()))
    })
    .await
    .expect("set up");
    assert_eq!(setup.generation, 1);
    assert_eq!(
        chat_row(&pool, bob).await,
        (Some("bob@chat.noombat.example".to_owned()), None, 1, false)
    );
}

/// The relay may have rotated before a setup fails, so a setup that fails
/// must still leave every older one unable to store its credentials. It is
/// released at once for a retry.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_setup_still_replaces_older_ones_and_frees_a_retry(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let older = noombat_chat::keys::set_up(&pool, bob, RELAY, |address| async move {
        Ok((address.expect("an address"), "older".to_owned()))
    })
    .await
    .expect("set up");
    a_minute_on(&pool, bob).await;
    let failed = noombat_chat::keys::set_up(&pool, bob, RELAY, |_| async move {
        Err(noombat_core::error::NoombatError::Internal(
            "the relay answer was lost".into(),
        ))
    })
    .await;
    assert!(failed.is_err());
    let stale = noombat_chat::keys::store_credentials(&pool, bob, older.generation, b"older").await;
    assert!(matches!(
        stale,
        Err(noombat_core::error::NoombatError::Conflict(_))
    ));
    let retried = noombat_chat::keys::set_up(&pool, bob, RELAY, |address| async move {
        Ok((address.expect("an address"), "retried".to_owned()))
    })
    .await
    .expect("a retry at once");
    assert_eq!(retried.generation, 3);
}

/// A relay that does not answer is given up on within the time it is
/// given; the account is then held the minute a finished setup holds it.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_relay_that_does_not_answer_is_given_up_on(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let short = std::time::Duration::from_millis(200);
    let started = std::time::Instant::now();
    let silent = noombat_chat::keys::set_up(&pool, bob, short, |_| async move {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        Ok(("never".to_owned(), "never".to_owned()))
    })
    .await;
    assert!(matches!(
        silent,
        Err(noombat_core::error::NoombatError::ServiceUnavailable(_))
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(!chat_row(&pool, bob).await.3, "still held after giving up");
    // The relay may yet rotate the password, so a retry waits the minute
    // a finished setup does, and no two rotations land out of order.
    let relay = |address: Option<String>| async move {
        Ok((address.expect("an address"), "rotated".to_owned()))
    };
    let again = noombat_chat::keys::set_up(&pool, bob, RELAY, relay).await;
    assert!(
        matches!(
            again,
            Err(noombat_core::error::NoombatError::QuotaExceeded(_))
        ),
        "{again:?}"
    );
    a_minute_on(&pool, bob).await;
    noombat_chat::keys::set_up(&pool, bob, RELAY, relay)
        .await
        .expect("a minute on");
}

/// A setup under way holds the account until it ends or its time runs out.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_setup_under_way_holds_the_account_until_it_expires(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    sqlx::query("UPDATE actors SET chat_setup_until = now() + interval '1 minute' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("under way");
    let refused = noombat_chat::keys::set_up(&pool, bob, RELAY, |_| async move {
        panic!("the relay was asked during another setup")
    })
    .await;
    assert!(matches!(
        refused,
        Err(noombat_core::error::NoombatError::Conflict(_))
    ));
    sqlx::query("UPDATE actors SET chat_setup_until = now() - interval '1 second' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("abandoned");
    noombat_chat::keys::set_up(&pool, bob, RELAY, |address| async move {
        Ok((address.expect("an address"), "after".to_owned()))
    })
    .await
    .expect("set up once it expired");
}

/// An account that may not chat is refused before the relay is asked, and
/// one suspended while the relay answers keeps no address.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_suspended_account_is_not_set_up(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("suspended");
    let refused = noombat_chat::keys::set_up(&pool, bob, RELAY, |_| async move {
        panic!("the relay was asked for a suspended account")
    })
    .await;
    assert!(matches!(
        refused,
        Err(noombat_core::error::NoombatError::Forbidden)
    ));

    let carol = insert_member(&pool, "carol", false, true).await;
    let suspending = pool.clone();
    let refused = noombat_chat::keys::set_up(&pool, carol, RELAY, |_| async move {
        sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
            .bind(carol)
            .execute(&suspending)
            .await
            .expect("suspended meanwhile");
        Ok(("carol@chat.noombat.example".to_owned(), "new".to_owned()))
    })
    .await;
    assert!(matches!(
        refused,
        Err(noombat_core::error::NoombatError::Forbidden)
    ));
    assert_eq!(chat_row(&pool, carol).await.0, None);
}

/// An erasure clears the address and credentials; a tab still open must
/// not write the credentials back.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn credentials_are_not_written_back_after_an_erasure(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    // As erasure leaves the account: suspended, address and credentials gone.
    sqlx::query(
        "UPDATE actors SET actor_status = 'suspended', chatmail_addr = NULL, chatmail_cred = NULL \
         WHERE id = $1",
    )
    .bind(bob)
    .execute(&pool)
    .await
    .expect("erased");
    let refused = noombat_chat::keys::store_credentials(&pool, bob, 0, b"credentials").await;
    assert!(refused.is_err());
    assert_eq!(chat_row(&pool, bob).await.1, None);
}

/// Changing the password re-wraps the credentials, which must name their
/// setup like any other write of them.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_password_change_writes_only_the_newest_setups_credentials(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    sqlx::query(
        "UPDATE actors SET email_verified_at = now(), chat_setup_generation = 1 WHERE id = $1",
    )
    .bind(bob)
    .execute(&pool)
    .await
    .expect("a proved address, and a second setup");
    let token = token_for(&pool, bob, "bob").await;
    let json = [("content-type", "application/json")];
    let auth_key = "00".repeat(32);
    let body = |setup: Option<i64>| {
        let mut body = serde_json::json!({ "auth_key": auth_key, "chatmail_cred": "AQ==" });
        if let Some(setup) = setup {
            body["chat_setup"] = setup.into();
        }
        body.to_string().into_bytes()
    };
    let password = "/api/v1/auth/password";
    let unnamed = send_with(&pool, "POST", password, Some(&token), &json, &body(None)).await;
    assert_eq!(unnamed.status, StatusCode::BAD_REQUEST);
    let stale = send_with(&pool, "POST", password, Some(&token), &json, &body(Some(0))).await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(chat_row(&pool, bob).await.1, None, "nothing written");
    let newest = send_with(&pool, "POST", password, Some(&token), &json, &body(Some(1))).await;
    assert_eq!(newest.status, StatusCode::NO_CONTENT);
    assert_eq!(chat_row(&pool, bob).await.1, Some(vec![1]));
    // Re-encrypted credentials take a new number, so a tab still holding
    // them under the old password has its writes refused.
    assert_eq!(newest.setup.as_deref(), Some("2"));
    assert_eq!(chat_row(&pool, bob).await.2, 2);
    let old_tab = noombat_chat::keys::store_credentials(&pool, bob, 1, b"old").await;
    assert!(matches!(
        old_tab,
        Err(noombat_core::error::NoombatError::Conflict(_))
    ));

    // Changing it again: the credentials held must come re-encrypted, and
    // not while a setup is under way.
    let change = |cred: Option<&str>| {
        let mut body = serde_json::json!({ "auth_key": "11".repeat(32), "old_auth_key": auth_key });
        if let Some(cred) = cred {
            body["chatmail_cred"] = cred.into();
            body["chat_setup"] = 2.into();
        }
        body.to_string().into_bytes()
    };
    let without = send_with(&pool, "POST", password, Some(&token), &json, &change(None)).await;
    assert_eq!(without.status, StatusCode::BAD_REQUEST);
    sqlx::query("UPDATE actors SET chat_setup_until = now() + interval '1 minute' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("a setup under way");
    let during = send_with(
        &pool,
        "POST",
        password,
        Some(&token),
        &json,
        &change(Some("Ag==")),
    )
    .await;
    assert_eq!(during.status, StatusCode::CONFLICT);
    assert_eq!(
        chat_row(&pool, bob).await.1,
        Some(vec![1]),
        "nothing written"
    );
}

/// The setup header is digits alone; a sign is refused, not read.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_setup_named_with_a_sign_is_refused(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let token = token_for(&pool, bob, "bob").await;
    for setup in ["+0", "-1", ""] {
        let header = [("noombat-chat-setup", setup)];
        let reply = send_with(
            &pool,
            "PUT",
            "/api/v1/me/chat_key",
            Some(&token),
            &header,
            &key(BOB_KEY),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{setup:?}");
    }
}

/// A suspended account stores no credentials, whatever setup it names;
/// the key route refuses it before its write is reached.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_suspended_account_stores_no_credentials_for_its_setup(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("suspended");
    let credentials = noombat_chat::keys::store_credentials(&pool, bob, 0, b"credentials").await;
    assert!(matches!(
        credentials,
        Err(noombat_core::error::NoombatError::Forbidden)
    ));
    assert_eq!(chat_row(&pool, bob).await.1, None);
}

/// A setup that a newer one replaced while the relay was asked keeps
/// nothing: the newer setup's address and password are the ones to hold.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_setup_replaced_while_the_relay_was_asked_keeps_nothing(pool: PgPool) {
    let bob = insert_member(&pool, "bob", false, true).await;
    let newer = pool.clone();
    let outcome = noombat_chat::keys::set_up(&pool, bob, RELAY, move |_| async move {
        sqlx::query(
            "UPDATE actors SET chat_setup_generation = chat_setup_generation + 1 WHERE id = $1",
        )
        .bind(bob)
        .execute(&newer)
        .await
        .expect("a newer setup's claim");
        Ok(("bob@chat.noombat.example".to_owned(), "older".to_owned()))
    })
    .await;
    assert!(
        matches!(outcome, Err(noombat_core::error::NoombatError::Conflict(_))),
        "{outcome:?}"
    );
    assert_eq!(chat_row(&pool, bob).await.0, None, "no address kept");
}

/// A setup that works is not replaced, and the relay is not asked.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_usable_setup_is_not_set_up_again(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    sqlx::query("UPDATE actors SET chatmail_cred = '\\x01' WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("a blob");
    let refused = noombat_chat::keys::set_up(&pool, bob, RELAY, |_| async move {
        panic!("the relay was asked to rotate a working setup")
    })
    .await;
    assert!(matches!(
        refused,
        Err(noombat_core::error::NoombatError::Conflict(_))
    ));
}

/// The credentials are served with their setup's number, and stored only
/// by a write naming the newest; a key likewise.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn writes_name_the_newest_setup_or_are_refused(pool: PgPool) {
    let bob = insert_member(&pool, "bob", true, true).await;
    let token = token_for(&pool, bob, "bob").await;
    let cred = "/api/v1/me/chatmail_cred";
    let named = |setup: &'static str| [("noombat-chat-setup", setup)];

    let unnamed = send(&pool, "PUT", cred, Some(&token), b"blob").await;
    assert_eq!(unnamed.status, StatusCode::BAD_REQUEST);
    let stored = send_with(&pool, "PUT", cred, Some(&token), &named("0"), b"blob").await;
    assert_eq!(stored.status, StatusCode::NO_CONTENT);
    let served = send(&pool, "GET", cred, Some(&token), b"").await;
    assert_eq!(
        (served.body.as_slice(), served.setup.as_deref()),
        (b"blob".as_slice(), Some("0"))
    );

    // Another tab sets chat up again.
    sqlx::query("UPDATE actors SET chat_setup_generation = 1 WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await
        .expect("a newer setup");
    let stale = send_with(&pool, "PUT", cred, Some(&token), &named("0"), b"stale").await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    let stale_key = publish(&pool, &token, &key(BOB_KEY)).await;
    assert_eq!(stale_key.status, StatusCode::CONFLICT);
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_keys")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(keys, 0);
    let newest = send_with(&pool, "PUT", cred, Some(&token), &named("1"), b"newest").await;
    assert_eq!(newest.status, StatusCode::NO_CONTENT);
    let served = send(&pool, "GET", cred, Some(&token), b"").await;
    assert_eq!(served.setup.as_deref(), Some("1"));
    let key_reply = send_with(
        &pool,
        "PUT",
        "/api/v1/me/chat_key",
        Some(&token),
        &named("1"),
        &key(BOB_KEY),
    )
    .await;
    assert_eq!(key_reply.status, StatusCode::NO_CONTENT);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn resetting_a_setup_keeps_the_address_and_forgets_the_rest(pool: PgPool) {
    let pair = bob_publishes(&pool, true).await;
    sqlx::query(
        "UPDATE actors SET chatmail_cred = '\\x01', chat_requires_reprovisioning = TRUE WHERE id = $1",
    )
    .bind(pair.bob)
    .execute(&pool)
    .await
    .expect("a blob and the flag");
    let setup = noombat_chat::keys::set_up(&pool, pair.bob, RELAY, |address| async move {
        Ok((address.expect("the address kept"), "rotated".to_owned()))
    })
    .await
    .expect("set up again");
    assert_eq!(setup.password, "rotated");
    assert_eq!(setup.generation, 1);
    let (address, blob, flagged): (Option<String>, Option<Vec<u8>>, bool) = sqlx::query_as(
        "SELECT chatmail_addr, chatmail_cred, chat_requires_reprovisioning FROM actors WHERE id = $1",
    )
    .bind(pair.bob)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(address.as_deref(), Some("bob@chat.noombat.example"));
    assert_eq!(blob, None);
    assert!(!flagged);
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_keys WHERE actor_id = $1")
        .bind(pair.bob)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(keys, 0);
}
