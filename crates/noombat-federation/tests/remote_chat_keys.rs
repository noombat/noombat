// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Members of other noombat instances, against a local server standing in
//! for their instance: reading its chat domain from NodeInfo, and keeping
//! a member's chat key when their actor is fetched or updated. Its own
//! test binary, because it allows fetches to loopback addresses for the
//! whole process.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use noombat_federation::nodeinfo::{fetch_chatmail_domain, remote_chatmail_domain};
use noombat_federation::remote_chat_key::find_by_handle;
use reqwest::Url;
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve each request's path from `route`, which gives a status and a body,
/// and return the server's origin.
async fn serve(route: impl Fn(&str, &str) -> (u16, String) + Send + 'static) -> Url {
    // Named `localhost`, so that a chat domain can sit under its host.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let origin = format!("http://localhost:{port}");
    let base = origin.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]);
            let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
            let (status, body) = route(&base, &path);
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    Url::parse(&origin).expect("origin")
}

fn client() -> reqwest::Client {
    noombat_federation::http::set_allow_local_targets(true);
    noombat_federation::http::client("noombat-test".into(), Duration::from_secs(5)).expect("client")
}

fn links_to(href: &str) -> String {
    let rel = "http://nodeinfo.diaspora.software/ns/schema/2.1";
    serde_json::json!({ "links": [{ "rel": rel, "href": href }] }).to_string()
}

#[tokio::test]
async fn the_chat_domain_is_read_from_the_linked_document() {
    // Linked at a path of its own; the usual path names another domain.
    let origin = serve(|base, path| match path {
        "/.well-known/nodeinfo" => (200, links_to(&format!("{base}/nodeinfo/custom"))),
        "/nodeinfo/custom" => (
            200,
            r#"{"version":"2.1","metadata":{"noombat:chatmailDomain":"Chat.Other.Example"}}"#
                .into(),
        ),
        "/nodeinfo/2.1" => (
            200,
            r#"{"version":"2.1","metadata":{"noombat:chatmailDomain":"chat.wrong.example"}}"#
                .into(),
        ),
        _ => (404, "{}".into()),
    })
    .await;
    let domain = fetch_chatmail_domain(&client(), &origin)
        .await
        .expect("read");
    assert_eq!(domain.as_deref(), Some("chat.other.example"));
}

#[tokio::test]
async fn an_instance_without_a_chat_domain_publishes_none() {
    let origin = serve(|base, path| match path {
        "/.well-known/nodeinfo" => (200, links_to(&format!("{base}/nodeinfo/2.1"))),
        "/nodeinfo/2.1" => (200, r#"{"version":"2.1","metadata":{}}"#.into()),
        _ => (404, "{}".into()),
    })
    .await;
    let domain = fetch_chatmail_domain(&client(), &origin)
        .await
        .expect("read");
    assert_eq!(domain, None);
}

#[tokio::test]
async fn a_document_on_another_host_is_not_followed() {
    // The link names the same server by another host name, where a chat
    // domain is served: following it would read that domain.
    let origin = serve(|base, path| match path {
        "/.well-known/nodeinfo" => (
            200,
            links_to(&format!(
                "{}/nodeinfo/elsewhere",
                base.replace("localhost", "127.0.0.1")
            )),
        ),
        _ => (
            200,
            r#"{"metadata":{"noombat:chatmailDomain":"chat.elsewhere.example"}}"#.into(),
        ),
    })
    .await;
    let domain = fetch_chatmail_domain(&client(), &origin)
        .await
        .expect("read");
    assert_eq!(domain, None);
}

#[tokio::test]
async fn a_missing_nodeinfo_is_an_error_not_an_absence() {
    let origin = serve(|_, _| (404, "{}".into())).await;
    assert!(fetch_chatmail_domain(&client(), &origin).await.is_err());
}

// Made by OpenPGP.js 6.3.2 as the web client makes a member's key, for
// bob@chat.localhost.
const BOB_KEY: &str = concat!(
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

/// Another noombat instance: its NodeInfo names chat.localhost, its
/// WebFinger names Bob's actor at `actor` (his own URL when `None`), and
/// his actor document carries his key while `publishes` holds.
fn other_instance(
    publishes: Arc<AtomicBool>,
    actor: Option<&'static str>,
) -> impl Fn(&str, &str) -> (u16, String) + Send + 'static {
    move |base, path| match path {
        webfinger if webfinger.starts_with("/.well-known/webfinger?resource=acct%3Abob%40") => {
            let href = actor.map_or_else(|| format!("{base}/users/bob"), str::to_owned);
            let jrd = serde_json::json!({
                "subject": "acct:bob@other.example",
                "links": [{ "rel": "self", "type": "application/activity+json", "href": href }],
            });
            (200, jrd.to_string())
        }
        // A refusal whose body still names an actor, which must not be read.
        refused if refused.starts_with("/.well-known/webfinger?resource=acct%3Arefused%40") => {
            let jrd = serde_json::json!({
                "subject": "acct:refused@other.example",
                "links": [{
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": format!("{base}/users/bob"),
                }],
            });
            (404, jrd.to_string())
        }
        "/.well-known/nodeinfo" => (200, links_to(&format!("{base}/nodeinfo/2.1"))),
        "/nodeinfo/2.1" => (
            200,
            r#"{"version":"2.1","metadata":{"noombat:chatmailDomain":"chat.localhost"}}"#.into(),
        ),
        "/users/bob" => {
            let mut actor = serde_json::json!({
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
            });
            if publishes.load(Ordering::SeqCst) {
                actor["noombat:chatKey"] = serde_json::json!({
                    "noombat:address": "bob@chat.localhost",
                    "noombat:keyData": BOB_KEY,
                });
            }
            (200, actor.to_string())
        }
        _ => (404, "{}".into()),
    }
}

async fn stored_address(pool: &PgPool, ap_id: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT k.address FROM chat_keys k JOIN actors a ON a.id = k.actor_id WHERE a.ap_id = $1",
    )
    .bind(ap_id)
    .fetch_optional(pool)
    .await
    .expect("query")
}

/// The instance actor that signs this instance's fetches.
async fn insert_signing_actor(pool: &PgPool) {
    let keys = noombat_identity::keys::generate_rsa_keypair().expect("RSA key");
    sqlx::query(
        "INSERT INTO actors \
             (actor_type, ap_id, username, domain, public_key_pem, private_key_pem, is_local) \
         VALUES ('application', 'https://noombat.example/actor', 'noombat.example', \
                 'noombat.example', $1, $2, TRUE)",
    )
    .bind(&keys.public_pem)
    .bind(&keys.private_pem)
    .execute(pool)
    .await
    .expect("instance actor");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_update_keeps_a_members_key_and_a_plain_fetch_does_not(pool: PgPool) {
    insert_signing_actor(&pool).await;
    let publishes = Arc::new(AtomicBool::new(false));
    let origin = serve(other_instance(Arc::clone(&publishes), None)).await;
    let client = client();
    let bob = format!("{origin}users/bob");

    noombat_federation::inbox::resolve_actor(&pool, &client, &bob)
        .await
        .expect("resolved");
    assert_eq!(stored_address(&pool, &bob).await, None);

    // Bob publishes a key and his instance sends an Update.
    publishes.store(true, Ordering::SeqCst);
    let update = serde_json::json!({
        "id": format!("{origin}activities/1"),
        "type": "Update",
        "actor": bob,
        "object": { "id": bob, "type": "Person" },
    });
    let activity = serde_json::from_value(update.clone()).expect("an activity");
    noombat_federation::inbox::process_activity(&pool, &client, &bob, &update, activity)
        .await
        .expect("processed");
    assert_eq!(
        stored_address(&pool, &bob).await.as_deref(),
        Some("bob@chat.localhost")
    );

    // A plain fetch, as made while checking an inbound signature, reads no
    // key even when the document carries one.
    sqlx::query("DELETE FROM actors WHERE ap_id = $1")
        .bind(&bob)
        .execute(&pool)
        .await
        .expect("forget bob");
    noombat_federation::inbox::resolve_actor(&pool, &client, &bob)
        .await
        .expect("resolved");
    assert_eq!(stored_address(&pool, &bob).await, None);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_cached_chat_domain_is_used_for_a_day_then_read_again(pool: PgPool) {
    let origin = serve(other_instance(Arc::new(AtomicBool::new(true)), None)).await;
    let client = client();
    let domain =
        origin.host_str().expect("host").to_owned() + &format!(":{}", origin.port().expect("port"));
    let actor = format!("{origin}users/bob");
    sqlx::query(
        "INSERT INTO remote_chatmail_domains (domain, chatmail_domain) \
         VALUES ($1, 'chat.cached.example')",
    )
    .bind(&domain)
    .execute(&pool)
    .await
    .expect("fresh entry");
    let cached = remote_chatmail_domain(&pool, &client, &actor).await;
    assert_eq!(
        cached.expect("cached").as_deref(),
        Some("chat.cached.example")
    );

    sqlx::query("UPDATE remote_chatmail_domains SET fetched_at = now() - interval '25 hours'")
        .execute(&pool)
        .await
        .expect("expire");
    let read = remote_chatmail_domain(&pool, &client, &actor).await;
    assert_eq!(read.expect("read").as_deref(), Some("chat.localhost"));
    let recorded: (Option<String>, bool) = sqlx::query_as(
        "SELECT chatmail_domain, fetched_at > now() - interval '1 minute' \
         FROM remote_chatmail_domains WHERE domain = $1",
    )
    .bind(&domain)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(recorded, (Some("chat.localhost".into()), true));
}

/// The relay sends to the stand-in instance's chat domain.
fn allowlist() -> Vec<String> {
    vec!["chat.localhost".to_owned()]
}

fn authority(origin: &Url) -> String {
    format!(
        "{}:{}",
        origin.host_str().expect("host"),
        origin.port().expect("port")
    )
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_elsewhere_is_found_by_handle_once_they_publish(pool: PgPool) {
    insert_signing_actor(&pool).await;
    let publishes = Arc::new(AtomicBool::new(false));
    let origin = serve(other_instance(Arc::clone(&publishes), None)).await;
    let client = client();
    let domain = authority(&origin);

    // Known here before he published a key, then looked up after.
    let found = find_by_handle(&pool, &client, "bob", &domain, &allowlist())
        .await
        .expect("looked up");
    assert!(found.is_none());
    publishes.store(true, Ordering::SeqCst);
    let (actor, key) = find_by_handle(&pool, &client, "bob", &domain, &allowlist())
        .await
        .expect("looked up")
        .expect("a key");
    assert_eq!(actor.ap_id, format!("{origin}users/bob"));
    assert_eq!(key.address, "bob@chat.localhost");
    assert_eq!(key.key, base64_decode(BOB_KEY));

    // Kept, and used without fetching him again: a document that no longer
    // carries it reaches this instance as an `Update`.
    publishes.store(false, Ordering::SeqCst);
    let found = find_by_handle(&pool, &client, "bob", &domain, &allowlist())
        .await
        .expect("looked up");
    assert!(found.is_some());

    // A day on, the kept key is read again, and goes with the document's.
    sqlx::query("UPDATE chat_keys SET updated_at = now() - interval '25 hours'")
        .execute(&pool)
        .await
        .expect("aged");
    let found = find_by_handle(&pool, &client, "bob", &domain, &allowlist())
        .await
        .expect("looked up");
    assert!(
        found.is_none(),
        "a day-old key was trusted without reading it again"
    );
    publishes.store(true, Ordering::SeqCst);

    // Kept, but not offered while the relay cannot send to that domain.
    let other_relay = vec!["chat.third.example".to_owned()];
    let found = find_by_handle(&pool, &client, "bob", &domain, &other_relay).await;
    assert!(matches!(found, Ok(None)), "{found:?}");
}

fn base64_decode(b64: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("a fixture")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_webfinger_refusal_names_no_actor(pool: PgPool) {
    let origin = serve(other_instance(Arc::new(AtomicBool::new(true)), None)).await;
    let found = find_by_handle(
        &pool,
        &client(),
        "refused",
        &authority(&origin),
        &allowlist(),
    )
    .await;
    assert!(found.is_err(), "{found:?}");
}

#[test]
fn a_loopback_name_is_reached_over_http_in_the_development_posture() {
    let _ = client();
    assert_eq!(
        noombat_federation::http::scheme_for("127.0.0.1:8080"),
        "http"
    );
    assert_eq!(
        noombat_federation::http::scheme_for("localhost:8443"),
        "http"
    );
    assert_eq!(
        noombat_federation::http::scheme_for("other.example"),
        "https"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn nothing_is_looked_up_on_a_blocked_domain(pool: PgPool) {
    sqlx::query(
        "INSERT INTO domain_restrictions (domain, restriction) VALUES ('blocked.invalid', 'block')",
    )
    .execute(&pool)
    .await
    .expect("block");
    // `.invalid` never resolves, so reaching the network would be an error,
    // whichever spelling of the blocked host the handle uses.
    sqlx::query(
        "INSERT INTO domain_restrictions (domain, restriction) VALUES ('Shouting.Invalid', 'block')",
    )
    .execute(&pool)
    .await
    .expect("a block stored in mixed case");
    for domain in [
        "blocked.invalid",
        "BLOCKED.Invalid",
        "blocked.invalid:443",
        "shouting.invalid",
    ] {
        let found = find_by_handle(&pool, &client(), "bob", domain, &allowlist()).await;
        assert!(matches!(found, Ok(None)), "{domain}: {found:?}");
    }

    // A handle whose WebFinger names an actor on the blocked domain, spelt
    // as the URL parser reads it and in two other ways.
    for actor in [
        "http://blocked.invalid/users/bob",
        "http://BLOCKED.invalid/users/bob",
        "http://blocked.invalid:80/users/bob",
        // No host can be read from it at all.
        "not a url",
    ] {
        let origin = serve(other_instance(Arc::new(AtomicBool::new(true)), Some(actor))).await;
        let found =
            find_by_handle(&pool, &client(), "bob", &authority(&origin), &allowlist()).await;
        assert!(matches!(found, Ok(None)), "{actor}: {found:?}");
    }
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_handle_naming_an_actor_of_this_instance_finds_nothing(pool: PgPool) {
    let origin = serve(other_instance(Arc::new(AtomicBool::new(true)), None)).await;
    let bob = format!("{origin}users/bob");
    sqlx::query(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, 'bob', 'noombat.example', 'KEY', TRUE)",
    )
    .bind(&bob)
    .execute(&pool)
    .await
    .expect("local actor");
    let found = find_by_handle(&pool, &client(), "bob", &authority(&origin), &allowlist()).await;
    assert!(matches!(found, Ok(None)), "{found:?}");
}
