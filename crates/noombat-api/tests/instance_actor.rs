// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Server-to-server fetches are signed as the instance, not as a person.
//!
//! The assertion that matters is the one made with an administrator
//! present: picking the instance actor from an instance that has no admin
//! proves nothing, because the old selection would have fallen through to
//! the same row.

use noombat_federation::signed_fetch::find_local_signing_actor;
use noombat_identity::repo::{ensure_instance_actor, find_instance_actor};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

/// An ordinary local actor holding a private key, at the given role.
async fn local_actor(pool: &PgPool, username: &str, role: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors \
             (actor_type, ap_id, username, public_key_pem, private_key_pem, \
              ed25519_public_key, ed25519_private_key, domain, is_local, instance_role) \
         VALUES ('individual', $1, $2, 'PEM', 'PRIV', 'ED-PUB', 'ED-PRIV', $3, TRUE, $4) \
         RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("insert actor")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn fetches_are_signed_as_the_instance_even_when_an_admin_exists(pool: PgPool) {
    let admin = local_actor(&pool, "root", "admin").await;
    let instance = ensure_instance_actor(&pool, DOMAIN).await.expect("mint");

    let signer = find_local_signing_actor(&pool)
        .await
        .expect("select signer");

    assert_eq!(
        signer, instance,
        "an outbound fetch signed as the administrator discloses them to the host being asked"
    );
    assert_ne!(signer, admin);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_instance_actor_is_minted_once(pool: PgPool) {
    let first = ensure_instance_actor(&pool, DOMAIN).await.expect("mint");
    let second = ensure_instance_actor(&pool, DOMAIN).await.expect("re-mint");

    assert_eq!(first, second, "a second boot minted a second signing key");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM actors WHERE is_local AND actor_type = 'application'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_schema_refuses_a_second_instance_actor(pool: PgPool) {
    ensure_instance_actor(&pool, DOMAIN).await.expect("mint");

    // Which key signs is selected by type with LIMIT 1, so two rows would
    // make it depend on row order rather than on anything decided.
    let refused = sqlx::query(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('application', $1, 'impostor', 'PEM', $2, TRUE)",
    )
    .bind(format!("https://{DOMAIN}/users/impostor"))
    .bind(DOMAIN)
    .execute(&pool)
    .await;

    assert!(refused.is_err(), "a second instance actor was accepted");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_instance_actor_is_named_for_the_domain(pool: PgPool) {
    let id = ensure_instance_actor(&pool, DOMAIN).await.expect("mint");

    let (username, actor_type): (String, String) =
        sqlx::query_as("SELECT username, actor_type FROM actors WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();

    // A dot cannot appear in a registerable username, so this name is
    // unreachable by any person and needs no reservation list.
    assert_eq!(username, DOMAIN);
    assert_eq!(actor_type, "application");
    assert_eq!(find_instance_actor(&pool).await.unwrap(), Some(id));
}

/// The characters a receiving instance admits in an actor's path segment.
///
/// GoToSocial parses the username back out of `/users/{username}` with
/// `[a-z0-9_.-]+`. Mastodon and Mitra are no more permissive. A key id
/// carrying anything else names a different actor to the peer than the one
/// that signed, so the signature cannot verify.
fn is_parseable_by_a_peer(username: &str) -> bool {
    !username.is_empty()
        && username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

#[test]
fn the_instance_actor_username_drops_the_port() {
    // The domain carries a port in every development and test stack, which
    // is where the interop suites run, so this is the configuration the
    // suites actually exercise rather than an exotic one.
    assert_eq!(
        noombat_identity::repo::instance_actor_username("noombat.localhost:8443"),
        "noombat.localhost"
    );
    assert_eq!(
        noombat_identity::repo::instance_actor_username("noombat.example"),
        "noombat.example"
    );
}

#[test]
fn a_ported_domain_still_yields_a_username_a_peer_can_parse() {
    // Guards the guard: a colon is what broke this, so assert against the
    // character rule rather than against one known-bad string.
    for domain in [
        "noombat.localhost:8443",
        "noombat.example",
        "127.0.0.1:8443",
    ] {
        let username = noombat_identity::repo::instance_actor_username(domain);
        assert!(
            is_parseable_by_a_peer(&username),
            "{domain} minted the unparseable username {username:?}"
        );
    }
    assert!(
        !is_parseable_by_a_peer("noombat.localhost:8443"),
        "the character rule accepts a colon, so it would not have caught this"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_ported_domain_mints_a_resolvable_key_id(pool: PgPool) {
    // The end of the chain the fix is about: what a peer dereferences is
    // the last segment of the key id, and it has to name this actor.
    let ported = "noombat.localhost:8443";
    let id = ensure_instance_actor(&pool, ported).await.expect("mint");

    let (username, ap_id): (String, String) =
        sqlx::query_as("SELECT username, ap_id FROM actors WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let segment = ap_id.rsplit('/').next().expect("a path segment");
    assert_eq!(segment, username, "the key id names a different actor");
    assert!(
        is_parseable_by_a_peer(segment),
        "a peer cannot parse {segment:?} out of {ap_id}"
    );
    assert_eq!(ap_id, format!("https://{ported}/users/noombat.localhost"));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_instance_without_one_still_federates(pool: PgPool) {
    // The fallback exists so that an instance mid-setup can still fetch.
    // It is a window, not a resting state: the boot sequence closes it.
    let only = local_actor(&pool, "alice", "user").await;

    let signer = find_local_signing_actor(&pool)
        .await
        .expect("select signer");

    assert_eq!(signer, only);
}
