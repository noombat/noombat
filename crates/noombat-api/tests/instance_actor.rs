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
