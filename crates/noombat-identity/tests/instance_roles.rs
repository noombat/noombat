// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Instance roles: the write path, and the two refusals that keep an
//! instance from locking itself out.
//!
//! These drive the repository layer directly, because the interesting
//! behaviour is the guard arithmetic rather than the HTTP.

use noombat_core::actor::InstanceRole;
use noombat_identity::repo::{count_admins, set_instance_role};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn insert_actor(pool: &PgPool, username: &str, role: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local, instance_role)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE, $5)"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(role)
    .execute(pool)
    .await
    .expect("actor fixture inserted");
    id
}

async fn role_of(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT instance_role FROM actors WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("role readable")
}

/// The write path exists at all, which is the whole point.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_can_be_written(pool: PgPool) {
    let id = insert_actor(&pool, "alice", "user").await;
    assert_eq!(role_of(&pool, id).await, "user", "fixture starts as a user");

    set_instance_role(&pool, id, InstanceRole::Admin)
        .await
        .expect("promotion should succeed");

    assert_eq!(role_of(&pool, id).await, "admin");
}

/// Remote actors are not ours to promote.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_remote_actor_cannot_be_promoted(pool: PgPool) {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO actors (id, actor_type, ap_id, username, domain, public_key_pem, is_local)
           VALUES ($1, 'individual', 'https://elsewhere.example/users/bob', 'bob',
                   'elsewhere.example', 'PEM', FALSE)"#,
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("remote fixture inserted");

    let result = set_instance_role(&pool, id, InstanceRole::Admin).await;

    assert!(result.is_err(), "a remote actor must not be promotable");
    assert_eq!(role_of(&pool, id).await, "user", "and must be unchanged");
}

/// The count that the last-administrator guard depends on.
///
/// The guard is only as good as this arithmetic, and a count that
/// included moderators or remote actors would let the last admin be
/// demoted while reporting that others remained.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn only_local_admins_are_counted(pool: PgPool) {
    insert_actor(&pool, "alice", "admin").await;
    insert_actor(&pool, "mod", "moderator").await;
    insert_actor(&pool, "carol", "user").await;
    sqlx::query(
        r#"INSERT INTO actors (id, actor_type, ap_id, username, domain, public_key_pem,
                               is_local, instance_role)
           VALUES (gen_random_uuid(), 'individual', 'https://elsewhere.example/users/dave',
                   'dave', 'elsewhere.example', 'PEM', FALSE, 'admin')"#,
    )
    .execute(&pool)
    .await
    .expect("remote admin fixture inserted");

    assert_eq!(
        count_admins(&pool).await.expect("countable"),
        1,
        "a moderator is not an administrator and a remote actor is not ours"
    );
}

/// The bootstrap's own condition: it fires on zero and not otherwise.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_bootstrap_condition_is_zero_administrators(pool: PgPool) {
    assert_eq!(count_admins(&pool).await.unwrap(), 0, "an empty instance");

    let id = insert_actor(&pool, "alice", "user").await;
    assert_eq!(count_admins(&pool).await.unwrap(), 0, "a user is not one");

    set_instance_role(&pool, id, InstanceRole::Admin)
        .await
        .unwrap();
    assert_eq!(
        count_admins(&pool).await.unwrap(),
        1,
        "once promoted, the bootstrap must not fire again on restart"
    );
}
