// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Erasure completes: the maildir, the retention window, and the 410.
//!
//! Three things were missing and each let an erasure look finished while
//! something survived it. `delete_account` had no caller, so the mailbox
//! stayed. `purge_tombstoned_actor` had no caller and keyed on a status
//! erasure shared with suspension, so the row stayed. And nothing served
//! `410 Gone`, so a peer that re-fetched an erased actor got a live
//! document and no reason to drop its copy.

use noombat_api::chatmail_ops;
use noombat_api::erasure;
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn insert_actor(pool: &PgPool, username: &str, chatmail: Option<&str>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             chatmail_addr) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE, $4) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(chatmail)
    .fetch_one(pool)
    .await
    .expect("actor fixture")
}

fn media_store() -> noombat_api::media::MediaStore {
    noombat_api::media::MediaStore::local(std::env::temp_dir()).expect("a local media store")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn erasure_records_the_maildir_it_owes(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", Some("alice@chat.example")).await;

    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    let (address, state): (String, String) =
        sqlx::query_as("SELECT address, state FROM chatmail_operations")
            .fetch_one(&pool)
            .await
            .expect("an operation was recorded");

    // Recorded before the tombstone, because tombstoning clears
    // `chatmail_addr` and afterwards nothing knows which mailbox to
    // remove. Without this the maildir simply survives the account.
    assert_eq!(address, "alice@chat.example");
    assert_eq!(state, "pending");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_account_with_no_chatmail_address_owes_nothing(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", None).await;

    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM chatmail_operations")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(count, 0);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn erasure_starts_the_retention_clock(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", None).await;

    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    // A second clock, separate from `deletion_requested_at`, and set
    // rather than inferred from `actor_status`, which erasure and
    // suspension share.
    let erased_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT erased_at FROM actors WHERE id = $1")
            .bind(actor)
            .fetch_one(&pool)
            .await
            .expect("readable");
    assert!(erased_at.is_some());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_row_is_purged_once_its_work_is_settled(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", None).await;
    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    let purged = erasure::purge_retained(&pool).await;
    assert_eq!(purged, 1);

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM actors WHERE id = $1")
        .bind(actor)
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(remaining, 0);

    // The 410 record outlives the row. That is the whole point of
    // keeping `tombstoned_actors` separate.
    let tombstones: i64 = sqlx::query_scalar("SELECT count(*) FROM tombstoned_actors")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(tombstones, 1);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_queued_delete_holds_the_row_open(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", None).await;
    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    sqlx::query(
        "INSERT INTO delivery_queue (actor_id, payload, target_inbox) \
         VALUES ($1, '{}'::jsonb, 'https://peer.example/inbox')",
    )
    .bind(actor)
    .execute(&pool)
    .await
    .expect("queued");

    // `fetch_signing_credentials` uses `fetch_one`, so deleting the row
    // now makes the queued Delete permanently unsignable and the peers
    // that never received it keep their copy forever.
    assert_eq!(erasure::purge_retained(&pool).await, 0);

    sqlx::query("DELETE FROM delivery_queue")
        .execute(&pool)
        .await
        .expect("drained");

    assert_eq!(erasure::purge_retained(&pool).await, 1);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_pending_maildir_holds_the_row_open_until_the_backstop(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", Some("alice@chat.example")).await;
    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    assert!(
        !chatmail_ops::settled_for(&pool, actor)
            .await
            .expect("readable")
    );
    assert_eq!(
        erasure::purge_retained(&pool).await,
        0,
        "the row carries the id the operation is keyed on"
    );

    // Thirty days on, the backstop wins: an erasure that never completes
    // is the defect this path exists to close, and a sidecar that is
    // permanently gone must not keep every erased row alive.
    sqlx::query("UPDATE actors SET erased_at = now() - interval '31 days' WHERE id = $1")
        .bind(actor)
        .execute(&pool)
        .await
        .expect("aged");

    assert_eq!(erasure::purge_retained(&pool).await, 1);

    // And the operation survives the row, so the address is still known.
    let address: String = sqlx::query_scalar("SELECT address FROM chatmail_operations")
        .fetch_one(&pool)
        .await
        .expect("readable");
    assert_eq!(address, "alice@chat.example");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_settled_operation_releases_the_row(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", Some("alice@chat.example")).await;
    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    sqlx::query("UPDATE chatmail_operations SET state = 'succeeded', completed_at = now()")
        .execute(&pool)
        .await
        .expect("settled");

    assert!(
        chatmail_ops::settled_for(&pool, actor)
            .await
            .expect("readable")
    );
    assert_eq!(erasure::purge_retained(&pool).await, 1);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_exhausted_operation_also_releases_the_row(pool: PgPool) {
    let actor = insert_actor(&pool, "alice", Some("alice@chat.example")).await;
    erasure::erase_actor(&pool, &None, &media_store(), actor)
        .await
        .expect("erased");

    sqlx::query("UPDATE chatmail_operations SET state = 'failed', attempts = 8")
        .execute(&pool)
        .await
        .expect("failed");

    // Settled is drained *or* exhausted. An operation that has failed
    // its last attempt will never succeed, and holding the row open for
    // it means the retention window never ends.
    assert!(
        chatmail_ops::settled_for(&pool, actor)
            .await
            .expect("readable")
    );
    assert_eq!(erasure::purge_retained(&pool).await, 1);

    // And it is still on the administration page, which is the point of
    // giving up loudly rather than silently.
    let failures = chatmail_ops::failures(&pool).await.expect("readable");
    assert_eq!(failures.len(), 1);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn two_erasures_of_one_address_are_one_piece_of_work(pool: PgPool) {
    let alice = insert_actor(&pool, "alice", Some("shared@chat.example")).await;
    erasure::erase_actor(&pool, &None, &media_store(), alice)
        .await
        .expect("erased");

    chatmail_ops::enqueue_delete(&pool, alice, "shared@chat.example")
        .await
        .expect("second enqueue");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM chatmail_operations")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(count, 1);
}
