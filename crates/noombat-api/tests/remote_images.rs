// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The queue that fetches a remote post's pictures.
//!
//! The success path needs a peer to fetch from, so what is asserted here
//! is everything around it: that a refused URL is recorded rather than
//! retried for ever, that the guard refuses the URLs it must, and that a
//! deleted post takes its owed work with it.

use std::time::Duration;

use noombat_api::media::MediaStore;
use noombat_api::media_ops;
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn actor(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('individual', $1, $2, 'PEM', $3, FALSE) RETURNING id",
    )
    .bind(format!("https://peer.example/users/a-{id}"))
    .bind(format!("peer{}", &id.simple().to_string()[..8]))
    .bind("peer.example")
    .fetch_one(pool)
    .await
    .expect("insert actor")
}

async fn post(pool: &PgPool, author: Uuid) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO posts (actor_id, ap_id, content_html, ap_object) \
         VALUES ($1, $2, '<p>hi</p>', '{}'::jsonb) RETURNING id",
    )
    .bind(author)
    .bind(format!("https://peer.example/posts/{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("insert post")
}

async fn enqueue(pool: &PgPool, post_id: Uuid, actor_id: Uuid, url: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO media_fetch_operations (post_id, actor_id, remote_url, ordinal) \
         VALUES ($1, $2, $3, 0) RETURNING id",
    )
    .bind(post_id)
    .bind(actor_id)
    .bind(url)
    .fetch_one(pool)
    .await
    .expect("enqueue")
}

async fn state_of(pool: &PgPool, id: Uuid) -> (String, i32, Option<String>) {
    sqlx::query_as("SELECT state, attempts, last_error FROM media_fetch_operations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read back")
}

fn store() -> (tempfile::TempDir, MediaStore) {
    let root = tempfile::tempdir().expect("temp dir");
    let media = MediaStore::local(root.path()).expect("store");
    (root, media)
}

/// A URL the fetch guard refuses is recorded and retried, not dropped
/// and not attempted for ever. `169.254.169.254` is the case the guard
/// exists for: it hands out cloud credentials to anything that asks.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_url_is_recorded_and_retried(pool: PgPool) {
    let (_root, media) = store();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");

    let author = actor(&pool).await;
    let post_id = post(&pool, author).await;
    let id = enqueue(
        &pool,
        post_id,
        author,
        "https://169.254.169.254/latest/meta-data",
    )
    .await;

    let stored = media_ops::drain(&pool, &media, &client, DOMAIN).await;
    assert_eq!(stored, 0, "a refused URL must store nothing");

    let (state, attempts, last_error) = state_of(&pool, id).await;
    assert_eq!(state, "pending", "one refusal is not a permanent failure");
    assert_eq!(attempts, 1);

    // The guard refused it, rather than the network failing to reach it.
    // Asserting only that something went wrong would pass just as well
    // with no guard at all, since the address is unroutable either way.
    let reason = last_error.expect("the reason has to be kept");
    assert!(
        reason.contains("private or reserved address"),
        "the fetch must be refused before it is attempted, got: {reason}"
    );

    // And it is not due again immediately, or the worker would spin on it.
    let due_now: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM media_fetch_operations \
         WHERE id = $1 AND next_attempt_at <= now()",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(due_now, 0, "the retry has to wait");
}

/// A fetch that keeps failing is eventually given up on, so the queue
/// does not grow a permanent tail of work nobody will ever complete.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_fetch_is_given_up_on_eventually(pool: PgPool) {
    let (_root, media) = store();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");

    let author = actor(&pool).await;
    let post_id = post(&pool, author).await;
    let id = enqueue(&pool, post_id, author, "https://127.0.0.1/private.png").await;

    // Short of the limit, then one more. The row is made due again
    // between passes, which is what the backoff would do in time.
    for _ in 0..6 {
        sqlx::query("UPDATE media_fetch_operations SET next_attempt_at = now() WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("make due");
        media_ops::drain(&pool, &media, &client, DOMAIN).await;
    }

    let (state, attempts, _) = state_of(&pool, id).await;
    assert_eq!(state, "failed");
    assert!(attempts >= 6, "got {attempts}");
}

/// Deleting the post takes its owed fetches with it. Work queued for a
/// post that no longer exists could never produce a visible image, and
/// would keep contacting a peer about it.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn deleting_the_post_cancels_its_fetches(pool: PgPool) {
    let author = actor(&pool).await;
    let post_id = post(&pool, author).await;
    enqueue(&pool, post_id, author, "https://peer.example/a.png").await;

    sqlx::query("DELETE FROM posts WHERE id = $1")
        .bind(post_id)
        .execute(&pool)
        .await
        .expect("delete post");

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM media_fetch_operations")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(left, 0);
}

/// The same image delivered twice is the same work, not more of it. A
/// peer may redeliver a document, and each redelivery must not add
/// another fetch of a picture already queued.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_redelivered_image_is_queued_once(pool: PgPool) {
    let author = actor(&pool).await;
    let post_id = post(&pool, author).await;

    for _ in 0..3 {
        sqlx::query(
            "INSERT INTO media_fetch_operations (post_id, actor_id, remote_url, ordinal) \
             VALUES ($1, $2, $3, 0) ON CONFLICT (post_id, remote_url) DO NOTHING",
        )
        .bind(post_id)
        .bind(author)
        .bind("https://peer.example/a.png")
        .execute(&pool)
        .await
        .expect("enqueue");
    }

    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM media_fetch_operations")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(queued, 1);
}

/// A fetched image keeps the position it had in the peer's document, so
/// the gallery reads in the order its author arranged rather than in
/// whichever order the fetches happened to finish.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_gallery_reads_in_the_authors_order(pool: PgPool) {
    let author = actor(&pool).await;
    let post_id = post(&pool, author).await;

    // Written in reverse, as concurrent fetches finishing out of order
    // would write them.
    for ordinal in [2_i16, 0, 1] {
        let key = Uuid::new_v4().simple().to_string();
        sqlx::query(
            "INSERT INTO media_attachments \
                 (actor_id, post_id, media_type, object_key, backend, purpose, url, ordinal) \
             VALUES ($1, $2, 'image/png', $3, 'local', 'post', $4, $5)",
        )
        .bind(author)
        .bind(post_id)
        .bind(&key)
        .bind(format!("https://{DOMAIN}/media/{ordinal}"))
        .bind(ordinal)
        .execute(&pool)
        .await
        .expect("insert attachment");
    }

    // Through the reader the pages use, not a query of this test's own:
    // asserting on its own SQL would still pass if that function stopped
    // ordering by position.
    let urls: Vec<String> = noombat_api::routes::feed::attachments_for(&pool, post_id)
        .await
        .into_iter()
        .map(|attachment| attachment.url)
        .collect();

    assert_eq!(
        urls,
        vec![
            format!("https://{DOMAIN}/media/0"),
            format!("https://{DOMAIN}/media/1"),
            format!("https://{DOMAIN}/media/2"),
        ]
    );
}
