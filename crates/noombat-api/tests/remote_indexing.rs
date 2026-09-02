// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Whose consent is needed before a remote post is indexed, and what
//! happens when a removal fails.
//!
//! Three parties have to agree and they answer to different people: the
//! operator turns the feature on, the author consents through their own
//! `indexable`, and the post has to be public and not something this
//! instance took on a relay's word. Any one of them saying no is enough.
//!
//! The removal half is the reason the queue is durable. A search
//! document outlives the row it was built from, so a removal that fails
//! silently leaves erased writing findable by its full text.

use noombat_api::search_ops;
use noombat_federation::remote_indexing;
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn set_remote_indexing(pool: &PgPool, enabled: bool) {
    sqlx::query("UPDATE instance_settings SET index_remote_posts = $1")
        .bind(enabled)
        .execute(pool)
        .await
        .expect("setting saved");
}

async fn insert_actor(pool: &PgPool, username: &str, is_local: bool, indexable: bool) -> Uuid {
    let privacy = serde_json::json!({
        "discoverable": indexable,
        "indexable": indexable,
        "require_follow_approval": false,
        "federate_profile": true,
        "chatmail_visible": true,
        "show_followers_count": true,
        "cv_download": "public",
    });
    let host = if is_local { DOMAIN } else { "peer.example" };

    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             actor_privacy) \
         VALUES ('individual', $1, $2, $3, 'KEY', $4, $5) RETURNING id",
    )
    .bind(format!("https://{host}/users/{username}"))
    .bind(username)
    .bind(host)
    .bind(is_local)
    .bind(&privacy)
    .fetch_one(pool)
    .await
    .expect("actor fixture")
}

async fn insert_post(pool: &PgPool, actor: Uuid, visibility: &str, relayed: bool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO posts (actor_id, ap_id, post_type, content_html, visibility, \
                            relayed_unverified, ap_object) \
         VALUES ($1, $2, 'note', 'hello world', $3, $4, '{}'::jsonb) RETURNING id",
    )
    .bind(actor)
    .bind(format!("https://peer.example/p/{}", Uuid::new_v4()))
    .bind(visibility)
    .bind(relayed)
    .fetch_one(pool)
    .await
    .expect("post fixture")
}

async fn queued_upserts(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM search_index_operations WHERE operation = 'upsert'")
        .fetch_one(pool)
        .await
        .expect("countable")
}

// ..... The three conditions .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_switch_is_off_by_default(pool: PgPool) {
    let author = insert_actor(&pool, "remote", false, true).await;
    let post = insert_post(&pool, author, "public", false).await;

    assert!(!remote_indexing::remote_indexing_enabled(&pool).await);

    remote_indexing::enqueue_if_indexable(&pool, post)
        .await
        .expect("queued");

    // Nobody gets the wider corpus by not choosing.
    assert_eq!(queued_upserts(&pool).await, 0);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_author_who_declined_is_not_indexed_even_when_enabled(pool: PgPool) {
    set_remote_indexing(&pool, true).await;

    let declined = insert_actor(&pool, "declined", false, false).await;
    let agreed = insert_actor(&pool, "agreed", false, true).await;

    let declined_post = insert_post(&pool, declined, "public", false).await;
    let agreed_post = insert_post(&pool, agreed, "public", false).await;

    remote_indexing::enqueue_if_indexable(&pool, declined_post)
        .await
        .expect("queued");
    remote_indexing::enqueue_if_indexable(&pool, agreed_post)
        .await
        .expect("queued");

    // The operator's switch does not overrule the author.
    assert_eq!(queued_upserts(&pool).await, 1);

    let queued: String = sqlx::query_scalar(
        "SELECT document_id FROM search_index_operations WHERE operation = 'upsert'",
    )
    .fetch_one(&pool)
    .await
    .expect("readable");
    assert_eq!(queued, agreed_post.to_string());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_public_or_relayed_post_is_not_indexed(pool: PgPool) {
    set_remote_indexing(&pool, true).await;
    let author = insert_actor(&pool, "remote", false, true).await;

    let followers_only = insert_post(&pool, author, "followers", false).await;
    let relayed = insert_post(&pool, author, "public", true).await;

    remote_indexing::enqueue_if_indexable(&pool, followers_only)
        .await
        .expect("queued");
    remote_indexing::enqueue_if_indexable(&pool, relayed)
        .await
        .expect("queued");

    // A relay's word is not the author's, and search is a better
    // amplification surface than trending because a query is aimed.
    assert_eq!(queued_upserts(&pool).await, 0);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_indexed_remote_post_is_marked_as_remote(pool: PgPool) {
    set_remote_indexing(&pool, true).await;
    let author = insert_actor(&pool, "remote", false, true).await;
    let post = insert_post(&pool, author, "public", false).await;

    remote_indexing::enqueue_if_indexable(&pool, post)
        .await
        .expect("queued");

    let document: serde_json::Value =
        sqlx::query_scalar("SELECT document FROM search_index_operations")
            .fetch_one(&pool)
            .await
            .expect("readable");

    // Without this the two corpora are one and the reader's choice
    // between them cannot be offered.
    assert_eq!(document["is_local"], false);
    assert_eq!(document["visibility"], "public");
}

// ..... Trending honours the same two gates .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn trending_separates_the_local_and_fediverse_corpora(pool: PgPool) {
    use noombat_api::trending::{Scope, compute_trending};

    let local = insert_actor(&pool, "alice", true, true).await;
    let remote = insert_actor(&pool, "bob", false, true).await;

    let local_post = insert_post(&pool, local, "public", false).await;
    let remote_post = insert_post(&pool, remote, "public", false).await;
    tag(&pool, local_post, "here").await;
    tag(&pool, remote_post, "elsewhere").await;

    // Off: the fediverse scope collapses to the local one, so a reader
    // asking for it is not silently shown remote content the operator
    // never enabled.
    set_remote_indexing(&pool, false).await;
    let wide = compute_trending(&pool, 24, 20, Scope::Fediverse)
        .await
        .expect("computed");
    let names: Vec<&str> = wide.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"here"), "{names:?}");
    assert!(!names.contains(&"elsewhere"), "{names:?}");

    // On: the wider scope widens, and the narrow one does not.
    set_remote_indexing(&pool, true).await;
    let wide = compute_trending(&pool, 24, 20, Scope::Fediverse)
        .await
        .expect("computed");
    let names: Vec<&str> = wide.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"elsewhere"), "{names:?}");

    let narrow = compute_trending(&pool, 24, 20, Scope::Local)
        .await
        .expect("computed");
    let names: Vec<&str> = narrow.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"here"), "{names:?}");
    assert!(
        !names.contains(&"elsewhere"),
        "asking for local content must not return the wider list: {names:?}"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn trending_leaves_out_a_remote_author_who_declined(pool: PgPool) {
    use noombat_api::trending::{Scope, compute_trending};

    set_remote_indexing(&pool, true).await;
    let declined = insert_actor(&pool, "declined", false, false).await;
    let post = insert_post(&pool, declined, "public", false).await;
    tag(&pool, post, "unwanted").await;

    let wide = compute_trending(&pool, 24, 20, Scope::Fediverse)
        .await
        .expect("computed");
    let names: Vec<&str> = wide.iter().map(|t| t.name.as_str()).collect();
    assert!(!names.contains(&"unwanted"), "{names:?}");
}

async fn tag(pool: &PgPool, post: Uuid, name: &str) {
    let tag_id: Uuid = sqlx::query_scalar(
        "INSERT INTO hashtags (name) VALUES ($1) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("hashtag fixture");

    sqlx::query("INSERT INTO post_hashtags (post_id, hashtag_id) VALUES ($1, $2)")
        .bind(post)
        .bind(tag_id)
        .execute(pool)
        .await
        .expect("tag link");
}

// ..... Removals are durable .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_removal_supersedes_a_pending_upsert(pool: PgPool) {
    set_remote_indexing(&pool, true).await;
    let author = insert_actor(&pool, "remote", false, true).await;
    let post = insert_post(&pool, author, "public", false).await;

    remote_indexing::enqueue_if_indexable(&pool, post)
        .await
        .expect("queued");
    search_ops::enqueue_removal(&pool, "posts", &post.to_string())
        .await
        .expect("removal queued");

    let (operation, document): (String, Option<serde_json::Value>) =
        sqlx::query_as("SELECT operation, document FROM search_index_operations")
            .fetch_one(&pool)
            .await
            .expect("readable");

    // The removal is the one with a person behind it, so it wins.
    assert_eq!(operation, "remove");
    assert!(document.is_none());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_upsert_does_not_overwrite_a_pending_removal(pool: PgPool) {
    set_remote_indexing(&pool, true).await;
    let author = insert_actor(&pool, "remote", false, true).await;
    let post = insert_post(&pool, author, "public", false).await;

    search_ops::enqueue_removal(&pool, "posts", &post.to_string())
        .await
        .expect("removal queued");
    remote_indexing::enqueue_if_indexable(&pool, post)
        .await
        .expect("queued");

    let (operation, document, state): (String, Option<serde_json::Value>, String) =
        sqlx::query_as("SELECT operation, document, state FROM search_index_operations")
            .fetch_one(&pool)
            .await
            .expect("readable");

    assert_eq!(
        operation, "remove",
        "an upsert racing a removal must lose, or erased content returns"
    );

    // The row must be untouched, not merely still labelled a removal.
    // `operation` survives on its own because the upsert does not set
    // it, so asserting only that would pass with the guard removed and
    // test nothing: the body would have been written onto the removal.
    assert!(
        document.is_none(),
        "the upsert wrote its body onto a pending removal: {document:?}"
    );
    assert_eq!(state, "pending");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_stuck_removal_is_counted_for_the_administrator(pool: PgPool) {
    search_ops::enqueue_removal(&pool, "posts", "abc")
        .await
        .expect("queued");

    // Outstanding while pending: the document is still in the index.
    assert_eq!(
        search_ops::stuck_removals(&pool).await.expect("countable"),
        1
    );

    sqlx::query("UPDATE search_index_operations SET state = 'succeeded'")
        .execute(&pool)
        .await
        .expect("settled");

    assert_eq!(
        search_ops::stuck_removals(&pool).await.expect("countable"),
        0
    );

    // A removal that gave up still counts, because the document is
    // still there. Giving up is not the same as being done.
    sqlx::query("UPDATE search_index_operations SET state = 'failed', attempts = 8")
        .execute(&pool)
        .await
        .expect("failed");
    assert_eq!(
        search_ops::stuck_removals(&pool).await.expect("countable"),
        1
    );
    assert_eq!(
        search_ops::failures(&pool).await.expect("readable").len(),
        1
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_peer_deleting_its_user_withdraws_what_this_instance_indexed(pool: PgPool) {
    set_remote_indexing(&pool, true).await;
    let author = insert_actor(&pool, "remote", false, true).await;
    let post = insert_post(&pool, author, "public", false).await;

    remote_indexing::enqueue_if_indexable(&pool, post)
        .await
        .expect("queued");

    // The peer's Delete. This is the obligation that taking a copy of
    // somebody else's content creates: their instance says the account
    // is gone, and this one has to withdraw what it indexed.
    remote_indexing::enqueue_removals_for_actor(&pool, author)
        .await
        .expect("removals queued");

    let removals: Vec<(String, String)> = sqlx::query_as(
        "SELECT index_name, document_id FROM search_index_operations \
         WHERE operation = 'remove' ORDER BY index_name",
    )
    .fetch_all(&pool)
    .await
    .expect("readable");

    assert!(
        removals
            .iter()
            .any(|(index, id)| index == "posts" && id == &post.to_string()),
        "the indexed post was not withdrawn: {removals:?}"
    );
    assert!(
        removals
            .iter()
            .any(|(index, id)| index == "profiles" && id == &author.to_string()),
        "{removals:?}"
    );

    // And the queued upsert is gone, not merely joined by a removal.
    assert_eq!(queued_upserts(&pool).await, 0);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn erasure_records_every_document_it_must_withdraw(pool: PgPool) {
    let alice = insert_actor(&pool, "alice", true, true).await;
    let post = insert_post(&pool, alice, "public", false).await;

    noombat_api::erasure::erase_actor(
        &pool,
        &None,
        &noombat_api::media::MediaStore::local(std::env::temp_dir()).expect("media store"),
        alice,
    )
    .await
    .expect("erased");

    let queued: Vec<(String, String)> = sqlx::query_as(
        "SELECT index_name, document_id FROM search_index_operations \
         WHERE operation = 'remove' ORDER BY index_name",
    )
    .fetch_all(&pool)
    .await
    .expect("readable");

    // The profile and the post both. With no search backend configured
    // the work stays pending, which is the honest state rather than a
    // warning nobody reads.
    assert!(
        queued
            .iter()
            .any(|(index, id)| index == "profiles" && id == &alice.to_string()),
        "{queued:?}"
    );
    assert!(
        queued
            .iter()
            .any(|(index, id)| index == "posts" && id == &post.to_string()),
        "{queued:?}"
    );
}
