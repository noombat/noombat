// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The three relay verification policies do three different things.
//!
//! An administrator could choose `verify`, `verify-or-fetch` or
//! `trust-relay` and the instance behaved identically under all three: a
//! relay's `Announce` was handled as an ordinary boost, the embedded
//! activity was ignored, and the post was re-fetched from its origin
//! whatever the setting said. The setting was offered and did nothing.
//!
//! What the flag means is the other half. `integrity_proof_verified`
//! could not carry it: a directly delivered post with no proof is also
//! NULL there, and that post is authenticated by an HTTP Signature bound
//! to its author, which a relayed one is not.

use noombat_core::authorisation::{ConnectionState, Relationship};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn insert_actor(pool: &PgPool, username: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("actor fixture")
}

async fn insert_post(pool: &PgPool, actor: Uuid, tag: &str, relayed_unverified: bool) -> Uuid {
    let post_id: Uuid = sqlx::query_scalar(
        "INSERT INTO posts (actor_id, ap_id, post_type, content_html, visibility, \
                            relayed_unverified, ap_object) \
         VALUES ($1, $2, 'note', 'hello', 'public', $3, '{}'::jsonb) RETURNING id",
    )
    .bind(actor)
    .bind(format!("https://{DOMAIN}/p/{}", Uuid::new_v4()))
    .bind(relayed_unverified)
    .fetch_one(pool)
    .await
    .expect("post fixture");

    let tag_id: Uuid = sqlx::query_scalar(
        "INSERT INTO hashtags (name) VALUES ($1) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(tag)
    .fetch_one(pool)
    .await
    .expect("hashtag fixture");

    sqlx::query("INSERT INTO post_hashtags (post_id, hashtag_id) VALUES ($1, $2)")
        .bind(post_id)
        .bind(tag_id)
        .execute(pool)
        .await
        .expect("tag link");

    post_id
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_post_defaults_to_verified_rather_than_relayed(pool: PgPool) {
    let actor = insert_actor(&pool, "alice").await;
    let post = insert_post(&pool, actor, "rust", false).await;

    let flagged: bool = sqlx::query_scalar("SELECT relayed_unverified FROM posts WHERE id = $1")
        .bind(post)
        .fetch_one(&pool)
        .await
        .expect("readable");

    // The default has to be `false`, not `true`: every ordinary post
    // takes it, and a default of `true` would badge the whole instance.
    assert!(!flagged);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn trending_leaves_out_what_only_a_relay_vouches_for(pool: PgPool) {
    let actor = insert_actor(&pool, "alice").await;

    // One ordinary post on `#rust`, and three relayed ones on `#spam`.
    // Without the exclusion the relay's tag wins on volume alone, which
    // is the whole attack: a relay promoting a tag to every reader on
    // this instance with nothing behind any of the posts.
    insert_post(&pool, actor, "rust", false).await;
    for _ in 0..3 {
        insert_post(&pool, actor, "spam", true).await;
    }

    let tags = noombat_api::trending::compute_trending(&pool, 24, 20)
        .await
        .expect("trending computed");

    let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"rust"), "{names:?}");
    assert!(
        !names.contains(&"spam"),
        "a relay must not be able to promote a tag on its own word: {names:?}"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_relationship_resolver_costs_one_round_trip(pool: PgPool) {
    // Not a performance assertion: what is asserted is that both axes
    // come back from one call, so no route has to ask twice and risk
    // asking differently.
    let alice = insert_actor(&pool, "alice").await;
    let bob = insert_actor(&pool, "bob").await;

    noombat_identity::repo::create_follow(&pool, alice, bob, true)
        .await
        .expect("follow");
    noombat_identity::connections::invite(&pool, alice, bob, None)
        .await
        .expect("invite");
    noombat_identity::connections::accept(&pool, bob, alice)
        .await
        .expect("accept");

    let rel = noombat_identity::connections::relationship(&pool, Some(alice), bob)
        .await
        .expect("resolved");

    assert_eq!(rel.connection, ConnectionState::Accepted);
    assert!(rel.is_follower());

    // An anonymous viewer resolves without touching the database at all.
    let anonymous = noombat_identity::connections::relationship(&pool, None, bob)
        .await
        .expect("resolved");
    assert_eq!(anonymous, Relationship::NONE);
}
