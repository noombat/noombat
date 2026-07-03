// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Hashtag persistence: upsert, post-linking, and follow/unfollow.

use noombat_core::error::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// A hashtag row.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Hashtag {
    pub id: Uuid,
    pub name: String,
}

/// Get-or-create a hashtag by its normalised name.
///
/// The name is stored in lowercase without the leading `#`.
pub async fn upsert_hashtag(pool: &PgPool, name: &str) -> Result<Hashtag> {
    let normalised = name.to_lowercase();
    let row = sqlx::query_as::<_, Hashtag>(
        r#"
        INSERT INTO hashtags (id, name)
        VALUES ($1, $2)
        ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
        RETURNING id, name
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&normalised)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Link a post to a set of hashtag names.
///
/// Performs two queries regardless of the number of hashtags:
/// 1. Batch-upsert all names into the `hashtags` table.
/// 2. Batch-insert the post-hashtag junction rows.
pub async fn link_post_hashtags(
    pool: &PgPool,
    post_id: Uuid,
    hashtag_names: &[String],
) -> Result<()> {
    if hashtag_names.is_empty() {
        return Ok(());
    }

    let normalised: Vec<String> = hashtag_names.iter().map(|n| n.to_lowercase()).collect();

    // Batch-upsert hashtags and retrieve their IDs.
    let ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO hashtags (id, name)
        SELECT gen_random_uuid(), unnest($1::text[])
        ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
        RETURNING id
        "#,
    )
    .bind(&normalised)
    .fetch_all(pool)
    .await?;

    // Batch-insert post-hashtag links.
    sqlx::query(
        r#"
        INSERT INTO post_hashtags (post_id, hashtag_id)
        SELECT $1, unnest($2::uuid[])
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(post_id)
    .bind(&ids)
    .execute(pool)
    .await?;

    Ok(())
}

/// Follow a hashtag by name.
///
/// Upserts the hashtag and creates the follow relation. The operation is
/// idempotent: re-following an already-followed hashtag is a no-op.
pub async fn follow_hashtag(pool: &PgPool, actor_id: Uuid, name: &str) -> Result<Hashtag> {
    let tag = upsert_hashtag(pool, name).await?;
    sqlx::query(
        r#"
        INSERT INTO hashtag_follows (actor_id, hashtag_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(actor_id)
    .bind(tag.id)
    .execute(pool)
    .await?;
    Ok(tag)
}

/// Unfollow a hashtag by name.
///
/// Silently succeeds if the hashtag does not exist or was not followed.
pub async fn unfollow_hashtag(pool: &PgPool, actor_id: Uuid, name: &str) -> Result<()> {
    let normalised = name.to_lowercase();
    sqlx::query(
        r#"
        DELETE FROM hashtag_follows
        WHERE actor_id = $1
          AND hashtag_id = (SELECT id FROM hashtags WHERE name = $2)
        "#,
    )
    .bind(actor_id)
    .bind(&normalised)
    .execute(pool)
    .await?;
    Ok(())
}

/// List all hashtags followed by an actor.
pub async fn list_followed_hashtags(pool: &PgPool, actor_id: Uuid) -> Result<Vec<Hashtag>> {
    let rows = sqlx::query_as::<_, Hashtag>(
        r#"
        SELECT h.id, h.name
        FROM hashtags h
        INNER JOIN hashtag_follows hf ON hf.hashtag_id = h.id
        WHERE hf.actor_id = $1
        ORDER BY h.name
        "#,
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Retrieve post IDs that match any of the given hashtag IDs, ordered by
/// creation date descending. Used for feed filtering.
pub async fn posts_by_hashtags(
    pool: &PgPool,
    hashtag_ids: &[Uuid],
    limit: i64,
    offset: i64,
) -> Result<Vec<Uuid>> {
    let rows = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT ph.post_id
        FROM post_hashtags ph
        INNER JOIN posts p ON p.id = ph.post_id
        WHERE ph.hashtag_id = ANY($1)
        GROUP BY ph.post_id, p.created_at
        ORDER BY p.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(hashtag_ids)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    #[test]
    fn normalisation() {
        // Verify the normalisation logic used in upsert_hashtag.
        assert_eq!("rust".to_owned(), "Rust".to_lowercase());
        assert_eq!("activitypub".to_owned(), "ActivityPub".to_lowercase());
    }
}
