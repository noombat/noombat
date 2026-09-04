// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Every image the product stores can carry a description.
//!
//! `alt_text` existed with neither a reader nor a writer, so no upload
//! could describe an image and nothing rendered a description. These
//! assertions cover the write side and the constraint that keeps a
//! description attached to something it actually describes.

use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn author(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('individual', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/author-{id}"))
    .bind(format!("author{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("insert author")
}

/// The description belongs to the upload, so replacing the picture
/// replaces the description with it. Keeping the old text would caption
/// the new image with the previous one's words.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn replacing_an_avatar_replaces_its_description(pool: PgPool) {
    let actor = author(&pool).await;

    let insert = |key: &'static str, alt: Option<&'static str>| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO media_attachments \
                 (actor_id, media_type, object_key, backend, purpose, url, alt_text) \
                 VALUES ($1, 'image/png', $2, 'local', 'avatar', $3, $4) \
                 ON CONFLICT (actor_id, purpose) WHERE purpose IN ('avatar', 'header') \
                 DO UPDATE SET object_key = EXCLUDED.object_key, \
                               url = EXCLUDED.url, \
                               alt_text = EXCLUDED.alt_text",
            )
            .bind(actor)
            .bind(key)
            .bind(format!("https://{DOMAIN}/media/{key}"))
            .bind(alt)
            .execute(&pool)
            .await
            .expect("upsert avatar");
        }
    };

    insert("first", Some("Standing by a river")).await;
    insert("second", None).await;

    let alt: Option<String> = sqlx::query_scalar(
        "SELECT alt_text FROM media_attachments WHERE actor_id = $1 AND purpose = 'avatar'",
    )
    .bind(actor)
    .fetch_one(&pool)
    .await
    .expect("read back");

    assert_eq!(alt, None, "the previous description must not survive");
}

/// A description with no image to describe is refused. It means the
/// write path dropped the URL, or the column was set on a post that
/// never had a picture, and either way the text describes nothing.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn alt_text_without_an_image_is_refused(pool: PgPool) {
    let actor = author(&pool).await;

    let refused = sqlx::query(
        "INSERT INTO posts (actor_id, ap_id, content_html, ap_object, featured_image_alt) \
         VALUES ($1, $2, '<p>hi</p>', '{}'::jsonb, 'A bridge at dusk')",
    )
    .bind(actor)
    .bind(format!("https://{DOMAIN}/posts/{}", Uuid::new_v4()))
    .execute(&pool)
    .await;

    assert!(refused.is_err(), "alt text with no image should be refused");
}

/// The same row with an image is accepted, so the constraint refuses the
/// broken shape rather than the feature.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn alt_text_with_an_image_is_stored(pool: PgPool) {
    let actor = author(&pool).await;

    sqlx::query(
        "INSERT INTO posts \
         (actor_id, ap_id, content_html, ap_object, featured_image_url, featured_image_alt) \
         VALUES ($1, $2, '<p>hi</p>', '{}'::jsonb, $3, 'A bridge at dusk')",
    )
    .bind(actor)
    .bind(format!("https://{DOMAIN}/posts/{}", Uuid::new_v4()))
    .bind(format!("https://{DOMAIN}/media/x"))
    .execute(&pool)
    .await
    .expect("insert with an image");

    let alt: Option<String> =
        sqlx::query_scalar("SELECT featured_image_alt FROM posts WHERE actor_id = $1")
            .bind(actor)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(alt.as_deref(), Some("A bridge at dusk"));
}
