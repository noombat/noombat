// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Images attached to Notes and Articles, and the blur a sensitive one
//! is hidden behind.
//!
//! Before this, `purpose` allowed `'post'` and nothing ever wrote it: the
//! only upload in the product was the avatar. These assertions cover the
//! upload-then-claim sequence, which is where an image can go missing or
//! be claimed by the wrong post.

use noombat_api::media::{MediaStore, blurhash_placeholder, process_attachment, process_avatar};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn actor(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('individual', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{name}-{id}"))
    .bind(format!("{name}{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("insert actor")
}

async fn upload(pool: &PgPool, owner: Uuid, alt: Option<&str>) -> Uuid {
    let key = Uuid::new_v4().simple().to_string();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO media_attachments \
         (actor_id, media_type, object_key, backend, purpose, url, alt_text, blurhash) \
         VALUES ($1, 'image/png', $2, 'local', 'post', $3, $4, 'LEHV6nWB2yk8pyo0adR*') \
         RETURNING id",
    )
    .bind(owner)
    .bind(&key)
    .bind(format!("https://{DOMAIN}/media/{key}"))
    .bind(alt)
    .fetch_one(pool)
    .await
    .expect("insert attachment")
}

async fn post(pool: &PgPool, author: Uuid, sensitive: bool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO posts (actor_id, ap_id, content_html, ap_object, sensitive) \
         VALUES ($1, $2, '<p>hi</p>', '{}'::jsonb, $3) RETURNING id",
    )
    .bind(author)
    .bind(format!("https://{DOMAIN}/posts/{}", Uuid::new_v4()))
    .bind(sensitive)
    .fetch_one(pool)
    .await
    .expect("insert post")
}

/// An upload starts unattached and stays that way until a post claims
/// it. That window is what lets the compose page show an image and
/// collect a description before the post exists.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_upload_starts_unattached(pool: PgPool) {
    let author = actor(&pool, "author").await;
    let image = upload(&pool, author, Some("A bridge")).await;

    let post_id: Option<Uuid> =
        sqlx::query_scalar("SELECT post_id FROM media_attachments WHERE id = $1")
            .bind(image)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(post_id, None);

    // And it is findable as unattached, which is what the sweep for
    // abandoned uploads reads.
    let unattached: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM media_attachments \
         WHERE purpose = 'post' AND post_id IS NULL AND actor_id = $1",
    )
    .bind(author)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(unattached, 1);
}

/// A claim points the row at the post, and a second claim does nothing.
/// Without the `post_id IS NULL` guard, an id replayed against another
/// post would move somebody's image from one post to another after
/// publication.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_image_cannot_be_claimed_twice(pool: PgPool) {
    let author = actor(&pool, "author").await;
    let image = upload(&pool, author, None).await;
    let first = post(&pool, author, false).await;
    let second = post(&pool, author, false).await;

    let claim = |post_id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "UPDATE media_attachments SET post_id = $1 \
                 WHERE id = $2 AND actor_id = $3 AND purpose = 'post' AND post_id IS NULL",
            )
            .bind(post_id)
            .bind(image)
            .bind(author)
            .execute(&pool)
            .await
            .expect("claim")
            .rows_affected()
        }
    };

    assert_eq!(claim(first).await, 1);
    assert_eq!(claim(second).await, 0, "a second claim must do nothing");

    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT post_id FROM media_attachments WHERE id = $1")
            .bind(image)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(owner, Some(first));
}

/// Somebody else's upload attaches nothing. The claim is scoped by
/// `actor_id`, so an id copied from another post's document cannot be
/// used to hang that image on a post of one's own.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn another_authors_upload_cannot_be_claimed(pool: PgPool) {
    let mine = actor(&pool, "mine").await;
    let theirs = actor(&pool, "theirs").await;
    let image = upload(&pool, theirs, None).await;
    let my_post = post(&pool, mine, false).await;

    let claimed = sqlx::query(
        "UPDATE media_attachments SET post_id = $1 \
         WHERE id = $2 AND actor_id = $3 AND purpose = 'post' AND post_id IS NULL",
    )
    .bind(my_post)
    .bind(image)
    .bind(mine)
    .execute(&pool)
    .await
    .expect("attempt claim")
    .rows_affected();

    assert_eq!(claimed, 0);
}

/// The flag defaults to off. A default that hid every image would train
/// readers to click through without reading the warning, which is what
/// the flag exists to avoid.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_post_is_not_sensitive_unless_said(pool: PgPool) {
    let author = actor(&pool, "author").await;
    let id = post(&pool, author, false).await;

    let sensitive: bool = sqlx::query_scalar("SELECT sensitive FROM posts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert!(!sensitive);
}

/// The reader's preference defaults to blurring. Somebody who has said
/// nothing gets the option that shows less, and the column is what a
/// signed-in reader changes.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_blur_preference_defaults_to_on(pool: PgPool) {
    let reader = actor(&pool, "reader").await;

    let blur: bool = sqlx::query_scalar("SELECT blur_sensitive_media FROM actors WHERE id = $1")
        .bind(reader)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert!(blur);

    sqlx::query("UPDATE actors SET blur_sensitive_media = FALSE WHERE id = $1")
        .bind(reader)
        .execute(&pool)
        .await
        .expect("turn it off");

    let blur: bool = sqlx::query_scalar("SELECT blur_sensitive_media FROM actors WHERE id = $1")
        .bind(reader)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert!(!blur, "the reader's choice has to stick");
}

/// Erasure takes the attachments with it. The rows are keyed on the
/// actor, so a post's images must not outlive the account that made
/// them.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn deleting_the_author_removes_their_attachments(pool: PgPool) {
    let author = actor(&pool, "author").await;
    let image = upload(&pool, author, Some("A bridge")).await;
    let id = post(&pool, author, true).await;

    sqlx::query("UPDATE media_attachments SET post_id = $1 WHERE id = $2")
        .bind(id)
        .bind(image)
        .execute(&pool)
        .await
        .expect("claim");

    sqlx::query("DELETE FROM actors WHERE id = $1")
        .bind(author)
        .execute(&pool)
        .await
        .expect("delete actor");

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM media_attachments WHERE id = $1")
        .bind(image)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(left, 0);
}

/// A small PNG with two colours, so the hash it produces is not the flat
/// one a single-colour image gives.
fn sample_png() -> Vec<u8> {
    let mut image = image::RgbaImage::new(64, 48);
    for (x, _y, pixel) in image.enumerate_pixels_mut() {
        *pixel = if x < 32 {
            image::Rgba([200, 40, 40, 255])
        } else {
            image::Rgba([20, 60, 180, 255])
        };
    }
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgba8(image)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .expect("encode sample");
    bytes
}

/// The hash is computed for a post attachment and not for an avatar.
/// A profile picture is never shown blurred, which is also what Mastodon
/// does, so computing one would be a value with no reader.
#[test]
fn only_an_attachment_gets_a_hash() {
    let png = sample_png();

    let attachment = process_attachment(&png).expect("process attachment");
    let hash = attachment.blurhash.expect("attachment carries a hash");
    assert!(!hash.is_empty(), "the hash should not be empty");

    let avatar = process_avatar(&png).expect("process avatar");
    assert_eq!(avatar.blurhash, None);
}

/// The stored hash decodes to the placeholder a reader is shown. A hash
/// that round-trips to nothing leaves a sensitive image behind a blank
/// panel, which tells the reader neither what is there nor that
/// anything is.
#[test]
fn a_hash_decodes_to_an_inline_placeholder() {
    let hash = process_attachment(&sample_png())
        .expect("process")
        .blurhash
        .expect("hash");

    let placeholder = blurhash_placeholder(&hash).expect("decode");
    assert!(placeholder.starts_with("data:image/png;base64,"));
    // Long enough to be a real image rather than an empty PNG header.
    assert!(placeholder.len() > 200, "got {} bytes", placeholder.len());
}

/// An absent or malformed hash is a plain panel, not a broken image.
/// Rows predate this code and peers send what they like, so failing to
/// decode one is ordinary rather than exceptional.
#[test]
fn an_undecodable_hash_yields_no_placeholder() {
    assert_eq!(blurhash_placeholder(""), None);
    assert_eq!(blurhash_placeholder("not-a-blurhash"), None);
}

/// An avatar and a header belong to the actor, never to a post, and the
/// constraint is what keeps a stray write from pointing one at a post.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_avatar_cannot_belong_to_a_post(pool: PgPool) {
    let actor = actor(&pool, "author").await;
    let post = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO posts (actor_id, ap_id, content_html, ap_object) \
         VALUES ($1, $2, '<p>hi</p>', '{}'::jsonb) RETURNING id",
    )
    .bind(actor)
    .bind(format!("https://{DOMAIN}/posts/{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("insert post");

    let refused = sqlx::query(
        "INSERT INTO media_attachments \
         (actor_id, post_id, media_type, object_key, backend, purpose, url) \
         VALUES ($1, $2, 'image/png', 'k', 'local', 'avatar', 'https://example/x')",
    )
    .bind(actor)
    .bind(post)
    .execute(&pool)
    .await;

    assert!(refused.is_err(), "an avatar must not carry a post_id");
}

/// The sweep frees an upload nobody posted, and leaves a claimed one
/// alone. Without it the unattached index would have no reader, and the
/// bytes behind an abandoned compose page would be kept for ever.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_frees_only_unclaimed_uploads(pool: PgPool) {
    let root = tempfile::tempdir().expect("temp dir");
    let media = MediaStore::local(root.path()).expect("store");

    let author = actor(&pool, "author").await;
    let abandoned = upload(&pool, author, None).await;
    let kept = upload(&pool, author, None).await;
    let recent = upload(&pool, author, None).await;

    let id = post(&pool, author, false).await;
    sqlx::query("UPDATE media_attachments SET post_id = $1 WHERE id = $2")
        .bind(id)
        .bind(kept)
        .execute(&pool)
        .await
        .expect("claim");

    // Both are unclaimed; only one is old enough to sweep, which is what
    // keeps the window from deleting an image still being written around.
    sqlx::query(
        "UPDATE media_attachments SET created_at = now() - interval '72 hours' WHERE id = $1",
    )
    .bind(abandoned)
    .execute(&pool)
    .await
    .expect("age the row");

    // Objects to remove, so the sweep is not deleting rows that point at
    // nothing: a store that answers "missing" would let it pass either way.
    for key in object_keys(&pool, &[abandoned, kept, recent]).await {
        media.put(&key, b"bytes").await.expect("write object");
    }

    let (_, _, swept) = noombat_api::housekeeping::sweep(&pool, &media).await;
    assert_eq!(swept, 1, "only the aged, unclaimed upload should go");

    let left: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM media_attachments ORDER BY created_at")
            .fetch_all(&pool)
            .await
            .expect("read back");
    assert!(!left.contains(&abandoned));
    assert!(left.contains(&kept), "a posted image must survive");
    assert!(left.contains(&recent), "a fresh upload must survive");
}

/// The object keys behind a set of rows.
async fn object_keys(pool: &PgPool, ids: &[Uuid]) -> Vec<String> {
    sqlx::query_scalar("SELECT object_key FROM media_attachments WHERE id = ANY($1)")
        .bind(ids)
        .fetch_all(pool)
        .await
        .expect("object keys")
}

/// Deleting a post takes its images off the disk, not just out of the
/// database. `media_attachments.post_id` cascades, so the rows that name
/// the objects go with the post: reading the keys first is the only
/// chance to free the bytes.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn deleting_a_post_frees_its_images(pool: PgPool) {
    let root = tempfile::tempdir().expect("temp dir");
    let media = MediaStore::local(root.path()).expect("store");

    let author = actor(&pool, "author").await;
    let image = upload(&pool, author, Some("A bridge")).await;
    let id = post(&pool, author, false).await;
    sqlx::query("UPDATE media_attachments SET post_id = $1 WHERE id = $2")
        .bind(id)
        .bind(image)
        .execute(&pool)
        .await
        .expect("claim");

    let keys = object_keys(&pool, &[image]).await;
    for key in &keys {
        media.put(key, b"bytes").await.expect("write object");
    }

    // The order the deletion path uses: keys, then the post, then the
    // objects. Reading them afterwards would find nothing.
    let collected = noombat_api::media::post_object_keys(&pool, id).await;
    assert_eq!(collected, keys, "the keys must be read before the delete");

    sqlx::query("DELETE FROM posts WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("delete post");
    noombat_api::media::purge_objects(&media, &collected).await;

    for key in &keys {
        assert!(
            media.get(key).await.is_err(),
            "a deleted post's image must not survive on disk"
        );
    }
}

/// An avatar can be taken down, not only replaced. The row, the object
/// and the actor's own pointer all have to go, or the picture keeps
/// being served from somewhere.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_avatar_can_be_removed(pool: PgPool) {
    let root = tempfile::tempdir().expect("temp dir");
    let media = MediaStore::local(root.path()).expect("store");

    let owner = actor(&pool, "owner").await;
    let key = Uuid::new_v4().simple().to_string();
    media.put(&key, b"bytes").await.expect("write object");
    sqlx::query(
        "INSERT INTO media_attachments \
         (actor_id, media_type, object_key, backend, purpose, url) \
         VALUES ($1, 'image/png', $2, 'local', 'avatar', $3)",
    )
    .bind(owner)
    .bind(&key)
    .bind(format!("https://{DOMAIN}/media/{key}"))
    .execute(&pool)
    .await
    .expect("insert avatar");
    sqlx::query("UPDATE actors SET avatar_url = $1 WHERE id = $2")
        .bind(format!("https://{DOMAIN}/media/{key}"))
        .bind(owner)
        .execute(&pool)
        .await
        .expect("point the actor at it");

    // What the route does, in its order: clear the pointer, drop the
    // row, then remove the object.
    sqlx::query("UPDATE actors SET avatar_url = NULL WHERE id = $1")
        .bind(owner)
        .execute(&pool)
        .await
        .expect("clear");
    sqlx::query("DELETE FROM media_attachments WHERE actor_id = $1 AND purpose = 'avatar'")
        .bind(owner)
        .execute(&pool)
        .await
        .expect("drop row");
    media.delete(&key).await.expect("remove object");

    let url: Option<String> = sqlx::query_scalar("SELECT avatar_url FROM actors WHERE id = $1")
        .bind(owner)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert_eq!(url, None);

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM media_attachments WHERE actor_id = $1 AND purpose = 'avatar'",
    )
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(rows, 0);
    assert!(media.get(&key).await.is_err(), "the object must be gone");
}
