// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Whether a post from another instance may enter this one's search
//! index and trending counts.
//!
//! Three conditions, all required, and separate because they answer to
//! different people: the **operator** turns the feature on, the
//! **author** consents through their own `indexable`, and the **post**
//! must be public and not something this instance took on a relay's
//! word. An operator switching it on does not overrule an author who
//! said no.
//!
//! Ingestion lives in this crate and the queue is a table, so the
//! enqueue is here; the worker that drains it is in `noombat-api`,
//! where the search backend is.

use noombat_core::error::Result;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Whether the operator has turned remote indexing on.
///
/// A missing settings row reads as off, like every other setting whose
/// absence this instance has to interpret.
pub async fn remote_indexing_enabled(pool: &PgPool) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT index_remote_posts FROM instance_settings LIMIT 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// Queue a freshly ingested remote post for indexing, if all three
/// conditions hold.
///
/// Silent when they do not: not indexing is the ordinary case, and a
/// line per declining author would be noise proportional to the corpus.
pub async fn enqueue_if_indexable(pool: &PgPool, post_id: Uuid) -> Result<()> {
    if !remote_indexing_enabled(pool).await {
        return Ok(());
    }

    // One query for the three per-post facts, because a post that fails
    // any of them costs nothing more to reject.
    let row = sqlx::query_as::<_, (String, String, String, Option<String>, bool, bool, bool)>(
        r#"SELECT p.ap_id,
                  p.content_html,
                  p.post_type,
                  p.title,
                  p.visibility = 'public'   AS is_public,
                  p.relayed_unverified,
                  COALESCE((a.actor_privacy->>'indexable')::boolean, FALSE) AS indexable
           FROM posts p
           JOIN actors a ON a.id = p.actor_id
           WHERE p.id = $1 AND a.is_local = FALSE"#,
    )
    .bind(post_id)
    .fetch_optional(pool)
    .await?;

    let Some((ap_id, content_html, post_type, title, is_public, relayed_unverified, indexable)) =
        row
    else {
        return Ok(());
    };

    // `indexable` is the author's own answer, read off their actor
    // document at ingestion, where absent was taken as withheld.
    //
    // `relayed_unverified` is the relay guard: a relay's word is not the
    // author's, and search amplifies better than trending because a
    // query is aimed.
    if !indexable || !is_public || relayed_unverified {
        return Ok(());
    }

    let actor_id = sqlx::query_scalar::<_, Uuid>("SELECT actor_id FROM posts WHERE id = $1")
        .bind(post_id)
        .fetch_one(pool)
        .await?;

    let document = json!({
        "id": post_id.to_string(),
        "ap_id": ap_id,
        "content": content_html,
        "actor_id": actor_id.to_string(),
        "visibility": "public",
        "post_type": post_type,
        "title": title,
        "is_local": false,
    });

    // Written to the queue rather than sent: this crate has no search
    // backend, and a remote post that fails to index is missing from
    // search with nobody to notice.
    crate::search_queue::enqueue_upsert(pool, "posts", &post_id.to_string(), &document).await?;

    Ok(())
}

/// Queue the removal of every indexed post by a remote actor.
///
/// The duty that taking a copy creates: the author's instance says the
/// account is gone, and a removal lost here leaves the full text
/// searchable after the row itself is deleted.
pub async fn enqueue_removals_for_actor(pool: &PgPool, actor_id: Uuid) -> Result<()> {
    let post_ids = sqlx::query_scalar::<_, Uuid>("SELECT id FROM posts WHERE actor_id = $1")
        .bind(actor_id)
        .fetch_all(pool)
        .await?;

    for post_id in post_ids {
        crate::search_queue::enqueue_removal(pool, "posts", &post_id.to_string()).await?;
    }

    crate::search_queue::enqueue_removal(pool, "profiles", &actor_id.to_string()).await?;

    Ok(())
}
