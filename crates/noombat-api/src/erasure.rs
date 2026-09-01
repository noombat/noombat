// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Account erasure: the grace period, and the worker that ends it.
//!
//! `POST /api/v1/me/delete` sets `actors.deletion_requested_at` and
//! tells the user their account will be erased in thirty days. Until
//! this module existed nothing read that column except the two places
//! that decide what to show the user, so the grace period never ended
//! and the erasure never happened. A user exercising their right to
//! erasure was shown a pending state indefinitely while their posts,
//! career history and Chatmail address stayed where they were.
//!
//! [`erase_actor`] is the sequence, and it is shared with the
//! administrative `DELETE /users/{username}` rather than reimplemented,
//! because one step of it is easy to get wrong in a way nothing would
//! notice: the follower inboxes have to be collected *before*
//! `tombstone_actor` runs, since tombstoning deletes the follow rows
//! that identify them. Erase first and the Delete activity goes to
//! nobody, leaving remote instances holding a copy forever. Two callers
//! and one copy of that ordering is the point of this module.

use std::sync::Arc;
use std::time::Duration;

use noombat_core::actor::Actor;
use noombat_core::error::Result;
use noombat_core::extension::SearchBackend;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Erase one actor: notify, tombstone, and drop from the search index.
///
/// Returns the pre-tombstone snapshot, which is what the outbound
/// `Delete` is built from; after tombstoning there is no longer enough
/// left of the actor to describe it.
pub async fn erase_actor(
    pool: &PgPool,
    search: &Option<Arc<dyn SearchBackend>>,
    media: &crate::media::MediaStore,
    actor_id: Uuid,
) -> Result<Actor> {
    // Before tombstoning: tombstone_actor deletes the follow rows these
    // come from.
    let inboxes = noombat_identity::repo::get_follower_inboxes(pool, actor_id)
        .await
        .unwrap_or_default();

    // Likewise, and for the same reason: tombstoning deletes the post
    // rows, and afterwards there is nothing left to say which documents
    // to withdraw. Keyed on the primary key, matching `index_post`.
    let indexed_posts: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM posts WHERE actor_id = $1")
        .bind(actor_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    // Same reason again: tombstoning deletes the postings, so the ids
    // have to be taken while they still exist.
    let indexed_jobs: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM job_postings WHERE actor_id = $1")
            .bind(actor_id)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    // And again, for the bytes rather than the rows. `tombstone_actor`
    // deletes the media_attachments rows, and afterwards nothing knows
    // which objects they named: the files would stay on disk, or in a
    // bucket, unreferenced and permanent. An erasure that leaves the
    // pictures behind is the failure this whole path exists to prevent.
    let media_keys: Vec<String> =
        sqlx::query_scalar("SELECT object_key FROM media_attachments WHERE actor_id = $1")
            .bind(actor_id)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let pre_tombstone = noombat_identity::repo::tombstone_actor(pool, actor_id).await?;

    // After the rows are gone, so nothing can serve an object whose
    // bytes have already been removed.
    for key in &media_keys {
        if let Err(error) = media.delete(key).await {
            // Reported, never swallowed: this is the state where the
            // database says erased and the disk disagrees.
            error!(%error, %actor_id, object_key = %key, "erasure could not remove a media object");
        }
    }

    // The request has been fulfilled, so retire it. `tombstone_actor`
    // leaves `deletion_requested_at` set, and the sweep selects on that
    // column, so without this the same account is picked up on every
    // pass: erased again hourly, and a fresh `Delete` sent to every
    // follower's inbox each time.
    //
    // A crash between the tombstone and this update leaves the flag
    // set and costs one redundant sweep. That is survivable, since
    // erasing an erased account deletes nothing and a `Delete` for an
    // actor that is already gone is ignored by receivers.
    sqlx::query("UPDATE actors SET deletion_requested_at = NULL WHERE id = $1")
        .bind(actor_id)
        .execute(pool)
        .await?;

    noombat_federation::delete::broadcast_delete(pool, &pre_tombstone, &inboxes).await;

    crate::search_sync::remove_from_index(search, "profiles", &actor_id.to_string());

    // The rows are gone from the database by now, but the search
    // documents outlive them and are full text: leaving them is an
    // erasure that leaves the writing searchable by its contents.
    //
    // Withdrawn under the same key `index_post` inserts under, the
    // post's primary key. The two must agree; changing one without the
    // other leaves erased writing searchable by its full text.
    for post_id in &indexed_posts {
        crate::search_sync::remove_from_index(search, "posts", &post_id.to_string());
    }

    // `index_job` keys on the posting's primary key, so this matches.
    for job_id in &indexed_jobs {
        crate::search_sync::remove_from_index(search, "jobs", &job_id.to_string());
    }

    Ok(pre_tombstone)
}

/// Actors whose grace period has elapsed.
async fn due_for_erasure(pool: &PgPool, grace_days: i32) -> Result<Vec<Uuid>> {
    let ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM actors \
         WHERE is_local = TRUE \
           AND deletion_requested_at IS NOT NULL \
           AND deletion_requested_at < now() - ($1 || ' days')::interval",
    )
    .bind(grace_days.to_string())
    .fetch_all(pool)
    .await?;

    Ok(ids)
}

/// Erase every account whose grace period has elapsed, once.
///
/// Returns how many were erased. One failure does not stop the rest:
/// an account that cannot be erased now is still due next time round,
/// and holding up every other user's erasure behind it would be the
/// wrong trade.
pub async fn sweep(
    pool: &PgPool,
    search: &Option<Arc<dyn SearchBackend>>,
    media: &crate::media::MediaStore,
    grace_days: i32,
) -> u64 {
    let due = match due_for_erasure(pool, grace_days).await {
        Ok(due) => due,
        Err(e) => {
            error!("could not list accounts due for erasure: {e}");
            return 0;
        }
    };

    let mut erased = 0;
    for actor_id in due {
        match erase_actor(pool, search, media, actor_id).await {
            Ok(_) => {
                // Deliberately no username or address in the log line:
                // this is the record of an erasure, and it should not
                // reintroduce what was erased.
                info!(%actor_id, "erased an account whose grace period elapsed");
                erased += 1;
            }
            Err(e) => warn!(%actor_id, "failed to erase, will retry next sweep: {e}"),
        }
    }

    erased
}

/// Run [`sweep`] on an interval, forever.
pub async fn run_worker(
    pool: PgPool,
    search: Option<Arc<dyn SearchBackend>>,
    media: crate::media::MediaStore,
    grace_days: i32,
    interval: Duration,
) {
    info!(
        interval_secs = interval.as_secs(),
        grace_days, "account erasure worker started"
    );

    loop {
        let erased = sweep(&pool, &search, &media, grace_days).await;
        if erased > 0 {
            info!(erased, "erasure sweep complete");
        }
        tokio::time::sleep(interval).await;
    }
}
