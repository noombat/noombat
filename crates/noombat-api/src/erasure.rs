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

    // And once more, for the mailbox. `tombstone_actor` clears
    // `chatmail_addr`, so after it runs nothing knows which maildir
    // belonged to this account. Recorded here rather than deleted here:
    // the sidecar is a separate process that can be down, and an
    // erasure that fails because of that must be retryable rather than
    // lost. The mailbox is part of what erasure removes: leaving
    // it is the erasure failing silently.
    let chatmail_addr: Option<String> =
        sqlx::query_scalar("SELECT chatmail_addr FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
            .flatten();

    if let Some(ref address) = chatmail_addr
        && let Err(error) = crate::chatmail_ops::enqueue_delete(pool, actor_id, address).await
    {
        error!(%error, %actor_id, "erasure could not record the maildir deletion it owes");
    }

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

    crate::search_sync::remove_from_index_durably(pool, search, "profiles", &actor_id.to_string())
        .await;

    // The rows are gone from the database by now, but the search
    // documents outlive them and are full text: leaving them is an
    // erasure that leaves the writing searchable by its contents.
    //
    // Withdrawn under the same key `index_post` inserts under, the
    // post's primary key. The two must agree; changing one without the
    // other leaves erased writing searchable by its full text.
    for post_id in &indexed_posts {
        crate::search_sync::remove_from_index_durably(pool, search, "posts", &post_id.to_string())
            .await;
    }

    // `index_job` keys on the posting's primary key, so this matches.
    for job_id in &indexed_jobs {
        crate::search_sync::remove_from_index_durably(pool, search, "jobs", &job_id.to_string())
            .await;
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

/// How long a tombstoned actor row is kept before it is hard-deleted.
///
/// A backstop, not a schedule. The row goes as soon as the Chatmail work
/// it owes is settled; this is the outer bound for the case where that
/// never settles, so a sidecar that is permanently gone does not keep
/// every erased row alive forever.
const TOMBSTONE_RETENTION_DAYS: i64 = 30;

/// Hard-delete tombstoned actors whose retention window has closed.
///
/// Two conditions, and the first is the one that matters:
/// **`fetch_signing_credentials` uses `fetch_one`**, so deleting the row
/// while a `Delete` is still queued for it makes that activity
/// permanently unsignable, and the peers that never received it keep
/// their copy forever. The queue has to be empty first.
///
/// The second is the Chatmail work: the row carries the actor id the
/// operations are keyed on, so purging early loses the link between a
/// failed maildir deletion and the account it belonged to.
///
/// Both are subject to the 30-day backstop, because either could stay
/// unsatisfied indefinitely and an erasure that never completes is the
/// defect this path exists to close.
pub async fn purge_retained(pool: &PgPool) -> u64 {
    let due = sqlx::query_scalar::<_, Uuid>(
        "SELECT a.id FROM actors a \
         WHERE a.erased_at IS NOT NULL \
           AND ( \
             ( NOT EXISTS (SELECT 1 FROM delivery_queue q WHERE q.actor_id = a.id) \
               AND NOT EXISTS ( \
                 SELECT 1 FROM chatmail_operations o \
                 WHERE o.actor_id = a.id AND o.state = 'pending' \
               ) \
             ) \
             OR a.erased_at < now() - ($1 || ' days')::interval \
           ) \
         LIMIT 200",
    )
    .bind(TOMBSTONE_RETENTION_DAYS.to_string())
    .fetch_all(pool)
    .await;

    let due = match due {
        Ok(ids) => ids,
        Err(e) => {
            error!("could not list actors due for purge: {e}");
            return 0;
        }
    };

    let mut purged = 0;
    for actor_id in due {
        match noombat_identity::repo::purge_tombstoned_actor(pool, actor_id).await {
            Ok(()) => {
                // `tombstoned_actors` keeps the ap_id, so federation
                // requests still get 410 rather than 404.
                info!(%actor_id, "purged a tombstoned actor row");
                purged += 1;
            }
            Err(e) => warn!(%actor_id, "failed to purge, will retry next sweep: {e}"),
        }
    }

    purged
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

        // The second clock, in the same worker: the grace period,
        // then the tombstone standing until its work is settled.
        // Not one long timer, because the second period ends on a
        // condition and the days are only a backstop.
        let purged = purge_retained(&pool).await;
        if purged > 0 {
            info!(purged, "tombstone retention sweep complete");
        }

        tokio::time::sleep(interval).await;
    }
}
