// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Expired email challenges, analytics rows past their retention, and
//! uploads no post ever claimed.
//!
//! One worker rather than three: they run on the same cadence, and a
//! second `tokio::spawn` for one `DELETE` is more machinery than the
//! work justifies.

use std::time::Duration;

use sqlx::PgPool;
use tracing::{info, warn};

use crate::media::MediaStore;

/// How long an uploaded image may wait for a post to claim it.
///
/// Long enough to write an article around the picture and come back to
/// it, and short enough that an abandoned compose page does not keep
/// bytes for ever. The window is generous on purpose: deleting an image
/// somebody is still writing around loses their work, where keeping one
/// an extra day costs a few hundred kilobytes.
const UNATTACHED_UPLOAD_HOURS: i64 = 48;

/// Delete uploads that were never attached to a post.
///
/// The object is removed before the row, because the row is what names
/// the object: dropping it first would leave bytes nothing can find.
/// A storage failure leaves the row in place, so the next pass tries
/// again rather than orphaning the object silently.
async fn purge_unattached_uploads(pool: &PgPool, media: &MediaStore) -> u64 {
    let stale: Vec<(uuid::Uuid, String)> = match sqlx::query_as(
        "SELECT id, object_key FROM media_attachments \
         WHERE purpose = 'post' AND post_id IS NULL \
           AND created_at < now() - make_interval(hours => $1)",
    )
    .bind(UNATTACHED_UPLOAD_HOURS as i32)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "unattached uploads could not be listed");
            return 0;
        }
    };

    let mut removed = 0;
    for (id, object_key) in stale {
        if let Err(e) = media.delete(&object_key).await {
            warn!(error = %e, %object_key, "an unattached upload's object could not be removed");
            continue;
        }
        match sqlx::query("DELETE FROM media_attachments WHERE id = $1 AND post_id IS NULL")
            .bind(id)
            .execute(pool)
            .await
        {
            Ok(result) => removed += result.rows_affected(),
            Err(e) => warn!(error = %e, %id, "an unattached upload's row could not be removed"),
        }
    }
    removed
}

/// The retention period the instance advertises.
///
/// Read from `instance_settings` on every pass rather than captured at
/// boot, so an administrator lowering it does not have to restart the
/// server for the change to take effect. A missing row leaves the
/// default the column carries.
async fn analytics_retention_days(pool: &PgPool) -> i32 {
    sqlx::query_scalar::<_, i32>("SELECT analytics_retention_days FROM instance_settings LIMIT 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(90)
}

/// Run every sweep once. Returns `(challenges, analytics rows, uploads)`.
///
/// The analytics half builds its own backend from the pool: retention is
/// a property of the store, so `purge_expired` is inherent to the
/// Postgres backend rather than part of the trait every consumer sees.
pub async fn sweep(pool: &PgPool, media: &MediaStore) -> (u64, u64, u64) {
    let challenges = match noombat_identity::email::purge_expired(pool).await {
        Ok(n) => n,
        Err(e) => {
            warn!(error = %e, "expired email challenges could not be purged");
            0
        }
    };

    let retention = analytics_retention_days(pool).await;
    let rows = match crate::analytics::PgAnalyticsBackend::new(pool.clone())
        .purge_expired(retention)
        .await
    {
        Ok(n) => n,
        Err(e) => {
            warn!(error = %e, "expired analytics rows could not be purged");
            0
        }
    };

    let uploads = purge_unattached_uploads(pool, media).await;

    (challenges, rows, uploads)
}

/// Sweep on a fixed interval.
pub async fn run_worker(pool: PgPool, media: MediaStore, interval: Duration) {
    info!(
        interval_secs = interval.as_secs(),
        "housekeeping worker started"
    );

    loop {
        let (challenges, rows, uploads) = sweep(&pool, &media).await;
        if challenges > 0 || rows > 0 || uploads > 0 {
            info!(
                challenges,
                analytics_rows = rows,
                unattached_uploads = uploads,
                "housekeeping sweep complete"
            );
        }
        tokio::time::sleep(interval).await;
    }
}
