// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Fetching the images a remote post declared.
//!
//! A peer's document names its pictures by URL. Rendering those URLs
//! directly would make every reader's browser connect to the other
//! instance, handing it a record of who read what, so the bytes are
//! fetched here and served from this instance like any other media. That
//! is the same rule the upload path follows, applied to somebody else's
//! image.
//!
//! Fetching is queued rather than done during delivery. The inbox holds
//! an open request from a peer, and waiting on a third instance's media
//! server there turns their outage into failed delivery of an activity
//! that arrived perfectly well.
//!
//! Nothing a peer sends is trusted, including the bytes: the URL goes
//! through the same guard as every federated fetch, the body is bounded
//! before it is buffered, and the image is decoded and re-encoded by the
//! same pipeline an upload goes through, which is what decides the
//! format from the content and strips the metadata.

use std::time::Duration;

use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::media::{
    MAX_UPLOAD_BYTES, MediaStore, ProcessedImage, new_object_key, process_attachment,
};

/// How many times a fetch is retried before it is given up on.
const MAX_ATTEMPTS: i32 = 6;

/// How many fetches one pass performs.
///
/// Small, because each is a request to somebody else's server: a pass
/// that drained a large backlog at once would look like a burst of
/// traffic aimed at whichever instance happens to be behind on delivery.
const BATCH: i64 = 20;

/// One image a post is waiting on.
#[derive(sqlx::FromRow)]
struct Pending {
    id: Uuid,
    post_id: Uuid,
    actor_id: Uuid,
    remote_url: String,
    alt_text: Option<String>,
    ordinal: i16,
    attempts: i32,
}

/// Wait before the next attempt, growing and capped.
///
/// Saturating throughout: `attempts` is read from a column, and a value
/// large enough to overflow the shift would otherwise panic a worker
/// nobody is watching.
fn backoff(attempts: i32) -> Duration {
    let steps = attempts.clamp(0, 16) as u32;
    let secs = 60u64.saturating_mul(1u64 << steps.min(6));
    Duration::from_secs(secs.min(3600))
}

/// Fetch every image that is due, once. Returns how many were stored.
pub async fn drain(
    pool: &PgPool,
    media: &MediaStore,
    client: &reqwest::Client,
    domain: &str,
) -> u64 {
    let due = match sqlx::query_as::<_, Pending>(
        "SELECT id, post_id, actor_id, remote_url, alt_text, ordinal, attempts \
         FROM media_fetch_operations \
         WHERE state = 'pending' AND next_attempt_at <= now() \
         ORDER BY next_attempt_at ASC LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = %e, "media fetch operations could not be read");
            return 0;
        }
    };

    let mut stored = 0;
    for pending in due {
        match fetch_one(pool, media, client, domain, &pending).await {
            Ok(()) => {
                mark_succeeded(pool, pending.id).await;
                stored += 1;
            }
            Err(reason) => mark_failed(pool, pending.id, pending.attempts, &reason).await,
        }
    }

    stored
}

/// Fetch one image, store it, and record the attachment.
///
/// The object is written before the row and removed again if the row
/// fails, so a failed attempt never leaves bytes nothing points at.
async fn fetch_one(
    pool: &PgPool,
    media: &MediaStore,
    client: &reqwest::Client,
    domain: &str,
    pending: &Pending,
) -> Result<(), String> {
    // The same guard every federated fetch goes through. This URL is the
    // most attacker-controlled input the instance takes: it arrives in a
    // peer's document and is dereferenced by the server itself.
    let response = noombat_federation::http::guarded_get_image(client, &pending.remote_url)
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("peer answered {}", response.status()));
    }

    // Bounded before buffering, and at the size a local upload may be:
    // accepting from a peer what would be refused from a user would make
    // federation the way around the limit.
    let raw = noombat_federation::http::bytes_within_limit(response, MAX_UPLOAD_BYTES, "an image")
        .await
        .map_err(|e| e.to_string())?;

    // Decoded, bounded and re-encoded by the upload pipeline. The peer's
    // declared media type is not consulted and the bytes are not passed
    // through, which is what decides the format from the content and
    // removes the location a photograph carries.
    let processed = process_attachment(&raw).map_err(|e| format!("{e:?}"))?;

    let object_key = new_object_key();
    media
        .put(&object_key, &processed.bytes)
        .await
        .map_err(|e| format!("storing the image failed: {e}"))?;

    match record(pool, media, domain, pending, &processed, &object_key).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Nothing references the object, so it must not be left.
            let _ = media.delete(&object_key).await;
            Err(e)
        }
    }
}

/// Write the `media_attachments` row for a fetched image.
///
/// The stored hash is this instance's own, not the peer's. It has to
/// describe the bytes served from here, and those have been re-encoded
/// and may have been scaled down, so the peer's hash would blur to
/// something the reader never sees.
async fn record(
    pool: &PgPool,
    media: &MediaStore,
    domain: &str,
    pending: &Pending,
    processed: &ProcessedImage,
    object_key: &str,
) -> Result<(), String> {
    let url = format!("https://{domain}/media/{object_key}");

    sqlx::query(
        "INSERT INTO media_attachments \
             (actor_id, post_id, media_type, object_key, backend, purpose, url, \
              byte_size, alt_text, blurhash, ordinal) \
         VALUES ($1, $2, $3, $4, $5, 'post', $6, $7, $8, $9, $10)",
    )
    .bind(pending.actor_id)
    .bind(pending.post_id)
    .bind(processed.media_type)
    .bind(object_key)
    .bind(media.backend())
    .bind(&url)
    .bind(processed.bytes.len() as i64)
    .bind(&pending.alt_text)
    .bind(&processed.blurhash)
    .bind(pending.ordinal)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|e| format!("recording the image failed: {e}"))
}

async fn mark_succeeded(pool: &PgPool, id: Uuid) {
    if let Err(e) = sqlx::query(
        "UPDATE media_fetch_operations \
         SET state = 'succeeded', completed_at = now(), attempts = attempts + 1, last_error = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    {
        error!(%id, error = %e, "a fetched image could not be recorded as done");
    }
}

async fn mark_failed(pool: &PgPool, id: Uuid, attempts: i32, reason: &str) {
    let next = attempts + 1;
    let exhausted = next >= MAX_ATTEMPTS;

    let result = sqlx::query(
        "UPDATE media_fetch_operations \
         SET attempts = $2, last_error = $3, \
             state = CASE WHEN $4 THEN 'failed' ELSE 'pending' END, \
             next_attempt_at = now() + ($5 || ' seconds')::interval \
         WHERE id = $1",
    )
    .bind(id)
    .bind(next)
    .bind(reason)
    .bind(exhausted)
    .bind(backoff(next).as_secs().to_string())
    .execute(pool)
    .await;

    if let Err(e) = result {
        error!(%id, error = %e, "a failed image fetch could not be recorded");
        return;
    }

    if exhausted {
        // A post that will now never show its pictures, which is what an
        // administrator asking why a post looks empty needs to find.
        warn!(%id, attempts = next, reason, "an image fetch gave up");
    } else {
        info!(%id, attempts = next, reason, "an image fetch failed; will retry");
    }
}

/// Drain due fetches on a fixed interval.
pub async fn run_worker(
    pool: PgPool,
    media: MediaStore,
    client: reqwest::Client,
    domain: String,
    interval: Duration,
) {
    loop {
        let stored = drain(&pool, &media, &client, &domain).await;
        if stored > 0 {
            info!(stored, "remote images fetched");
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_grows_and_is_capped() {
        assert_eq!(backoff(0), Duration::from_secs(60));
        assert!(backoff(3) > backoff(1));
        assert!(backoff(60) <= Duration::from_secs(3600));
    }

    /// `attempts` is read from a column, so a value nobody expected must
    /// not panic a worker that runs unattended.
    #[test]
    fn the_backoff_never_overflows() {
        assert!(backoff(i32::MAX) <= Duration::from_secs(3600));
        assert!(backoff(-1) >= Duration::from_secs(60));
    }
}
