// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Search-index work that must not be lost, and the record of it.
//!
//! A search document outlives the row it was built from. Erasure deletes
//! the post and the index keeps its full text, so a removal that fails is
//! an erasure that leaves the writing searchable by its contents. That
//! cannot be fire-and-forget: nobody reads a warning about something that
//! already returned success to the person who asked for it.
//!
//! So a removal is written down first and drained by a worker with
//! backoff, and a removal that exhausts its attempts stays visible on the
//! administration page rather than disappearing.
//!
//! **Additions are asymmetric on purpose.** A local post that fails to
//! index is missing from search and its author notices. A remote post
//! that fails to index is missing from search and nobody notices, so
//! those are queued; local additions stay direct, where the cost of the
//! round trip is paid by the request that caused it.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use noombat_core::error::Result;
use noombat_core::extension::SearchBackend;
use serde_json::Value;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

/// How many attempts before an operation is given up on.
///
/// Given up on, not forgotten: the row stays `failed` with its error, so
/// an administrator can see what is stuck out of the index.
const MAX_ATTEMPTS: i32 = 8;

/// Backoff for attempt `n`, capped at an hour.
fn backoff(attempts: i32) -> Duration {
    let seconds = 30_u64.saturating_mul(1 << attempts.clamp(0, 6) as u32);
    Duration::from_secs(seconds.min(3600))
}

/// Record that a document must leave the index.
///
/// Delegates to [`noombat_federation::search_queue`], which owns the
/// `ON CONFLICT` rules. Two writers with two copies of those rules is
/// two answers to when a removal beats an upsert.
pub async fn enqueue_removal(pool: &PgPool, index: &str, document_id: &str) -> Result<()> {
    noombat_federation::search_queue::enqueue_removal(pool, index, document_id).await
}

/// Record that a document should enter the index.
pub async fn enqueue_upsert(
    pool: &PgPool,
    index: &str,
    document_id: &str,
    document: &Value,
) -> Result<()> {
    noombat_federation::search_queue::enqueue_upsert(pool, index, document_id, document).await
}

/// One operation that will not be retried again.
#[derive(Debug, sqlx::FromRow)]
pub struct FailedOperation {
    pub index_name: String,
    pub document_id: String,
    pub operation: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Operations that exhausted their attempts, removals first.
///
/// Removals lead because they are the ones with a rights consequence: a
/// stuck upsert is content missing from search, a stuck removal is
/// content that should be gone and is not.
pub async fn failures(pool: &PgPool) -> Result<Vec<FailedOperation>> {
    let rows = sqlx::query_as::<_, FailedOperation>(
        "SELECT index_name, document_id, operation, attempts, last_error, created_at \
         FROM search_index_operations WHERE state = 'failed' \
         ORDER BY (operation = 'remove') DESC, created_at DESC LIMIT 200",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// How many removals are stuck, which is the figure that matters.
pub async fn stuck_removals(pool: &PgPool) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM search_index_operations \
         WHERE operation = 'remove' AND state <> 'succeeded'",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Drain every operation that is due, once. Returns how many succeeded.
///
/// With no search backend configured there is nothing to drain and the
/// work stays pending, which is the honest state: the documents are not
/// out of an index this instance does not have, and if one is configured
/// later the backlog is still there.
pub async fn drain(pool: &PgPool, search: &Option<Arc<dyn SearchBackend>>) -> u64 {
    let Some(backend) = search.as_ref() else {
        return 0;
    };

    let due = match sqlx::query_as::<_, (Uuid, String, String, String, Option<Value>, i32)>(
        "SELECT id, index_name, document_id, operation, document, attempts \
         FROM search_index_operations \
         WHERE state = 'pending' AND next_attempt_at <= now() \
         ORDER BY (operation = 'remove') DESC, next_attempt_at ASC LIMIT 100",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = %e, "search index operations could not be read");
            return 0;
        }
    };

    let mut succeeded = 0;
    for (id, index, document_id, operation, document, attempts) in due {
        let outcome = match operation.as_str() {
            "remove" => backend.delete(&index, &document_id).await,
            "upsert" => match document {
                Some(doc) => backend.upsert(&index, &document_id, doc).await,
                // An upsert with no body cannot be retried into
                // existence, so it is failed rather than retried forever.
                None => {
                    mark_failed(pool, id, MAX_ATTEMPTS, "queued upsert carries no document").await;
                    continue;
                }
            },
            other => {
                mark_failed(
                    pool,
                    id,
                    MAX_ATTEMPTS,
                    &format!("unknown operation {other}"),
                )
                .await;
                continue;
            }
        };

        match outcome {
            Ok(()) => {
                mark_succeeded(pool, id).await;
                succeeded += 1;
            }
            Err(e) => mark_failed(pool, id, attempts, &e.to_string()).await,
        }
    }

    succeeded
}

async fn mark_succeeded(pool: &PgPool, id: Uuid) {
    if let Err(e) = sqlx::query(
        "UPDATE search_index_operations \
         SET state = 'succeeded', completed_at = now(), attempts = attempts + 1, last_error = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    {
        error!(%id, error = %e, "search index operation completed and could not be recorded");
    }
}

async fn mark_failed(pool: &PgPool, id: Uuid, attempts: i32, reason: &str) {
    let next = attempts + 1;
    let exhausted = next >= MAX_ATTEMPTS;

    let result = sqlx::query(
        "UPDATE search_index_operations \
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
        error!(%id, error = %e, "search index failure could not be recorded");
        return;
    }

    if exhausted {
        // Loud, because a removal that gave up is content still
        // searchable that somebody asked to have removed.
        error!(%id, attempts = next, reason, "search index operation gave up");
    } else {
        warn!(%id, attempts = next, reason, "search index operation failed; will retry");
    }
}

/// Drain due operations on a fixed interval.
pub async fn run_worker(pool: PgPool, search: Option<Arc<dyn SearchBackend>>, interval: Duration) {
    loop {
        let settled = drain(&pool, &search).await;
        if settled > 0 {
            info!(settled, "search index operations completed");
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_grows_and_is_capped() {
        assert_eq!(backoff(0), Duration::from_secs(30));
        assert_eq!(backoff(4), Duration::from_secs(480));
        assert!(backoff(60) <= Duration::from_secs(3600));
    }

    #[test]
    fn the_backoff_never_overflows() {
        assert!(backoff(i32::MAX) <= Duration::from_secs(3600));
        assert!(backoff(-1) >= Duration::from_secs(30));
    }
}
