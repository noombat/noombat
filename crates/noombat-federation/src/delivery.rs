// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Delivery queue worker for outbound ActivityPub activities.

use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Maximum number of concurrent outbound HTTP deliveries per poll cycle.
const MAX_CONCURRENT_DELIVERIES: usize = 10;

/// A row from the `delivery_queue` table.
#[derive(FromRow)]
struct DeliveryRow {
    id: i64,
    payload: Value,
    target_inbox: String,
    attempts: i16,
}

/// Enqueue an activity for delivery to a remote inbox.
pub async fn enqueue(
    pool: &PgPool,
    payload: &Value,
    target_inbox: &str,
) -> noombat_core::error::Result<()> {
    sqlx::query(
        r#"INSERT INTO delivery_queue (payload, target_inbox)
           VALUES ($1, $2)"#,
    )
    .bind(payload)
    .bind(target_inbox)
    .execute(pool)
    .await?;

    info!(target_inbox, "enqueued activity for delivery");
    Ok(())
}

/// Process pending deliveries (called by a background Tokio task).
///
/// Up to 50 rows are fetched per cycle. Deliveries are dispatched
/// concurrently (bounded to [`MAX_CONCURRENT_DELIVERIES`]) so that a
/// slow or unreachable remote server does not block the entire batch.
///
/// On transient failure, applies exponential backoff up to a maximum of
/// 10 attempts.
pub async fn process_queue(pool: &PgPool, http_client: &reqwest::Client) {
    let rows = sqlx::query_as::<_, DeliveryRow>(
        r#"SELECT id, payload, target_inbox, attempts
           FROM delivery_queue
           WHERE next_retry <= now() AND attempts < 10
           ORDER BY next_retry ASC
           LIMIT 50
           FOR UPDATE SKIP LOCKED"#,
    )
    .fetch_all(pool)
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            error!("failed to fetch delivery queue: {e}");
            return;
        }
    };

    if rows.is_empty() {
        return;
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES));
    let mut set = JoinSet::new();

    for row in rows {
        let pool = pool.clone();
        let client = http_client.clone();
        let permit = semaphore.clone();

        set.spawn(async move {
            // Acquire a permit before performing the HTTP request,
            // bounding the number of simultaneous outbound connections.
            let _permit = permit.acquire().await.expect("semaphore closed");
            deliver_one(&pool, &client, row).await;
        });
    }

    // Await all spawned tasks.
    while let Some(result) = set.join_next().await {
        if let Err(e) = result {
            error!("delivery task panicked: {e}");
        }
    }
}

/// Attempt delivery of a single activity to a remote inbox.
async fn deliver_one(pool: &PgPool, http_client: &reqwest::Client, row: DeliveryRow) {
    let body = serde_json::to_vec(&row.payload).unwrap_or_default();
    let result = http_client
        .post(&row.target_inbox)
        .header("Content-Type", "application/activity+json")
        .body(body)
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            let _ = sqlx::query("DELETE FROM delivery_queue WHERE id = $1")
                .bind(row.id)
                .execute(pool)
                .await;
            info!(target_inbox = %row.target_inbox, "delivered successfully");
        }
        Ok(resp) if resp.status().as_u16() == 410 => {
            // 410 Gone — remote actor deleted; remove from queue.
            let _ = sqlx::query("DELETE FROM delivery_queue WHERE id = $1")
                .bind(row.id)
                .execute(pool)
                .await;
            info!(target_inbox = %row.target_inbox, "remote actor gone (410); dropping");
        }
        _ => {
            // Transient failure: exponential backoff.
            let backoff_secs = 60i64 * 2i64.pow(row.attempts as u32);
            let max_backoff = TimeDelta::days(7).num_seconds();
            let delay = backoff_secs.min(max_backoff);
            let next_retry = Utc::now() + TimeDelta::seconds(delay);

            let _ = sqlx::query(
                r#"UPDATE delivery_queue
                   SET attempts = attempts + 1, next_retry = $1
                   WHERE id = $2"#,
            )
            .bind(next_retry)
            .bind(row.id)
            .execute(pool)
            .await;

            error!(
                target_inbox = %row.target_inbox,
                attempts = row.attempts,
                "delivery failed; retrying later"
            );
        }
    }
}
