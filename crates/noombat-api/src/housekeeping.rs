// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Expired email challenges, and analytics rows past their retention.
//!
//! One worker rather than two: both run on the same cadence, and a
//! second `tokio::spawn` for one `DELETE` is more machinery than the
//! work justifies.

use std::time::Duration;

use sqlx::PgPool;
use tracing::{info, warn};

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

/// Run both sweeps once. Returns `(challenges, analytics rows)`.
///
/// The analytics half builds its own backend from the pool: retention is
/// a property of the store, so `purge_expired` is inherent to the
/// Postgres backend rather than part of the trait every consumer sees.
pub async fn sweep(pool: &PgPool) -> (u64, u64) {
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

    (challenges, rows)
}

/// Sweep on a fixed interval.
pub async fn run_worker(pool: PgPool, interval: Duration) {
    info!(
        interval_secs = interval.as_secs(),
        "housekeeping worker started"
    );

    loop {
        let (challenges, rows) = sweep(&pool).await;
        if challenges > 0 || rows > 0 {
            info!(
                challenges,
                analytics_rows = rows,
                "housekeeping sweep complete"
            );
        }
        tokio::time::sleep(interval).await;
    }
}
