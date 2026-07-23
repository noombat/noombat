// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! PostgreSQL implementation of the [`AnalyticsBackend`] trait.
//!
//! Increments are recorded as daily-bucketed counters in the
//! `analytics_counters` table. No IP addresses, user agents, or
//! session identifiers are stored.

use noombat_core::error::{NoombatError, Result};
use noombat_core::extension::AnalyticsBackend;
use serde_json::{Value, json};
use sqlx::PgPool;
use tracing::debug;

/// Concrete [`AnalyticsBackend`] backed by the PostgreSQL
/// `analytics_counters` table.
pub struct PgAnalyticsBackend {
    pool: PgPool,
}

impl PgAnalyticsBackend {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Purge analytics rows older than `retention_days`.
    ///
    /// Intended to be called by a background worker on a nightly
    /// schedule.
    pub async fn purge_expired(&self, retention_days: i32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM analytics_counters \
             WHERE period < CURRENT_DATE - $1::int",
        )
        .bind(retention_days)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            debug!(deleted, retention_days, "purged expired analytics rows");
        }
        Ok(deleted)
    }
}

#[async_trait::async_trait]
impl AnalyticsBackend for PgAnalyticsBackend {
    /// Increment a counter for the given target, metric, and the
    /// current date.
    ///
    /// Uses an upsert (`ON CONFLICT ... DO UPDATE`) so that the first
    /// interaction on a given day creates the row and subsequent
    /// interactions increment it atomically.
    async fn increment(&self, target_type: &str, target_id: &str, metric: &str) -> Result<()> {
        let target_uuid: uuid::Uuid = target_id
            .parse()
            .map_err(|e| NoombatError::BadRequest(format!("invalid target UUID: {e}")))?;

        sqlx::query(
            r#"INSERT INTO analytics_counters
                   (target_type, target_id, metric, period, count)
               VALUES ($1, $2, $3, CURRENT_DATE, 1)
               ON CONFLICT (target_type, target_id, metric, period)
               DO UPDATE SET count = analytics_counters.count + 1"#,
        )
        .bind(target_type)
        .bind(target_uuid)
        .bind(metric)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Query aggregated counter values for a target over a date range.
    async fn query(
        &self,
        target_type: &str,
        target_id: &str,
        metric: &str,
        start: &str,
        end: &str,
    ) -> Result<Vec<Value>> {
        let target_uuid: uuid::Uuid = target_id
            .parse()
            .map_err(|e| NoombatError::BadRequest(format!("invalid target UUID: {e}")))?;

        let start_date: chrono::NaiveDate = start
            .parse()
            .map_err(|e| NoombatError::BadRequest(format!("invalid start date: {e}")))?;
        let end_date: chrono::NaiveDate = end
            .parse()
            .map_err(|e| NoombatError::BadRequest(format!("invalid end date: {e}")))?;

        let rows = sqlx::query_as::<_, (chrono::NaiveDate, i64)>(
            r#"SELECT period, count
               FROM analytics_counters
               WHERE target_type = $1
                 AND target_id = $2
                 AND metric = $3
                 AND period >= $4
                 AND period <= $5
               ORDER BY period ASC"#,
        )
        .bind(target_type)
        .bind(target_uuid)
        .bind(metric)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let results: Vec<Value> = rows
            .into_iter()
            .map(|(period, count)| {
                json!({
                    "period": period.to_string(),
                    "count": count,
                })
            })
            .collect();

        Ok(results)
    }
}
