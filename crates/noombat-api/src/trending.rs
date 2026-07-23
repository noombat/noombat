// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Trending hashtags: background computation and query.
//!
//! A background worker periodically computes the top hashtags over a
//! configurable rolling window (default: 24 hours) by counting posts
//! that reference each hashtag within the window. The results are
//! cached in Redis (when available) or in-memory, and served via the
//! explore/trending endpoint.

use chrono::{DateTime, Utc};
use noombat_core::error::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// A trending hashtag with its post count over the rolling window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendingHashtag {
    pub name: String,
    pub post_count: i64,
}

/// In-memory cache of the trending hashtag list.
///
/// Updated by the background worker; read by the HTTP handler.
/// Wrapped in [`Arc<RwLock<_>>`] for concurrent access.
#[derive(Debug, Clone)]
pub struct TrendingCache {
    inner: Arc<RwLock<CacheState>>,
}

#[derive(Debug)]
struct CacheState {
    tags: Vec<TrendingHashtag>,
    updated_at: Option<DateTime<Utc>>,
}

impl TrendingCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheState {
                tags: Vec::new(),
                updated_at: None,
            })),
        }
    }

    /// Read the current trending hashtags from the cache.
    pub async fn get(&self) -> Vec<TrendingHashtag> {
        self.inner.read().await.tags.clone()
    }

    /// Replace the cached trending hashtags with a new list.
    async fn set(&self, tags: Vec<TrendingHashtag>) {
        let mut state = self.inner.write().await;
        state.tags = tags;
        state.updated_at = Some(Utc::now());
    }
}

impl Default for TrendingCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the top trending hashtags over the given rolling window.
///
/// Counts the number of distinct posts that reference each hashtag
/// within `[now - window_hours, now]`, ordered by post count
/// descending.
///
/// # Arguments
///
/// * `pool`: database connection pool.
/// * `window_hours`: the rolling window size in hours (default: 24).
/// * `limit`: maximum number of trending tags to return (default: 20).
pub async fn compute_trending(
    pool: &PgPool,
    window_hours: i32,
    limit: i64,
) -> Result<Vec<TrendingHashtag>> {
    let rows = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT h.name, COUNT(DISTINCT ph.post_id) AS post_count
        FROM post_hashtags ph
        INNER JOIN hashtags h ON h.id = ph.hashtag_id
        INNER JOIN posts p ON p.id = ph.post_id
        WHERE p.created_at >= NOW() - make_interval(hours => $1)
          AND p.visibility = 'public'
        GROUP BY h.name
        ORDER BY post_count DESC
        LIMIT $2
        "#,
    )
    .bind(window_hours)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let tags = rows
        .into_iter()
        .map(|(name, post_count)| TrendingHashtag { name, post_count })
        .collect();

    Ok(tags)
}

/// Run the trending hashtags background worker.
///
/// Computes trending hashtags at `interval` and writes the result
/// to `cache`. Runs indefinitely; intended to be spawned as a
/// detached Tokio task.
///
/// # Arguments
///
/// * `pool`: database connection pool.
/// * `cache`: shared trending cache.
/// * `interval`: recomputation interval (default: 5 minutes).
/// * `window_hours`: rolling window in hours (default: 24).
/// * `limit`: maximum trending tags (default: 20).
pub async fn run_worker(
    pool: PgPool,
    cache: TrendingCache,
    interval: Duration,
    window_hours: i32,
    limit: i64,
) {
    info!(
        interval_secs = interval.as_secs(),
        window_hours,
        limit,
        "trending hashtags worker started"
    );

    loop {
        match compute_trending(&pool, window_hours, limit).await {
            Ok(tags) => {
                debug!(count = tags.len(), "trending hashtags recomputed");
                cache.set(tags).await;
            }
            Err(e) => {
                warn!("trending hashtags computation failed: {e}");
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_starts_empty() {
        let cache = TrendingCache::new();
        let tags = cache.get().await;
        assert!(tags.is_empty());
    }

    #[tokio::test]
    async fn cache_set_and_get() {
        let cache = TrendingCache::new();
        let tags = vec![
            TrendingHashtag {
                name: "rust".into(),
                post_count: 42,
            },
            TrendingHashtag {
                name: "activitypub".into(),
                post_count: 17,
            },
        ];
        cache.set(tags.clone()).await;
        let retrieved = cache.get().await;
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0].name, "rust");
        assert_eq!(retrieved[0].post_count, 42);
    }
}
