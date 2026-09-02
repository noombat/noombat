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

/// Which corpus a reader is asking about.
///
/// Both lists are computed and cached, because they are different
/// questions rather than one question filtered: "what is being discussed
/// here" and "what is being discussed on the servers this one talks to"
/// have different answers and a reader may want either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Posts by accounts on this instance.
    #[default]
    Local,
    /// Everything this instance holds and is allowed to count.
    Fediverse,
}

impl Scope {
    /// Read a query-string value.
    ///
    /// An unrecognised value is `Local`, the narrower of the two: a
    /// typo should not silently widen what a reader is shown.
    pub fn from_param(value: Option<&str>) -> Self {
        match value {
            Some("fediverse") | Some("all") => Self::Fediverse,
            _ => Self::Local,
        }
    }
}

/// In-memory cache of the trending hashtag list.
///
/// Updated by the background worker; read by the HTTP handler.
/// Wrapped in [`Arc<RwLock<_>>`] for concurrent access.
#[derive(Debug, Clone)]
pub struct TrendingCache {
    inner: Arc<RwLock<CacheState>>,
}

#[derive(Debug, Default)]
struct CacheState {
    local: Vec<TrendingHashtag>,
    fediverse: Vec<TrendingHashtag>,
    updated_at: Option<DateTime<Utc>>,
}

impl TrendingCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheState::default())),
        }
    }

    /// Read the current trending hashtags for one scope.
    pub async fn get(&self, scope: Scope) -> Vec<TrendingHashtag> {
        let state = self.inner.read().await;
        match scope {
            Scope::Local => state.local.clone(),
            Scope::Fediverse => state.fediverse.clone(),
        }
    }

    /// Replace the cached list for one scope.
    async fn set(&self, scope: Scope, tags: Vec<TrendingHashtag>) {
        let mut state = self.inner.write().await;
        match scope {
            Scope::Local => state.local = tags,
            Scope::Fediverse => state.fediverse = tags,
        }
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
pub async fn compute_trending(
    pool: &PgPool,
    window_hours: i32,
    limit: i64,
    scope: Scope,
) -> Result<Vec<TrendingHashtag>> {
    // Remote posts count only where the operator has turned remote
    // indexing on. Trending was already fediverse-wide and uncontrolled:
    // a remote post with linked hashtags counted, and nothing said so or
    // let anybody choose otherwise.
    let remote_allowed = scope == Scope::Fediverse && remote_indexing_enabled(pool).await;

    let rows = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT h.name, COUNT(DISTINCT ph.post_id) AS post_count
        FROM post_hashtags ph
        INNER JOIN hashtags h ON h.id = ph.hashtag_id
        INNER JOIN posts p ON p.id = ph.post_id
        INNER JOIN actors a ON a.id = p.actor_id
        WHERE p.created_at >= NOW() - make_interval(hours => $1)
          AND p.visibility = 'public'
          -- Trending is the one surface where a relay could manufacture
          -- consensus: enough relayed posts on a tag and the tag is
          -- promoted to every reader here, with nothing but the relay's
          -- word behind any of them. Excluded rather than badged: a
          -- trending list has no room for a badge, and the list is the
          -- claim.
          AND p.relayed_unverified = FALSE
          AND (
            a.is_local
            -- A remote author counts only if they said their posts may
            -- be indexed. The operator's switch does not overrule them.
            OR ($2 AND COALESCE((a.actor_privacy->>'indexable')::boolean, FALSE))
          )
        GROUP BY h.name
        ORDER BY post_count DESC
        LIMIT $3
        "#,
    )
    .bind(window_hours)
    .bind(remote_allowed)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let tags = rows
        .into_iter()
        .map(|(name, post_count)| TrendingHashtag { name, post_count })
        .collect();

    Ok(tags)
}

/// Whether the operator has turned remote indexing on.
async fn remote_indexing_enabled(pool: &PgPool) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT index_remote_posts FROM instance_settings LIMIT 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// Run the trending hashtags background worker.
///
/// Computes trending hashtags at `interval` and writes the result
/// to `cache`. Runs indefinitely; intended to be spawned as a
/// detached Tokio task.
pub async fn run_worker(
    pool: PgPool,
    cache: TrendingCache,
    interval: Duration,
    window_hours: i32,
    limit: i64,
) {
    info!(
        interval_secs = interval.as_secs(),
        window_hours, limit, "trending hashtags worker started"
    );

    loop {
        // Both scopes on every pass. The fediverse list collapses to
        // the local one where the operator has not turned remote
        // indexing on, which costs a second query and keeps the reader's
        // choice meaningful rather than silently absent.
        for scope in [Scope::Local, Scope::Fediverse] {
            match compute_trending(&pool, window_hours, limit, scope).await {
                Ok(tags) => {
                    debug!(count = tags.len(), ?scope, "trending hashtags recomputed");
                    cache.set(scope, tags).await;
                }
                Err(e) => {
                    warn!(?scope, "trending hashtags computation failed: {e}");
                }
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
        assert!(cache.get(Scope::Local).await.is_empty());
        assert!(cache.get(Scope::Fediverse).await.is_empty());
    }

    #[test]
    fn an_unknown_scope_reads_as_local() {
        // The narrower of the two. A typo must not widen what a reader
        // is shown without their asking.
        assert_eq!(Scope::from_param(Some("fediverse")), Scope::Fediverse);
        assert_eq!(Scope::from_param(Some("all")), Scope::Fediverse);
        assert_eq!(Scope::from_param(Some("everything")), Scope::Local);
        assert_eq!(Scope::from_param(None), Scope::Local);
        assert_eq!(Scope::default(), Scope::Local);
    }

    #[tokio::test]
    async fn the_two_scopes_are_cached_apart() {
        let cache = TrendingCache::new();
        cache
            .set(
                Scope::Fediverse,
                vec![TrendingHashtag {
                    name: "elsewhere".into(),
                    post_count: 9,
                }],
            )
            .await;

        // Writing one must not populate the other, or a reader asking
        // for local content gets the wider list under the narrower name.
        assert!(cache.get(Scope::Local).await.is_empty());
        assert_eq!(cache.get(Scope::Fediverse).await.len(), 1);
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
        cache.set(Scope::Local, tags.clone()).await;
        let retrieved = cache.get(Scope::Local).await;
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0].name, "rust");
        assert_eq!(retrieved[0].post_count, 42);
    }
}
