// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Per-IP fixed-window rate-limit middleware backed by Redis, with an
//! in-process `governor`-based fallback that activates when Redis is
//! unavailable.
//!
//! The primary limiter uses an atomic Lua script (`INCR` + conditional
//! `EXPIRE` + `TTL`) on Redis. When Redis is not configured or a
//! command fails, the request is checked against a [`governor`] keyed
//! rate limiter stored in [`AppState`](crate::state::AppState),
//! preventing a complete bypass (fail-closed).
//!
//! # Fallback limiter notes
//!
//! The Redis primary uses a fixed-window counter; the `governor`
//! fallback uses the GCRA (Generic Cell Rate Algorithm), a leaky-bucket
//! variant. GCRA smooths traffic evenly, whereas a fixed-window counter
//! resets at window boundaries. The two are not behaviorally identical,
//! but both enforce the configured requests-per-minute ceiling, which
//! is the objective of the fallback.
//!
//! The `governor` `DashMap`-backed keyed state store grows by one
//! entry per unique key (IP address or domain). Entries are never
//! evicted. Under a DDoS with many spoofed source IPs this could
//! consume significant memory; however, the fallback is active only
//! during Redis outages, bounding the exposure window.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::RETRY_AFTER;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tracing::warn;

use crate::state::AppState;

/// Maximum requests per window (Redis primary).
const DEFAULT_LIMIT: i64 = 120;
/// Window size in seconds (Redis primary).
const DEFAULT_WINDOW_SECS: i64 = 60;

/// Lua script that atomically increments the counter, sets the TTL on
/// first creation, and returns both the current count and the
/// remaining TTL.
///
/// Returns a two-element array: `{count, ttl}`.
const RATE_LIMIT_LUA: &str = r"
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    local ttl = redis.call('TTL', KEYS[1])
    return {count, ttl}
";

/// In-process keyed rate limiter (governor-backed).
///
/// Wraps `DefaultKeyedRateLimiter<String>` in an [`Arc`] because the
/// inner [`RateLimiter`] uses atomic state and is not [`Clone`];
/// `Arc` allows it to be shared across the cloneable [`AppState`].
///
/// Used as a fallback when Redis is unconfigured or unreachable.
#[derive(Clone)]
pub struct FallbackRateLimiter {
    inner: Arc<DefaultKeyedRateLimiter<String>>,
}

impl FallbackRateLimiter {
    /// Create a new fallback limiter with the given per-minute quota.
    pub fn new(requests_per_minute: u32) -> Self {
        let quota = Quota::per_minute(
            NonZeroU32::new(requests_per_minute).expect("requests_per_minute must be > 0"),
        );
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    /// Check whether `key` is within the rate limit.
    ///
    /// Returns `true` if the request is allowed, `false` if it should
    /// be rejected.
    ///
    /// Note: `governor`'s `check_key` requires `&String`, so an
    /// allocation from `&str` is unavoidable with the current API.
    /// The cost is bounded (IP strings are at most ~45 bytes for
    /// IPv6) and occurs only when the fallback is active.
    pub fn check(&self, key: &str) -> bool {
        self.inner.check_key(&key.to_owned()).is_ok()
    }
}

/// Axum middleware that enforces a per-IP rate limit.
///
/// Tries Redis first; on failure, falls back to the in-process
/// governor-backed limiter.
pub async fn rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Extract the remote IP.
    let ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());

    // ..... Try Redis .....
    if let Some(mut redis) = state.redis.clone() {
        let key = format!("rl:{ip}");

        match redis::cmd("EVAL")
            .arg(RATE_LIMIT_LUA)
            .arg(1i64)
            .arg(&key)
            .arg(DEFAULT_WINDOW_SECS)
            .query_async::<Vec<i64>>(&mut redis)
            .await
        {
            Ok(result) => {
                let count = result.first().copied().unwrap_or(0);
                let ttl = result.get(1).copied().unwrap_or(DEFAULT_WINDOW_SECS);

                if count > DEFAULT_LIMIT {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(RETRY_AFTER, ttl.max(1).to_string())],
                    )
                        .into_response();
                }

                // Redis succeeded; allow the request.
                return next.run(request).await;
            }
            Err(e) => {
                warn!("Redis EVAL failed (falling back to in-process limiter): {e}");
                // Fall through to governor.
            }
        }
    }

    // ..... In-process fallback (Redis absent or failed) .....
    if !state.fallback_rate_limiter.check(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, DEFAULT_WINDOW_SECS.max(1).to_string())],
        )
            .into_response();
    }

    next.run(request).await
}
