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
    /// Create a new fallback limiter.
    ///
    /// `max_requests` is the ceiling per `window`. Both must be
    /// greater than zero; this function panics otherwise (callers
    /// must validate configuration before constructing the limiter).
    pub fn new(max_requests: u32, window: std::time::Duration) -> Self {
        assert!(max_requests > 0, "rate limit must be > 0");
        assert!(!window.is_zero(), "rate limit window must be > 0");

        // Replenishment interval = window / max_requests.
        let interval = window / max_requests;
        let quota = Quota::with_period(interval)
            .expect("rate limit interval must be non-zero")
            .allow_burst(NonZeroU32::new(max_requests).expect("max_requests already checked > 0"));

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

/// The outcome of a rate-limit check.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Over the limit. Carries the seconds to advertise in `Retry-After`.
    Limited {
        retry_after: i64,
    },
}

impl Decision {
    /// The `429` this decision maps to, or `None` when allowed.
    pub fn into_response(self) -> Option<Response> {
        match self {
            Decision::Allowed => None,
            Decision::Limited { retry_after } => Some(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(RETRY_AFTER, retry_after.max(1).to_string())],
                )
                    .into_response(),
            ),
        }
    }
}

/// Count one request against `key` and decide whether to allow it.
///
/// Redis first, then the in-process governor when Redis is absent or
/// errors. Callers that need a limit other than the instance-wide one
/// pass their own `limit` and `window`; note that the fallback limiter
/// has a single quota fixed at construction, so during a Redis outage
/// every caller degrades to that quota. The key still separates them,
/// so a caller cannot be starved by another's traffic, but a tighter
/// route-specific ceiling is not preserved. The exposure is bounded by
/// the outage.
pub async fn check_key(state: &AppState, key: &str, limit: i64, window: i64) -> Decision {
    if let Some(mut redis) = state.redis.clone() {
        match redis::cmd("EVAL")
            .arg(RATE_LIMIT_LUA)
            .arg(1i64)
            .arg(key)
            .arg(window)
            .query_async::<Vec<i64>>(&mut redis)
            .await
        {
            Ok(result) => {
                let count = result.first().copied().unwrap_or(0);
                let ttl = result.get(1).copied().unwrap_or(window);

                return if count > limit {
                    Decision::Limited { retry_after: ttl }
                } else {
                    Decision::Allowed
                };
            }
            Err(e) => {
                warn!("Redis EVAL failed (falling back to in-process limiter): {e}");
                // Fall through to governor.
            }
        }
    }

    if state.fallback_rate_limiter.check(key) {
        Decision::Allowed
    } else {
        Decision::Limited {
            retry_after: window,
        }
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

    let decision = check_key(
        &state,
        &format!("rl:{ip}"),
        state.rate_limit,
        state.rate_limit_window_secs,
    )
    .await;

    match decision.into_response() {
        Some(limited) => limited,
        None => next.run(request).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn allowed_produces_no_response() {
        assert!(Decision::Allowed.into_response().is_none());
    }

    #[test]
    fn limited_produces_429_with_retry_after() {
        let response = Decision::Limited { retry_after: 42 }
            .into_response()
            .expect("a limited decision is a response");

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "42");
    }

    /// `Retry-After: 0` invites an immediate retry, which is the one
    /// value a limiter must not emit. Redis reports a TTL of 0 for a key
    /// expiring within the current second, and -1 for one with no TTL
    /// set, so this is reachable rather than theoretical.
    #[test]
    fn retry_after_is_never_below_one() {
        for retry_after in [-1, 0] {
            let response = Decision::Limited { retry_after }
                .into_response()
                .expect("a limited decision is a response");

            assert_eq!(response.headers()[RETRY_AFTER], "1", "for {retry_after}");
        }
    }

    /// Keys are independent buckets.
    ///
    /// This is what makes per-account keying worth anything: one
    /// requester exhausting their budget must not spend anyone else's.
    #[test]
    fn the_fallback_limiter_counts_per_key() {
        let limiter = FallbackRateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("cv:acct:alice"));
        assert!(limiter.check("cv:acct:alice"));
        assert!(
            !limiter.check("cv:acct:alice"),
            "the third request is over a ceiling of two"
        );
        assert!(
            limiter.check("cv:acct:bob"),
            "a separate key has its own budget"
        );
    }
}
