// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Fixed-window rate limiting backed by Redis, with an in-process
//! `governor`-based fallback.
//!
//! [`check_key`] is the one entry point. Callers name their own key,
//! ceiling and window, so the same counting serves the instance-wide
//! per-IP limit, the per-domain federation limit and per-route limits such
//! as CV downloads. It returns a [`Decision`] rather than a response,
//! because callers disagree about what a refusal looks like: the
//! middleware answers `429`, the federation inbox `503`.
//!
//! Keys are prefixed by call site (`rl:`, `rl:fed:`, `cv:`). That is
//! load-bearing: two call sites sharing a quota share a governor limiter,
//! and the prefix is what keeps their buckets apart.
//!
//! The primary limiter is an atomic Lua script (`INCR` + conditional
//! `EXPIRE` + `TTL`) on Redis. When Redis is unconfigured or a command
//! fails, the request falls back to a [`governor`] keyed limiter held in
//! [`AppState`](crate::state::AppState), so there is no complete bypass.
//!
//! The fallback is not only an outage path: `NOOMBAT_REDIS_URL` is
//! optional, so on an instance that never configures Redis the governor is
//! the only limiter there is. That is why it honours each caller's ceiling
//! rather than one instance-wide quota, and why the difference in
//! behaviour matters: Redis counts a fixed window, governor smooths with
//! GCRA. Both enforce the configured ceiling, which is the objective.
//!
//! The governor's `DashMap` keyed state grows by one entry per unique key
//! and never evicts, so a flood from spoofed source IPs costs memory, with
//! no outage window bounding it on a Redis-less instance.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::Duration;

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

/// In-process keyed rate limiter (governor-backed), one limiter per
/// quota.
///
/// `governor` fixes a limiter's quota at construction, so one limiter
/// cannot answer for two ceilings. This keeps one per distinct
/// `(limit, window)` pair, created on first use.
///
/// The outer map is keyed by the *quota*, which comes from configuration
/// and constants and never from a request, so its size is the number of
/// call sites. That is deliberate: the inner per-key stores already grow
/// without eviction, so keying the outer map on anything request-derived
/// would turn a bounded cost into an exhaustion vector.
///
/// The `Arc` is what lets this be shared across the cloneable
/// [`AppState`], since [`RateLimiter`] holds atomic state and is not
/// [`Clone`].
#[derive(Clone, Default)]
pub struct FallbackRateLimiter {
    by_quota: Arc<RwLock<HashMap<QuotaKey, Arc<DefaultKeyedRateLimiter<String>>>>>,
}

/// A ceiling and a window in seconds, identifying one governor limiter.
type QuotaKey = (u32, u64);

impl FallbackRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check `key` against a ceiling of `limit` per `window`.
    ///
    /// `true` allows the request. A quota `governor` cannot represent,
    /// meaning a zero limit or a zero window, denies rather than
    /// panicking: it is a misconfiguration, and this module fails
    /// closed. A poisoned lock denies for the same reason.
    ///
    /// Note: `governor`'s `check_key` requires `&String`, so an
    /// allocation from `&str` is unavoidable with the current API. The
    /// cost is bounded and occurs only when the fallback is active.
    pub fn check(&self, key: &str, limit: u32, window: Duration) -> bool {
        match self.limiter_for(limit, window) {
            Some(limiter) => limiter.check_key(&key.to_owned()).is_ok(),
            None => false,
        }
    }

    /// The limiter for this quota, creating it if this is its first use.
    fn limiter_for(
        &self,
        limit: u32,
        window: Duration,
    ) -> Option<Arc<DefaultKeyedRateLimiter<String>>> {
        let quota_key = (limit, window.as_secs());

        // The common path once each call site has been seen once. The
        // guard is dropped before the governor check so no request
        // holds the lock while being counted.
        if let Ok(map) = self.by_quota.read()
            && let Some(limiter) = map.get(&quota_key)
        {
            return Some(Arc::clone(limiter));
        }

        let quota = Self::quota(limit, window)?;
        let mut map = self.by_quota.write().ok()?;
        Some(Arc::clone(
            map.entry(quota_key)
                .or_insert_with(|| Arc::new(RateLimiter::keyed(quota))),
        ))
    }

    /// `limit` requests per `window`, or `None` if that is not a quota.
    fn quota(limit: u32, window: Duration) -> Option<Quota> {
        let burst = NonZeroU32::new(limit)?;
        // Replenishment interval = window / limit.
        let interval = window.checked_div(limit)?;
        Some(Quota::with_period(interval)?.allow_burst(burst))
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

    // A ceiling or window that will not fit the fallback's types is a
    // misconfiguration rather than traffic, so it denies.
    let (Ok(limit), Ok(window_secs)) = (u32::try_from(limit), u64::try_from(window)) else {
        return Decision::Limited { retry_after: 1 };
    };

    if state
        .fallback_rate_limiter
        .check(key, limit, Duration::from_secs(window_secs))
    {
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

    const MINUTE: Duration = Duration::from_secs(60);

    /// Keys are independent buckets.
    ///
    /// This is what makes per-account keying worth anything: one
    /// requester exhausting their budget must not spend anyone else's.
    #[test]
    fn the_fallback_limiter_counts_per_key() {
        let limiter = FallbackRateLimiter::new();

        assert!(limiter.check("cv:acct:alice", 2, MINUTE));
        assert!(limiter.check("cv:acct:alice", 2, MINUTE));
        assert!(
            !limiter.check("cv:acct:alice", 2, MINUTE),
            "the third request is over a ceiling of two"
        );
        assert!(
            limiter.check("cv:acct:bob", 2, MINUTE),
            "a separate key has its own budget"
        );
    }

    /// Each quota gets its own limiter.
    ///
    /// The point of the registry. Before it, one instance-wide quota
    /// answered for every caller, so a route asking for 20 per hour got
    /// whatever the per-IP limiter had been built with. On an instance
    /// with no Redis configured that was not a degraded mode, it was the
    /// only behaviour there was.
    #[test]
    fn each_quota_is_enforced_separately() {
        let limiter = FallbackRateLimiter::new();

        // Exhaust a tight ceiling.
        assert!(limiter.check("k", 1, MINUTE));
        assert!(!limiter.check("k", 1, MINUTE));

        // The same key under a different quota is a different bucket,
        // and the generous ceiling is honoured rather than the tight one.
        for i in 0..10 {
            assert!(
                limiter.check("k", 50, MINUTE),
                "request {i} under a ceiling of fifty"
            );
        }

        // And the tight one is still exhausted.
        assert!(!limiter.check("k", 1, MINUTE));
    }

    /// A quota governor cannot represent denies rather than panicking.
    ///
    /// Configuration is validated at startup, so this is unreachable
    /// from `noombat.toml`. It is reachable from a caller passing a
    /// constant, which is the case that would otherwise take the process
    /// down at run time rather than at boot.
    #[test]
    fn an_impossible_quota_denies() {
        let limiter = FallbackRateLimiter::new();

        assert!(!limiter.check("k", 0, MINUTE), "a ceiling of zero");
        assert!(!limiter.check("k", 10, Duration::ZERO), "a zero window");
    }
}
