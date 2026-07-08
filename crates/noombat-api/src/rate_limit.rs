// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Per-IP fixed-window rate-limit middleware backed by Redis.
//!
//! Uses an atomic Lua script (`INCR` + conditional `EXPIRE` + `TTL`)
//! to enforce a maximum number of requests per fixed window per remote
//! IP address. The script executes as a single Redis transaction,
//! eliminating the race condition that would arise from separate
//! `INCR` and `EXPIRE` commands (a crash between the two could leave
//! a key without a TTL, permanently rate-limiting the affected IP).
//!
//! When Redis is not configured (`AppState.redis` is `None`), or when
//! a Redis command fails transiently, requests pass through without
//! rate limiting (open-fail).

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::RETRY_AFTER;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::warn;

use crate::state::AppState;

/// Maximum requests per window.
const DEFAULT_LIMIT: i64 = 120;
/// Window size in seconds.
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

/// Axum middleware that enforces a per-IP rate limit via Redis.
///
/// If Redis is not configured, or if a Redis command fails transiently,
/// the request is allowed through (open-fail). This ensures that a
/// Redis outage does not render the entire instance unavailable.
///
/// Rate-limited responses carry a `Retry-After` header indicating the
/// number of seconds until the current window expires (RFC 9110).
pub async fn rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(mut redis) = state.redis.clone() else {
        return next.run(request).await;
    };

    // Extract the remote IP from the `ConnectInfo<SocketAddr>`
    // extension inserted by `into_make_service_with_connect_info`.
    let ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());

    let key = format!("rl:{ip}");

    let result: Vec<i64> = match redis::cmd("EVAL")
        .arg(RATE_LIMIT_LUA)
        .arg(1i64)
        .arg(&key)
        .arg(DEFAULT_WINDOW_SECS)
        .query_async(&mut redis)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Redis EVAL failed (rate limiting degraded): {e}");
            return next.run(request).await;
        }
    };

    let count = result.first().copied().unwrap_or(0);
    let ttl = result.get(1).copied().unwrap_or(DEFAULT_WINDOW_SECS);

    if count > DEFAULT_LIMIT {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, ttl.max(1).to_string())],
        )
            .into_response();
    }

    next.run(request).await
}
