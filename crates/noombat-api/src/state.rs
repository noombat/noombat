// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared application state passed to all Axum handlers.

use std::sync::Arc;

use noombat_chat::admin_client::ChatmailAdminClient;
use noombat_core::envelope::EnvelopeKey;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::oauth_orcid::OrcidConfig;
use noombat_identity::session::SessionConfig;
use redis::aio::ConnectionManager;
use sqlx::PgPool;

use crate::rate_limit::FallbackRateLimiter;

/// Application-wide state, injected into Axum handlers via [`axum::extract::State`].
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub domain: String,
    /// Port the browser connects to.
    /// Consumed only by [`crate::middleware::websocket_origin`], which
    /// appends it for a local domain carrying no port of its own. A
    /// production deployment sits behind a TLS terminator on 443, so the
    /// value is ignored there.
    pub public_port: u16,
    pub http_client: reqwest::Client,
    pub open_registrations: bool,
    /// Development-only bearer token for C2S outbox POST!
    /// To be replaced by full authentication!
    pub admin_token: Option<String>,
    /// Search backend (default: Meilisearch).
    pub search: Option<Arc<dyn noombat_core::extension::SearchBackend>>,
    /// Instance-level feature flags exposed via NodeInfo.
    pub nodeinfo_features: NodeInfoFeatures,
    /// Redis connection (optional). Used for rate limiting and
    /// session storage. `None` when `NOOMBAT_REDIS_URL` is not
    /// configured.
    pub redis: Option<ConnectionManager>,
    /// Session (JWT) configuration. `None` when the JWT secret is
    /// not configured (disables session-based auth).
    pub session_config: Option<SessionConfig>,
    /// ORCID OAuth configuration. `None` when ORCID client
    /// credentials are not configured.
    pub orcid_config: Option<OrcidConfig>,
    /// Chatmail domain (e.g. `chat.noombat.social`). `None` when
    /// chat is not configured.
    pub chatmail_domain: Option<String>,
    /// Chatmail admin sidecar REST API URL (internal-only).
    pub chatmail_admin_url: Option<String>,
    /// Shared secret for authenticating requests to the admin sidecar.
    pub chatmail_admin_secret: Option<String>,
    /// Pre-constructed HTTP client for the Chatmail admin sidecar.
    /// `None` when the sidecar URL or secret is not configured.
    pub chatmail_admin_client: Option<ChatmailAdminClient>,
    /// Administrative contact email address, used as the `mailto`
    /// parameter for the CrossRef polite pool (DOI resolution and
    /// ORCID import). Defaults to `"admin@{domain}"` when not
    /// explicitly configured via `NOOMBAT_CONTACT_EMAIL`.
    pub contact_email: String,
    /// Trending hashtags cache, updated by the background worker.
    pub trending_cache: Option<crate::trending::TrendingCache>,
    /// Analytics backend (default: PostgreSQL counters).
    pub analytics: Option<Arc<dyn noombat_core::extension::AnalyticsBackend>>,
    /// Relay verification policy in effect for this instance.
    pub relay_verification_policy: Option<String>,
    /// Envelope-encryption key for secrets at rest (TOTP secrets,
    /// private keys). `None` in development when `NOOMBAT_KEK` is
    /// not set.
    pub envelope_key: Option<Arc<EnvelopeKey>>,
    /// In-process rate limiter used when Redis is unavailable or
    /// unconfigured, preventing fail-open bypass. Shared by every call
    /// site: it holds one governor limiter per distinct quota, so each
    /// caller's ceiling is still its own.
    pub fallback_rate_limiter: FallbackRateLimiter,
    /// Per-IP rate limit ceiling (Redis primary).
    pub rate_limit: i64,
    /// Per-IP rate limit window in seconds (Redis primary).
    pub rate_limit_window_secs: i64,
    /// Per-domain federation rate limit ceiling (Redis primary).
    pub fed_rate_limit: i64,
    /// Per-domain federation rate limit window in seconds (Redis primary).
    pub fed_rate_limit_window_secs: i64,
    /// CV downloads allowed per requester per window. Far below the
    /// instance-wide limit, because each one spawns a Typst compilation.
    pub cv_download_limit: i64,
    /// Window for [`Self::cv_download_limit`], in seconds.
    pub cv_download_window_secs: i64,
    /// Days between a deletion request and the erasure that completes
    /// it. Quoted to the user by the deletion API and acted on by the
    /// erasure worker, from this one value.
    pub deletion_grace_days: i32,
    /// Whether signed-fetch failures fall back to unsigned GET
    /// (default `false`).
    pub allow_unsigned_fetch: bool,
}
