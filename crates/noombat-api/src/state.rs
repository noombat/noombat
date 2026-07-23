// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared application state passed to all Axum handlers.

use std::sync::Arc;

use noombat_chat::admin_client::ChatmailAdminClient;
use noombat_core::auth::AuthorisationBackend;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::oauth_orcid::OrcidConfig;
use noombat_identity::session::SessionConfig;
use redis::aio::ConnectionManager;
use sqlx::PgPool;

/// Application-wide state, injected into Axum handlers via [`axum::extract::State`].
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub domain: String,
    pub http_client: reqwest::Client,
    pub open_registrations: bool,
    /// Development-only bearer token for C2S outbox POST!
    /// To be replaced by full authentication!
    pub admin_token: Option<String>,
    /// Authorisation backend (default: Cedar).
    pub auth: Arc<dyn AuthorisationBackend>,
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
}
