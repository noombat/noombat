// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Noombat server entry point.
//!
//! Loads configuration, runs migrations, spawns the delivery-queue worker,
//! and starts the Axum HTTP listener.

mod meilisearch;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::envelope::EnvelopeKey;

/// Top-level configuration, loaded from `noombat.toml` and environment
/// variables prefixed with `NOOMBAT_`.
#[derive(Debug, Deserialize)]
struct Config {
    /// Instance domain (e.g. `noombat.social`).
    domain: String,
    /// PostgreSQL connection URL.
    database_url: String,
    /// Listen address (default `0.0.0.0`).
    #[serde(default = "default_host")]
    host: String,
    /// Listen port (default `8443`).
    #[serde(default = "default_port")]
    port: u16,
    /// Maximum database connections (default `10`).
    #[serde(default = "default_max_connections")]
    max_connections: u32,
    /// Whether open registration is enabled (default `true`).
    #[serde(default = "default_true")]
    open_registrations: bool,
    /// Development-only bearer token for C2S outbox POST!
    /// If unset, the outbox POST endpoint is disabled.
    admin_token: Option<String>,
    /// Meilisearch base URL (e.g. `http://localhost:7700`).
    /// If unset, full-text search is disabled.
    meili_url: Option<String>,
    /// Meilisearch API key (optional).
    meili_key: Option<String>,
    /// Interval in seconds between link re-verification sweeps (default 3600).
    #[serde(default = "default_reverify_interval")]
    link_reverify_interval_secs: u64,
    /// Maximum age in days before a verified link is re-checked (default 7).
    #[serde(default = "default_reverify_max_age")]
    link_max_age_days: i32,
    /// Whether the Chatmail sidecar is deployed (default `false`).
    #[serde(default)]
    chatmail_available: bool,
    /// Chatmail domain (e.g. `chat.noombat.social`).
    chatmail_domain: Option<String>,
    /// Chatmail admin sidecar REST API URL (internal-only).
    chatmail_admin_url: Option<String>,
    /// Shared secret for authenticating requests to the admin sidecar.
    chatmail_admin_secret: Option<String>,
    /// Administrative contact email address, used as the `mailto`
    /// parameter for the CrossRef polite pool. Defaults to
    /// `admin@{domain}` when not explicitly set.
    contact_email: Option<String>,
    /// Whether group support is enabled (default `false`).
    #[serde(default)]
    groups_enabled: bool,
    /// Whether event support is enabled (default `false`).
    #[serde(default)]
    events_enabled: bool,
    /// Whether article (long-form post) support is enabled (default `false`).
    #[serde(default)]
    articles_enabled: bool,
    /// Redis connection URL (e.g. `redis://redis:6379`).
    /// If unset, rate limiting and session storage are disabled.
    redis_url: Option<String>,
    /// JWT signing secret for session tokens (HS256). Must be at
    /// least 32 bytes. If unset, session-based auth is disabled.
    jwt_secret: Option<String>,
    /// Access-token lifetime in seconds (default: 900 = 15 min).
    #[serde(default = "default_access_ttl")]
    access_ttl_secs: i64,
    /// Refresh-token lifetime in seconds (default: 2592000 = 30 days).
    #[serde(default = "default_refresh_ttl")]
    refresh_ttl_secs: i64,
    /// ORCID OAuth client ID.
    orcid_client_id: Option<String>,
    /// ORCID OAuth client secret.
    orcid_client_secret: Option<String>,
    /// Whether FEP-8b32 integrity proofs (`eddsa-jcs-2022`) are
    /// attached to all outbound activities (default `true`).
    #[serde(default = "default_true")]
    integrity_proofs_enabled: bool,
    /// Relay verification policy: `verify`, `verify-or-fetch`, or
    /// `trust-relay`. `None` when relay support is not activated.
    relay_verification_policy: Option<String>,
    /// Whether signed-fetch failures (missing key or signing error)
    /// silently fall back to unsigned HTTP GET. `false` by default
    /// (recommended for production). Set to `true` only when
    /// federating with implementations that reject signed fetches.
    #[serde(default)]
    allow_unsigned_fetch: bool,
    /// Hex-encoded 256-bit key-encryption key (KEK) for envelope
    /// encryption of secrets at rest. 64 hex characters (32 bytes).
    /// Required in production; if unset, secrets are stored as
    /// plaintext (development mode only).
    kek: Option<String>,
}

fn default_host() -> String {
    "0.0.0.0".to_owned()
}
fn default_port() -> u16 {
    8443
}
fn default_max_connections() -> u32 {
    10
}
fn default_true() -> bool {
    true
}
fn default_reverify_interval() -> u64 {
    3600
}
fn default_reverify_max_age() -> i32 {
    7
}
fn default_access_ttl() -> i64 {
    900
}
fn default_refresh_ttl() -> i64 {
    2_592_000
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env (if present) before reading configuration.
    let _ = dotenvy::dotenv();

    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,noombat=debug,tower_http=debug")),
        )
        .init();

    // Merge configuration: file to environment variables.
    let config: Config = Figment::new()
        .merge(Toml::file("noombat.toml"))
        .merge(Env::prefixed("NOOMBAT_"))
        .extract()
        .expect("failed to load configuration");

    info!(domain = %config.domain, "starting Noombat server");

    // ..... Production guard rails .....
    //
    // When the domain is not `localhost`, verify that security-
    // critical values are not equal to their documented defaults.
    validate_production_config(&config);

    // ..... Envelope encryption key .....
    //
    // Parse the hex-encoded KEK (if configured) and initialise the
    // process-global envelope key.
    let envelope_key: Option<Arc<EnvelopeKey>> = match config.kek.as_deref() {
        Some(hex) => {
            let key = EnvelopeKey::from_hex(hex)
                .expect("NOOMBAT_KEK must be 64 hex characters (32 bytes)");
            info!("envelope encryption enabled (KEK configured)");
            Some(Arc::new(key))
        }
        None => {
            info!("no NOOMBAT_KEK configured; envelope encryption disabled (dev-only)");
            None
        }
    };
    // Initialise the process-global key so that `seal_auto` and `open_auto`
    // work from any crate without explicit key threading. Clone out of
    // the Arc for the static; the Arc itself is stored in AppState.
    noombat_core::envelope::init(envelope_key.as_deref().cloned());

    // Database connection pool.
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .expect("failed to connect to PostgreSQL");

    // Run pending migrations.
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("failed to run database migrations");

    info!("database migrations applied");

    // HTTP client for federation delivery.
    //
    // NOTE: `discover_instance` in `noombat_identity::oauth_mastodon`
    // builds a separate pinned client for SSRF protection and
    // replicates the `user_agent` and `timeout` settings below. If
    // these defaults change, update that function to match.
    let http_client = reqwest::Client::builder()
        .user_agent(format!("Noombat/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    // Set the process-global unsigned-fetch policy before any
    // federation activity is processed.
    noombat_federation::signed_fetch::set_allow_unsigned_fetch(config.allow_unsigned_fetch);
    if config.allow_unsigned_fetch {
        info!("unsigned-fetch fallback enabled (not recommended for production)");
    }

    // Spawn the delivery-queue background worker.
    //
    // Uses PostgreSQL LISTEN/NOTIFY for near-instant dispatch when new
    // activities are enqueued, with a 30s polling fallback as a
    // safety net.
    {
        let pool = pool.clone();
        let client = http_client.clone();
        tokio::spawn(async move {
            noombat_federation::delivery::run_worker(pool, client, Duration::from_secs(30)).await;
        });
    }

    // Spawn the link re-verification background worker.
    {
        let pool = pool.clone();
        let client = http_client.clone();
        let domain = config.domain.clone();
        let interval = Duration::from_secs(config.link_reverify_interval_secs);
        let max_age = config.link_max_age_days;
        tokio::spawn(async move {
            loop {
                match noombat_identity::verification::reverify_stale_links(
                    &pool, &client, &domain, max_age,
                )
                .await
                {
                    Ok(changed) if !changed.is_empty() => {
                        info!(
                            count = changed.len(),
                            "re-verification sweep: links changed state"
                        );
                        // Broadcast an Update activity for each actor
                        // whose verification state changed, so that
                        // followers refresh their cached profile.
                        for actor_id in &changed {
                            match noombat_identity::repo::find_by_id(&pool, *actor_id).await {
                                Ok(actor) => {
                                    noombat_federation::update::enqueue_actor_update(
                                        &pool, &actor, &domain,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        %actor_id,
                                        error = %e,
                                        "failed to fetch actor for Update after re-verification"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("link re-verification sweep failed: {e}");
                    }
                    _ => {}
                }
                tokio::time::sleep(interval).await;
            }
        });
    }

    // ..... Build the Axum application .....

    // Meilisearch search backend (optional).
    let search: Option<Arc<dyn noombat_core::extension::SearchBackend>> =
        if let Some(ref meili_url) = config.meili_url {
            match meilisearch::MeilisearchBackend::new(meili_url, config.meili_key.as_deref()) {
                Ok(backend) => {
                    if let Err(e) = backend.ensure_indices().await {
                        tracing::warn!("Meilisearch index setup failed (search degraded): {e}");
                    } else {
                        info!(url = %meili_url, "Meilisearch search backend connected");
                    }
                    Some(Arc::new(backend))
                }
                Err(e) => {
                    tracing::warn!("Meilisearch client init failed (search disabled): {e}");
                    None
                }
            }
        } else {
            info!("no NOOMBAT_MEILI_URL configured; full-text search disabled");
            None
        };

    // Redis connection (optional).
    let redis: Option<redis::aio::ConnectionManager> = if let Some(ref redis_url) = config.redis_url
    {
        match redis::Client::open(redis_url.as_str()) {
            Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                Ok(mgr) => {
                    info!(url = %redis_url, "Redis connection established");
                    Some(mgr)
                }
                Err(e) => {
                    tracing::warn!("Redis connection failed (rate limiting disabled): {e}");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("invalid Redis URL (rate limiting disabled): {e}");
                None
            }
        }
    } else {
        info!("no NOOMBAT_REDIS_URL configured; rate limiting disabled");
        None
    };

    // Session configuration (optional).
    let session_config = config.jwt_secret.as_ref().map(|secret| {
        info!("JWT session authentication enabled");
        noombat_identity::session::SessionConfig {
            jwt_secret: secret.clone(),
            domain: config.domain.clone(),
            access_ttl_secs: config.access_ttl_secs,
            refresh_ttl_secs: config.refresh_ttl_secs,
        }
    });
    if session_config.is_none() {
        info!(
            "no NOOMBAT_JWT_SECRET configured; session-based auth disabled (dev-only bearer token active)"
        );
    }

    // ORCID configuration (optional).
    let orcid_config = match (&config.orcid_client_id, &config.orcid_client_secret) {
        (Some(id), Some(secret)) => {
            info!("ORCID OAuth enabled");
            Some(noombat_identity::oauth_orcid::OrcidConfig {
                client_id: id.clone(),
                client_secret: secret.clone(),
                ..Default::default()
            })
        }
        _ => {
            info!("ORCID OAuth not configured (Sign in with ORCID disabled)");
            None
        }
    };

    // Pre-construct shared resources before AppState consumes pool.
    let trending_cache = noombat_api::trending::TrendingCache::new();
    let analytics_backend: Option<Arc<dyn noombat_core::extension::AnalyticsBackend>> =
        Some(Arc::new(noombat_api::analytics::PgAnalyticsBackend::new(
            pool.clone(),
        )));
    // Clone pool for the trending worker (spawned after AppState is built).
    let trending_pool = pool.clone();
    let trending_cache_for_worker = trending_cache.clone();

    // In-process fallback rate limiters.
    // Activated when Redis is unavailable; prevent fail-open bypass.
    let fallback_rate_limiter = FallbackRateLimiter::new(120); // 120 req/min per IP
    let fallback_fed_rate_limiter = FallbackRateLimiter::new(300); // 300 req/min per domain

    let state = AppState {
        pool,
        domain: config.domain.clone(),
        http_client,
        open_registrations: config.open_registrations,
        admin_token: config.admin_token.clone(),
        search,
        nodeinfo_features: noombat_federation::nodeinfo::NodeInfoFeatures {
            chatmail_available: config.chatmail_available,
            chatmail_domain: config.chatmail_domain.clone(),
            groups_enabled: config.groups_enabled,
            events_enabled: config.events_enabled,
            articles_enabled: config.articles_enabled,
            integrity_proofs_enabled: config.integrity_proofs_enabled,
            relay_verification_policy: config.relay_verification_policy.clone(),
        },
        redis,
        session_config,
        orcid_config,
        chatmail_domain: config.chatmail_domain.clone(),
        chatmail_admin_url: config.chatmail_admin_url.clone(),
        chatmail_admin_secret: config.chatmail_admin_secret.clone(),
        chatmail_admin_client: noombat_chat::admin_client::ChatmailAdminClient::new(
            config.chatmail_admin_url.as_deref(),
            config.chatmail_admin_secret.as_deref(),
        ),
        contact_email: config
            .contact_email
            .clone()
            .unwrap_or_else(|| format!("admin@{}", config.domain)),
        trending_cache: Some(trending_cache),
        analytics: analytics_backend,
        relay_verification_policy: config.relay_verification_policy.clone(),
        envelope_key,
        fallback_rate_limiter,
        fallback_fed_rate_limiter,
        allow_unsigned_fetch: config.allow_unsigned_fetch,
    };
    let app = noombat_api::build_router(state);

    // Spawn the trending hashtags background worker.
    tokio::spawn(async move {
        noombat_api::trending::run_worker(
            trending_pool,
            trending_cache_for_worker,
            Duration::from_secs(300), // recompute every 5 minutes
            24,                       // 24-hour rolling window
            20,                       // top 20 tags
        )
        .await;
    });

    // Bind and serve.
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("server shut down");
    Ok(())
}

// ..... Production guard rails .....

/// Known-insecure default values that must not reach production.
const INSECURE_ADMIN_TOKEN: &str = "noombat";
const INSECURE_DB_CRED: &str = "noombat:noombat";
const INSECURE_MEILI_KEY: &str = "noombat-dev-key";
const INSECURE_CHATMAIL_SECRET: &str = "noombat-chatmail-dev-secret";

/// Minimum acceptable length for the JWT signing secret (HS256).
const MIN_JWT_SECRET_LEN: usize = 32;

/// Validate that security-critical configuration values are not set
/// to their documented defaults when the domain is not `localhost`.
///
/// Emits `error!`-level log messages and aborts the process on
/// violation.
fn validate_production_config(config: &Config) {
    // Development: skip all checks.
    if config.domain == "localhost" || config.domain.starts_with("localhost:") {
        return;
    }

    let mut fatal = false;

    match config.jwt_secret.as_deref() {
        None => {
            error!(
                "NOOMBAT_JWT_SECRET is not set. \
                 Session-based authentication is disabled; only the \
                 admin_token bearer is available. This is not safe \
                 for production."
            );
            fatal = true;
        }
        Some(s) if s.len() < MIN_JWT_SECRET_LEN => {
            error!(
                "NOOMBAT_JWT_SECRET is too short ({len} bytes, \
                 minimum {MIN_JWT_SECRET_LEN}). Use a secret of at \
                 least {MIN_JWT_SECRET_LEN} bytes (generate with: \
                 openssl rand -base64 48).",
                len = s.len(),
                MIN_JWT_SECRET_LEN = MIN_JWT_SECRET_LEN
            );
            fatal = true;
        }
        Some(_) => {}
    }

    if config.admin_token.as_deref() == Some(INSECURE_ADMIN_TOKEN) {
        error!(
            "NOOMBAT_ADMIN_TOKEN is set to the documented default \
             (\"{token}\"). Change it to a random value or remove \
             it entirely in production.",
            token = INSECURE_ADMIN_TOKEN
        );
        fatal = true;
    }

    if config.database_url.contains(INSECURE_DB_CRED) {
        error!(
            "DATABASE_URL contains the default credential \
             \"{cred}\". Use a strong, unique password in production.",
            cred = INSECURE_DB_CRED
        );
        fatal = true;
    }

    if config.meili_key.as_deref() == Some(INSECURE_MEILI_KEY) {
        error!(
            "NOOMBAT_MEILI_KEY is set to the documented default \
             (\"{key}\"). Set MEILI_MASTER_KEY to a random value.",
            key = INSECURE_MEILI_KEY
        );
        fatal = true;
    }

    if config.chatmail_admin_secret.as_deref() == Some(INSECURE_CHATMAIL_SECRET) {
        error!(
            "NOOMBAT_CHATMAIL_ADMIN_SECRET is set to the documented \
             default (\"{secret}\"). Set CHATMAIL_ADMIN_SECRET to a \
             random value.",
            secret = INSECURE_CHATMAIL_SECRET
        );
        fatal = true;
    }

    if config.kek.is_none() {
        error!(
            "NOOMBAT_KEK is not set. TOTP secrets and private keys \
             will be stored as plaintext. Set a 64-character hex key \
             (generate with: openssl rand -hex 32)."
        );
        fatal = true;
    }

    if fatal {
        error!(
            "aborting: one or more insecure configuration defaults \
             detected with domain = \"{domain}\". Fix the values \
             above or set domain = \"localhost\" for local \
             development.",
            domain = config.domain
        );
        std::process::exit(1);
    }
}

/// Wait for SIGINT or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C"),
        _ = terminate => info!("received SIGTERM"),
    }
}
