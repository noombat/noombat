// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Noombat server entry point.
//!
//! Loads configuration, runs migrations, spawns the delivery-queue worker,
//! and starts the Axum HTTP listener.

mod cedar;
mod meilisearch;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use noombat_api::state::AppState;

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
    /// Path to the Cedar policies directory (default `policies`).
    #[serde(default = "default_policies_dir")]
    policies_dir: String,
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
fn default_policies_dir() -> String {
    "policies".to_owned()
}
fn default_reverify_interval() -> u64 {
    3600
}
fn default_reverify_max_age() -> i32 {
    7
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
    let http_client = reqwest::Client::builder()
        .user_agent(format!("Noombat/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    // Spawn the delivery-queue background worker.
    {
        let pool = pool.clone();
        let client = http_client.clone();
        tokio::spawn(async move {
            loop {
                noombat_federation::delivery::process_queue(&pool, &client).await;
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
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
                    Ok(count) if count > 0 => {
                        info!(count, "re-verified stale links");
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

    // Build the Axum application.
    let policies_dir = std::path::Path::new(&config.policies_dir);
    let policy_path = policies_dir.join("noombat.cedar");
    let schema_path = policies_dir.join("noombat.cedarschema");

    let auth_backend = if policy_path.exists() {
        let schema_opt = if schema_path.exists() {
            Some(schema_path.as_path())
        } else {
            None
        };
        match cedar::load_cedar_backend(&policy_path, schema_opt) {
            Ok(backend) => {
                info!(
                    "Cedar authorisation backend loaded from {}",
                    policies_dir.display()
                );
                Arc::new(backend) as Arc<dyn noombat_core::auth::AuthorisationBackend>
            }
            Err(e) => {
                panic!("failed to load Cedar policies: {e}");
            }
        }
    } else {
        info!(
            "no Cedar policies found at {}; using empty policy set",
            policy_path.display()
        );
        Arc::new(cedar::CedarBackend::new("", None).expect("failed to create empty Cedar backend"))
            as Arc<dyn noombat_core::auth::AuthorisationBackend>
    };

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

    let state = AppState {
        pool,
        domain: config.domain.clone(),
        http_client,
        open_registrations: config.open_registrations,
        admin_token: config.admin_token.clone(),
        auth: auth_backend,
        search,
    };
    let app = noombat_api::build_router(state);

    // Bind and serve.
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("server shut down");
    Ok(())
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
