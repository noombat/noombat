// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Chatmail relay administration sidecar daemon.
//!
//! Exposes a private REST API on an internal-only network interface
//! for account lifecycle operations required by Noombat's moderation
//! layer: password rotation, session termination (`doveadm kick`),
//! maildir deletion, and Postfix access map management.
//!
//! All endpoints are served under the `/admin/v1/` path prefix.

mod access_maps;
mod allowlist;
mod config;
mod password;
mod router;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = config::Config::from_env();
    let addr: SocketAddr = format!("{}:{}", config.listen_host, config.listen_port)
        .parse()
        .expect("invalid listen address");

    // Load or initialise access maps from persistent storage.
    let maps = access_maps::AccessMaps::load_or_init(&config.access_maps_path);
    let state = Arc::new(AppState {
        config,
        maps: Mutex::new(maps),
        last_reload: Mutex::new(std::time::Instant::now()),
    });

    // Write the initial Postfix maps on startup.
    if let Ok(ref maps) = state.maps.lock() {
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(&state);

    // Start the allowlist synchronisation polling thread.
    allowlist::start_polling(Arc::clone(&state));

    info!(%addr, "noombat-chatmail-admin listening");

    let server = tiny_http::Server::http(addr).expect("failed to bind HTTP server");

    for request in server.incoming_requests() {
        let state = Arc::clone(&state);
        // The sole client is the co-located Noombat application server,
        // issuing requests only on moderator-initiated actions (suspension,
        // unsuspension, account deletion, per-pair sender blocks). The rate
        // is at most a few requests per hour; a thread pool is unnecessary.
        router::handle_request(request, &state);
    }
}

/// Shared state for the sidecar daemon.
pub struct AppState {
    pub config: config::Config,
    pub maps: Mutex<access_maps::AccessMaps>,
    /// Debounce tracking for Postfix reloads.
    pub last_reload: Mutex<std::time::Instant>,
}

/// Trigger a debounced `postfix reload`.
///
/// If the last reload was fewer than `reload_debounce_secs` ago, the
/// reload is skipped (the next map-modifying operation will trigger
/// it). This coalesces rapid successive reloads during bulk
/// operations.
pub fn trigger_postfix_reload_debounced(state: &AppState) {
    let debounce = std::time::Duration::from_secs(state.config.reload_debounce_secs);
    let mut last = state.last_reload.lock().unwrap_or_else(|e| e.into_inner());

    if last.elapsed() < debounce {
        tracing::debug!("postfix reload debounced (last reload {:.1?} ago)", last.elapsed());
        return;
    }

    let status = std::process::Command::new("postfix")
        .arg("reload")
        .status();
    match status {
        Ok(s) if s.success() => {
            info!("postfix reload succeeded");
            *last = std::time::Instant::now();
        }
        Ok(s) => tracing::warn!("postfix reload exited with status {s}"),
        Err(e) => tracing::warn!("postfix reload failed: {e}"),
    }
}
