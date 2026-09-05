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

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// A TCP listener that completes a TLS handshake before yielding a
/// connection.
///
/// `axum::serve` accepts anything implementing [`axum::serve::Listener`],
/// which is the whole extension point needed here: the alternative,
/// `axum-server`, brings `rustls-pemfile` and an unmaintained advisory
/// with it.
struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    /// A failed handshake must not end the loop.
    ///
    /// The trait cannot report one: it returns a connection, not a
    /// result. That is the right shape, because a peer offering a
    /// certificate this server will not accept is an ordinary event on a
    /// public port, and treating it as fatal would let anybody stop the
    /// sidecar by connecting to it.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = match self.tcp.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    warn!(error = %e, "admin API could not accept a connection");
                    continue;
                }
            };
            match self.acceptor.clone().accept(stream).await {
                Ok(tls) => return (tls, peer),
                Err(e) => warn!(%peer, error = %e, "admin API TLS handshake failed"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Read the certificate and key, refusing to start without them.
///
/// Every request to this daemon carries the admin secret as a bearer
/// token, and a plaintext listener puts that token on the wire. Falling
/// back to HTTP when the certificate is unreadable would mean a
/// misconfigured deployment quietly downgrading to the exact thing this
/// exists to prevent, so a missing or unusable file is fatal here.
///
/// Safe to be fatal: the container's entrypoint has already refused to
/// start without a certificate at this path, or generated one for a
/// development domain, before s6 supervises this service.
fn tls_acceptor(config: &config::Config) -> TlsAcceptor {
    let cert_path = &config.tls_cert_path;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .unwrap_or_else(|e| panic!("cannot read {cert_path}: {e}"))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| panic!("{cert_path} holds an unreadable certificate: {e}"));

    let key = PrivateKeyDer::from_pem_file(&config.tls_key_path)
        .unwrap_or_else(|e| panic!("cannot read the key at {}: {e}", config.tls_key_path));

    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap_or_else(|e| panic!("the admin API's certificate and key do not match: {e}"));

    TlsAcceptor::from(Arc::new(server))
}

#[tokio::main]
async fn main() {
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

    let acceptor = tls_acceptor(&state.config);
    let tcp = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("the admin API could not bind {addr}: {e}"));

    info!(%addr, "noombat-chatmail-admin listening over TLS");

    axum::serve(TlsListener { tcp, acceptor }, router::router(state))
        .await
        .unwrap_or_else(|e| panic!("the admin API stopped serving on {addr}: {e}"));
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
        tracing::debug!(
            "postfix reload debounced (last reload {:.1?} ago)",
            last.elapsed()
        );
        return;
    }

    let status = std::process::Command::new("postfix").arg("reload").status();
    match status {
        Ok(s) if s.success() => {
            info!("postfix reload succeeded");
            *last = std::time::Instant::now();
        }
        Ok(s) => tracing::warn!("postfix reload exited with status {s}"),
        Err(e) => tracing::warn!("postfix reload failed: {e}"),
    }
}
