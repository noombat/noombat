// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Chatmail account provisioning via IMAP first-login.
//!
//! Chatmail auto-creates accounts on first IMAP login. This module
//! generates a random Chatmail password, performs the first-login
//! IMAP connection, and returns the provisioned address and password.

use noombat_core::error::{NoombatError, Result};
use tracing::info;

use crate::session;

/// The result of a successful Chatmail account provisioning.
#[derive(Debug)]
pub struct ProvisionedAccount {
    /// The full Chatmail address (e.g. `alice@chat.noombat.social`).
    pub address: String,
    /// The generated Chatmail password.
    pub password: String,
}

/// Provision a Chatmail account by performing a first-login IMAP
/// connection.
///
/// Chatmail auto-creates the account on first login. The function
/// generates a random password, connects via IMAP, authenticates
/// (which triggers account creation), and returns the credentials.
///
/// The address is `username@chatmail_domain`, e.g.
/// `alice@chat.noombat.social`.
pub async fn provision_chatmail_account(
    chatmail_domain: &str,
    username: &str,
) -> Result<ProvisionedAccount> {
    let address = format!("{username}@{chatmail_domain}");
    let password = generate_chatmail_password();

    // Establish a TCP connection to the Chatmail IMAP server
    // (port 993, implicit TLS).
    let tcp_stream = tokio::net::TcpStream::connect((chatmail_domain, 993_u16))
        .await
        .map_err(|e| {
            NoombatError::Internal(format!(
                "TCP connection to {chatmail_domain}:993 failed: {e}"
            ))
        })?;

    // Wrap the TCP stream in TLS via tokio-rustls.
    let tls_connector = session::build_tls_connector();
    let server_name =
        rustls_pki_types::ServerName::try_from(chatmail_domain.to_owned()).map_err(|e| {
            NoombatError::Internal(format!("invalid server name {chatmail_domain}: {e}"))
        })?;
    let tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| {
            NoombatError::Internal(format!(
                "TLS handshake with {chatmail_domain}:993 failed: {e}"
            ))
        })?;

    // Create the async-imap client over the TLS stream. The
    // `runtime-tokio` feature of async-imap accepts
    // `tokio::io::AsyncRead + AsyncWrite` directly, matching the
    // types provided by `tokio-rustls`.
    let client = async_imap::Client::new(tls_stream);

    // Login triggers account auto-creation on Chatmail.
    let mut session = client.login(&address, &password).await.map_err(|(e, _)| {
        NoombatError::Internal(format!(
            "IMAP login for {address} failed (account provisioning): {e}"
        ))
    })?;

    // Logout cleanly.
    let _ = session.logout().await;

    info!(address = %address, "Chatmail account provisioned");

    Ok(ProvisionedAccount { address, password })
}

/// Generate a random password suitable for Chatmail (24 bytes,
/// base64url-encoded, no padding).
fn generate_chatmail_password() -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut buf = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}
