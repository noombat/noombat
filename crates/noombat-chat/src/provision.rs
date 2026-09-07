// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Chatmail account provisioning through the admin sidecar.
//!
//! The sidecar creates the account and owns the password; the IMAP login
//! below is a check that it works, not what brings it into being. The
//! relay's checkpassword helper answers before anybody has authenticated,
//! so anything it created would be created for whoever asked.

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

/// Provision `username@chatmail_domain`, then verify it with one login.
///
/// The password comes back from the sidecar rather than being generated
/// here. Both sides have a generator, and using this one would hand the
/// caller a password the relay's file does not hold, so every login
/// would fail with nothing to explain it.
pub async fn provision_chatmail_account(
    admin: &crate::admin_client::ChatmailAdminClient,
    chatmail_domain: &str,
    username: &str,
) -> Result<ProvisionedAccount> {
    let address = format!("{username}@{chatmail_domain}");
    let created = admin.create_account(&address).await?;
    let password = created.password;

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

    // A check, not a creation: the account already exists. A failure
    // here means the sidecar wrote something the relay cannot read, which
    // is most likely file ownership.
    let mut session = client.login(&address, &password).await.map_err(|(e, _)| {
        NoombatError::Internal(format!(
            "IMAP login for {address} failed after the sidecar created it: {e}"
        ))
    })?;

    // Logout cleanly.
    let _ = session.logout().await;

    info!(address = %address, "Chatmail account provisioned");

    Ok(ProvisionedAccount { address, password })
}
