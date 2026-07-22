// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! IMAP/SMTP session management for the Chatmail relay.
//!
//! This module provides the low-level IMAP and SMTP operations used
//! by the WebSocket relay handler in `noombat-api`. All Chatmail
//! protocol interaction, i.e. TLS connector construction, IMAP login,
//! message fetching, and SMTP submission, is concentrated here so
//! that the API layer delegates to `noombat-chat` rather than
//! depending on the IMAP/TLS/SMTP crates directly.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::mime_bridge;
use crate::relay::{RelayConfig, ServerMessage};

/// Type alias for the IMAP session over TLS.
pub type ImapSession = async_imap::Session<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// Build a `tokio-rustls` TLS connector using the Mozilla root
/// certificates (via `webpki-roots`).
///
/// This is shared by the provisioning flow ([`crate::provision`]) and
/// the relay session established here.
pub fn build_tls_connector() -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

/// Establish an IMAP session with the Chatmail relay and select
/// INBOX.
pub async fn connect_imap(
    tls_connector: &TlsConnector,
    config: &RelayConfig,
    address: &str,
    password: &str,
) -> Result<ImapSession, String> {
    let tcp = tokio::net::TcpStream::connect((&*config.imap_host, config.imap_port))
        .await
        .map_err(|e| format!("TCP connect failed: {e}"))?;

    let server_name = ServerName::try_from(config.imap_host.clone())
        .map_err(|e| format!("invalid server name: {e}"))?;

    let tls_stream = tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let client = async_imap::Client::new(tls_stream);

    let mut session = client
        .login(address, password)
        .await
        .map_err(|(e, _)| format!("IMAP login failed: {e}"))?;

    session
        .select("INBOX")
        .await
        .map_err(|e| format!("INBOX select failed: {e}"))?;

    Ok(session)
}

/// Fetch messages from the IMAP mailbox and return them as
/// [`ServerMessage::Message`] values.
///
/// `since_uid` of 0 means "all messages"; otherwise, messages with
/// UIDs strictly greater than `since_uid` are returned.
pub async fn fetch_messages(
    session: &mut ImapSession,
    since_uid: u32,
) -> Result<Vec<ServerMessage>, String> {
    let query = if since_uid == 0 {
        "1:*".to_owned()
    } else {
        format!("{}:*", since_uid + 1)
    };

    let messages = session
        .uid_fetch(&query, "(UID RFC822 INTERNALDATE)")
        .await
        .map_err(|e| format!("IMAP FETCH failed: {e}"))?;

    let mut result = Vec::new();

    use futures_lite::StreamExt;
    let mut stream = messages;
    while let Some(fetch_result) = stream.next().await {
        let fetch = match fetch_result {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, "IMAP fetch stream error");
                continue;
            }
        };

        let uid = match fetch.uid {
            Some(u) => u,
            None => continue,
        };

        let body = match fetch.body() {
            Some(b) => b,
            None => continue,
        };

        let from = mime_bridge::extract_from(body)
            .ok()
            .flatten()
            .unwrap_or_default();

        if from.is_empty() {
            continue;
        }

        let ciphertext = match mime_bridge::extract_ciphertext_body(body) {
            Ok(ct) => ct,
            Err(_) => continue,
        };

        let autocrypt_header = mime_bridge::extract_autocrypt_header(body).ok().flatten();

        let timestamp = fetch
            .internal_date()
            .map(|d| d.timestamp())
            .unwrap_or_else(|| chrono::Utc::now().timestamp());

        result.push(ServerMessage::Message {
            uid,
            from,
            body_b64: B64.encode(&ciphertext),
            autocrypt_header_b64: autocrypt_header.map(|h| B64.encode(h.header_value.as_bytes())),
            timestamp,
        });
    }

    Ok(result)
}

/// Send an encrypted message via SMTP.
///
/// Constructs a valid PGP/MIME message (RFC 3156: `multipart/encrypted`
/// with a `Version: 1` control part and the ciphertext payload) and
/// delivers it via SMTPS.
pub async fn send_message(
    config: &RelayConfig,
    from_addr: &str,
    password: &str,
    to_addr: &str,
    body_b64: &str,
    autocrypt_header_b64: Option<&str>,
) -> Result<(), String> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

    let ciphertext = B64
        .decode(body_b64)
        .map_err(|e| format!("invalid base64 body: {e}"))?;

    // Build the PGP/MIME message as raw RFC 2822 text.
    //
    // PGP/MIME (RFC 3156) requires a multipart/encrypted body with:
    //   Part 1: Content-Type: application/pgp-encrypted
    //           Body: "Version: 1"
    //   Part 2: Content-Type: application/octet-stream
    //           Body: the PGP-encrypted data
    //
    // lettre's Message builder does not support constructing this
    // two-part structure directly, so the raw MIME is assembled here.
    let boundary = format!("noombat-pgp-{:016x}", rand::random::<u64>());
    let date = chrono::Utc::now().to_rfc2822();

    let ciphertext_b64 = B64.encode(&ciphertext);
    // Wrap base64 at 76 characters per line per RFC 2045.
    let wrapped: String = ciphertext_b64
        .as_bytes()
        .chunks(76)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\r\n");

    let mut headers = format!(
        "From: <{from_addr}>\r\n\
         To: <{to_addr}>\r\n\
         Date: {date}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n"
    );

    // Inject the Autocrypt header if provided.
    if let Some(ac_b64) = autocrypt_header_b64
        && let Ok(ac_bytes) = B64.decode(ac_b64)
        && let Ok(ac_str) = String::from_utf8(ac_bytes)
    {
        headers.push_str(&format!("Autocrypt: {ac_str}\r\n"));
    }

    let raw_message = format!(
        "{headers}\r\n\
         --{boundary}\r\n\
         Content-Type: application/pgp-encrypted\r\n\
         Content-Description: PGP/MIME version identification\r\n\
         \r\n\
         Version: 1\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
         Content-Description: OpenPGP encrypted message\r\n\
         Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {wrapped}\r\n\
         \r\n\
         --{boundary}--\r\n"
    );

    let creds = Credentials::new(from_addr.to_owned(), password.to_owned());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
        .map_err(|e| format!("SMTP relay config failed: {e}"))?
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    let from: lettre::Address = from_addr.parse().map_err(|e| format!("bad From: {e}"))?;
    let to: lettre::Address = to_addr.parse().map_err(|e| format!("bad To: {e}"))?;

    let envelope = lettre::address::Envelope::new(Some(from), vec![to])
        .map_err(|e| format!("envelope construction failed: {e}"))?;

    mailer
        .send_raw(&envelope, raw_message.as_bytes())
        .await
        .map_err(|e| format!("SMTP send failed: {e}"))?;

    Ok(())
}
