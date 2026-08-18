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

    // The provider is named rather than left to `ClientConfig::builder()`,
    // which resolves a process-wide default and panics outright when the
    // dependency tree carries both rustls backends. Both are present
    // here, so there is no default for it to find.
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the bundled provider supports the default protocol versions")
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

    // Inject the Autocrypt header if provided, after validation.
    //
    // The header is validated to prevent:
    // 1. An `addr` attribute that does not match the authenticated
    //    sender (spoofed key exchange).
    // 2. An excessively large header that could abuse the SMTP
    //    envelope (e.g. a multi-megabyte keydata payload).
    if let Some(ac_b64) = autocrypt_header_b64
        && let Ok(ac_bytes) = B64.decode(ac_b64)
        && let Ok(ac_str) = String::from_utf8(ac_bytes)
    {
        if let Some(validated) = validate_autocrypt_header(&ac_str, from_addr) {
            headers.push_str(&fold_header_value("Autocrypt", validated));
        } else {
            warn!(
                from = %from_addr,
                "Autocrypt header rejected: addr mismatch, oversized, or malformed"
            );
        }
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

/// Maximum total byte length of an Autocrypt header value that the
/// relay will inject into an outgoing SMTP message. A typical
/// Ed25519/Curve25519 Autocrypt header is approximately 200 bytes;
/// an RSA-4096 header is approximately 6 KiB. The 16 384-byte
/// ceiling accommodates any realistic key size with margin.
const MAX_AUTOCRYPT_HEADER_BYTES: usize = 16_384;

/// Validate an Autocrypt header value before injection into an
/// SMTP message.
///
/// `Some` only when the `addr=` attribute matches `expected_sender`
/// case-insensitively and the value fits [`MAX_AUTOCRYPT_HEADER_BYTES`].
/// Deliberately lightweight: it checks the `addr` binding and the size,
/// not the full Autocrypt grammar, because `autocrypt.ts` has already
/// parsed and validated the header client-side.
fn validate_autocrypt_header<'a>(header: &'a str, expected_sender: &str) -> Option<&'a str> {
    if header.len() > MAX_AUTOCRYPT_HEADER_BYTES {
        return None;
    }

    // Extract the `addr` attribute value from the semicolon-delimited header.
    //
    // `split_once('=')` splits at the *first* `=`, which is correct:
    // attribute names never contain `=`, so everything after the first `=` is the value.
    // For `keydata=AAAA==` this yields `("keydata", "AAAA==")` with the base64 padding intact.
    // This function only inspects the `addr` attribute (whose value is an email address that
    // never contains `=`), but the semantics are safe for all Autocrypt attributes.
    let addr_value = header.split(';').map(str::trim).find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("addr") {
            Some(value.trim())
        } else {
            None
        }
    });

    match addr_value {
        Some(addr) if addr.eq_ignore_ascii_case(expected_sender) => Some(header),
        _ => None,
    }
}

/// Format a header field name and value as a folded RFC 5322 header line.
///
/// RFC 5322 §2.1.1 caps a line at 998 characters, which an Autocrypt
/// header carrying a base64 OpenPGP key in `keydata` passes easily, so
/// this inserts folding white space (CRLF and one space) at 76-character
/// widths, matching RFC 2045's base64 convention and the ciphertext
/// wrapping elsewhere in this module. The result ends with `\r\n`, ready
/// to concatenate into the header block.
fn fold_header_value(name: &str, value: &str) -> String {
    // Maximum number of value characters per line. The first line
    // carries the field name, colon, and space (`Name: `), so its
    // available width is shorter.
    const LINE_WIDTH: usize = 76;

    let prefix = format!("{name}: ");
    let first_line_budget = LINE_WIDTH.saturating_sub(prefix.len());

    let mut out = String::with_capacity(prefix.len() + value.len() + value.len() / LINE_WIDTH * 3);
    out.push_str(&prefix);

    let bytes = value.as_bytes();
    if bytes.len() <= first_line_budget {
        // Short enough to fit on one line.
        out.push_str(value);
        out.push_str("\r\n");
        return out;
    }

    // First line: fill up to first_line_budget.
    out.push_str(&value[..first_line_budget]);
    out.push_str("\r\n");

    // Continuation lines: each prefixed with a single space (FWS).
    let continuation_budget = LINE_WIDTH - 1; // 1 byte for the leading space
    let mut pos = first_line_budget;
    while pos < bytes.len() {
        let end = (pos + continuation_budget).min(bytes.len());
        out.push(' ');
        out.push_str(&value[pos..end]);
        out.push_str("\r\n");
        pos = end;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ..... build_tls_connector .....

    // Building the connector is the whole assertion: the failure mode is
    // a panic, not a wrong value. `ClientConfig::builder()` resolves a
    // process-wide default provider and aborts when the tree carries both
    // rustls backends, which took down every chat provisioning attempt
    // with a dropped connection and no response.
    //
    // Nothing installs a default provider in this process, so a
    // regression reaches the panic here exactly as it did in the server.
    #[test]
    fn the_tls_connector_names_its_crypto_provider() {
        let _connector = build_tls_connector();
    }

    // ..... validate_autocrypt_header .....

    #[test]
    fn valid_header_matching_addr() {
        let header = "addr=alice@chat.noombat.social; prefer-encrypt=mutual; keydata=AAAA";
        let result = validate_autocrypt_header(header, "alice@chat.noombat.social");
        assert_eq!(result, Some(header));
    }

    #[test]
    fn valid_header_case_insensitive_addr() {
        let header = "addr=Alice@Chat.Noombat.Social; keydata=AAAA";
        let result = validate_autocrypt_header(header, "alice@chat.noombat.social");
        assert_eq!(result, Some(header));
    }

    #[test]
    fn addr_mismatch_returns_none() {
        let header = "addr=mallory@evil.example; keydata=AAAA";
        let result = validate_autocrypt_header(header, "alice@chat.noombat.social");
        assert!(result.is_none());
    }

    #[test]
    fn missing_addr_returns_none() {
        let header = "prefer-encrypt=mutual; keydata=AAAA";
        let result = validate_autocrypt_header(header, "alice@chat.noombat.social");
        assert!(result.is_none());
    }

    #[test]
    fn oversized_header_returns_none() {
        // Build a header that exceeds MAX_AUTOCRYPT_HEADER_BYTES.
        let large_keydata = "A".repeat(MAX_AUTOCRYPT_HEADER_BYTES + 1);
        let header = format!("addr=alice@example.com; keydata={large_keydata}");
        let result = validate_autocrypt_header(&header, "alice@example.com");
        assert!(result.is_none());
    }

    #[test]
    fn keydata_with_base64_padding_does_not_break_split() {
        // The `keydata` value contains `=` characters (base64 padding).
        // `split_once('=')` must split at the first `=` (between the
        // attribute name and value), not at the padding.
        let header = "addr=alice@example.com; keydata=AAAA==";
        let result = validate_autocrypt_header(header, "alice@example.com");
        assert_eq!(result, Some(header));
    }

    #[test]
    fn empty_header_returns_none() {
        assert!(validate_autocrypt_header("", "alice@example.com").is_none());
    }

    // ..... fold_header_value .....

    #[test]
    fn short_value_not_folded() {
        let result = fold_header_value("Autocrypt", "addr=a@b.c; keydata=AA");
        assert_eq!(result, "Autocrypt: addr=a@b.c; keydata=AA\r\n");
        // No continuation lines.
        assert_eq!(result.matches("\r\n").count(), 1);
    }

    #[test]
    fn long_value_folded_within_limit() {
        // Generate a value longer than 76 characters.
        let value = "addr=alice@chat.noombat.social; prefer-encrypt=mutual; keydata=".to_owned()
            + &"A".repeat(200);
        let result = fold_header_value("Autocrypt", &value);

        // Every line (excluding the final empty split) must be at most 76
        // characters (not counting the CRLF itself).
        for line in result.trim_end_matches("\r\n").split("\r\n") {
            assert!(
                line.len() <= 76,
                "line exceeds 76 characters ({} chars): {:?}",
                line.len(),
                line,
            );
        }

        // The unfolded value (strip FWS) must reconstruct the original.
        let unfolded = result
            .strip_prefix("Autocrypt: ")
            .unwrap()
            .replace("\r\n ", "")
            .replace("\r\n", "");
        assert_eq!(unfolded, value);
    }

    #[test]
    fn folded_continuation_lines_start_with_space() {
        let value = "A".repeat(200);
        let result = fold_header_value("X-Test", &value);
        let lines: Vec<&str> = result.trim_end_matches("\r\n").split("\r\n").collect();
        // First line starts with field name; continuation lines with a space.
        assert!(lines[0].starts_with("X-Test: "));
        for continuation in &lines[1..] {
            assert!(
                continuation.starts_with(' '),
                "continuation line must start with a space: {:?}",
                continuation,
            );
        }
    }
}
