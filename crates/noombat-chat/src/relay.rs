// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! WebSocket <--> IMAP/SMTP ciphertext relay.
//!
//! This module implements the server-side proxy that relays encrypted
//! message traffic between the browser (via WebSocket) and the
//! Chatmail relay (via IMAP/SMTP). The proxy sees only ciphertext
//! and Autocrypt header bytes, i.e. it never decrypts message bodies.

use noombat_core::error::Result;
use serde::{Deserialize, Serialize};

/// A message from the browser to the relay.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Session establishment: the browser sends the Chatmail
    /// password (decrypted from the credential blob client-side)
    /// so the relay can authenticate to the Chatmail IMAP/SMTP
    /// server. This must be the first message after connection.
    /// The password is held in server memory only for the
    /// duration of the WebSocket session and discarded on close.
    #[serde(rename = "auth")]
    Auth {
        /// The Chatmail password (plaintext, from the decrypted blob).
        password: String,
    },
    /// Send an encrypted message via SMTP.
    #[serde(rename = "send")]
    Send {
        /// Recipient Chatmail address.
        to: String,
        /// Base64-encoded encrypted message body (PGP/MIME).
        body_b64: String,
        /// Base64-encoded Autocrypt header value to inject.
        autocrypt_header_b64: Option<String>,
    },
    /// Request to fetch new messages from the IMAP mailbox.
    #[serde(rename = "fetch")]
    Fetch {
        /// IMAP sequence number to start from (0 = all unseen).
        since_uid: u32,
    },
    /// Acknowledge receipt of a message (mark as seen in IMAP).
    #[serde(rename = "ack")]
    Ack { uid: u32 },
}

/// A message from the relay to the browser.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Session established: IMAP login succeeded.
    #[serde(rename = "ready")]
    Ready,
    /// A new incoming encrypted message.
    #[serde(rename = "message")]
    Message {
        /// IMAP UID for acknowledgement.
        uid: u32,
        /// Sender Chatmail address.
        from: String,
        /// Base64-encoded encrypted message body.
        body_b64: String,
        /// Base64-encoded Autocrypt header value (if present).
        autocrypt_header_b64: Option<String>,
        /// Message timestamp (Unix seconds).
        timestamp: i64,
    },
    /// Confirmation that a message was sent.
    #[serde(rename = "sent")]
    Sent {
        /// The recipient address.
        to: String,
    },
    /// An error occurred.
    #[serde(rename = "error")]
    Error { message: String },
}

/// Configuration for the chat relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Chatmail IMAP server hostname (e.g. `chat.noombat.social`).
    pub imap_host: String,
    /// Chatmail IMAP port (default: 993).
    pub imap_port: u16,
    /// Chatmail SMTP server hostname (same as IMAP for Chatmail).
    pub smtp_host: String,
    /// Chatmail SMTP port (default: 465, SMTPS).
    pub smtp_port: u16,
}

impl RelayConfig {
    /// Construct a relay configuration from a Chatmail domain.
    pub fn from_domain(chatmail_domain: &str) -> Self {
        Self {
            imap_host: chatmail_domain.to_owned(),
            imap_port: 993,
            smtp_host: chatmail_domain.to_owned(),
            smtp_port: 465,
        }
    }
}

/// Check whether a sender address is blocked for the given actor.
///
/// Queries the `chatmail_blocks` table. Returns `true` if the
/// sender should be rejected.
pub async fn is_sender_blocked(
    pool: &sqlx::PgPool,
    actor_id: uuid::Uuid,
    sender_addr: &str,
) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM chatmail_blocks WHERE actor_id = $1 AND blocked_addr = $2)",
    )
    .bind(actor_id)
    .bind(sender_addr)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

/// Add a Chatmail address to the actor's block list.
pub async fn block_sender(
    pool: &sqlx::PgPool,
    actor_id: uuid::Uuid,
    blocked_addr: &str,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO chatmail_blocks (actor_id, blocked_addr)
           VALUES ($1, $2)
           ON CONFLICT (actor_id, blocked_addr) DO NOTHING"#,
    )
    .bind(actor_id)
    .bind(blocked_addr)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a Chatmail address from the actor's block list.
pub async fn unblock_sender(
    pool: &sqlx::PgPool,
    actor_id: uuid::Uuid,
    blocked_addr: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM chatmail_blocks WHERE actor_id = $1 AND blocked_addr = $2")
        .bind(actor_id)
        .bind(blocked_addr)
        .execute(pool)
        .await?;
    Ok(())
}
