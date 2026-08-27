// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Outbound instance mail.
//!
//! This is the instance writing to one of its own users, and it is not the
//! Chatmail relay: that carries end-to-end encrypted message bodies between
//! people and never reads them, while this sends a short plaintext the
//! server composed. They share a library and nothing else, so they are kept
//! apart rather than given one configuration with two meanings.
//!
//! There is deliberately no fallback when no relay is configured. A
//! verification mail that is silently dropped leaves somebody waiting for a
//! message that was never sent, and the instance reporting success is what
//! makes that indistinguishable from a slow inbox.

use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use noombat_core::error::{NoombatError, Result};

/// SMTP settings for outbound instance mail.
#[derive(Debug, Clone)]
pub struct MailerConfig {
    pub host: String,
    pub port: u16,
    /// Omitted for a relay that authenticates by network position, which is
    /// the usual arrangement for a sidecar on the same host.
    pub username: Option<String>,
    pub password: Option<String>,
    /// The envelope sender, which is also what a reply reaches.
    pub from: String,
    /// `true` upgrades a plaintext connection with STARTTLS; `false` opens
    /// the connection wrapped, which is what port 465 expects.
    pub starttls: bool,
}

/// A configured transport for instance mail.
#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl std::fmt::Debug for Mailer {
    /// Hand-written so that credentials inside the transport cannot reach a
    /// log through a derived `Debug` on a struct that happens to hold one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailer").field("from", &self.from).finish()
    }
}

impl Mailer {
    /// Build a transport from configuration.
    pub fn new(config: &MailerConfig) -> Result<Self> {
        noombat_core::email_address::qualify(&config.from, "mail from address")?;

        let builder = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
        }
        .map_err(|e| NoombatError::Internal(format!("SMTP relay configuration failed: {e}")))?;

        let mut builder = builder.port(config.port);
        if let (Some(user), Some(password)) = (&config.username, &config.password) {
            builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
        }

        Ok(Self {
            transport: builder.build(),
            from: config.from.clone(),
        })
    }

    /// Send a plain-text message.
    pub async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        noombat_core::email_address::qualify(to, "recipient address")?;

        let message = Message::builder()
            .from(
                self.from
                    .parse()
                    .map_err(|e| NoombatError::Internal(format!("unusable From address: {e}")))?,
            )
            .to(to
                .parse()
                .map_err(|e| NoombatError::BadRequest(format!("unusable recipient: {e}")))?)
            .subject(subject)
            .body(body.to_owned())
            .map_err(|e| NoombatError::Internal(format!("message construction failed: {e}")))?;

        self.transport
            .send(message)
            .await
            .map_err(|e| NoombatError::Internal(format!("SMTP send failed: {e}")))?;

        Ok(())
    }
}
