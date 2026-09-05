// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! HTTP client for the `noombat-chatmail-admin` sidecar REST API.
//!
//! Provides typed async methods for each of the eight admin endpoints.
//! Used by the suspension/unsuspension orchestration handlers in `noombat-api`.

use noombat_core::error::{NoombatError, Result};
use serde::Deserialize;
use tracing::{error, info, warn};

/// Refuse an address that would change the path of the request it goes in.
///
/// Every method below interpolates its arguments into a URL, and one of
/// them reaches this client straight from a route parameter. A `/` there
/// moves a privileged request to a different endpoint on the sidecar,
/// which can delete a mailbox: the host is fixed by configuration, so the
/// exposure is the path rather than the destination.
///
/// Refusing rather than percent-encoding, because the sidecar slices its
/// own path with `strip_prefix` and never decodes. An encoded separator
/// would arrive as a literal `%2F` and match no mailbox, which turns a
/// blocked attack into a broken feature. This mirrors the sidecar's own
/// `validate_address`, one hop earlier, so the two agree about what an
/// address may contain.
fn check_segment(value: &str) -> Result<()> {
    let unsafe_byte = |b: u8| {
        matches!(b, b'/' | b'\\' | b'?' | b'#' | b'%' | b';')
            || b.is_ascii_whitespace()
            || b.is_ascii_control()
    };
    if value.is_empty() || value.bytes().any(unsafe_byte) || value.contains("..") {
        return Err(NoombatError::BadRequest(
            "chatmail address contains a character that cannot appear in a request path".into(),
        ));
    }
    Ok(())
}

/// An HTTP client trusting the relay's authority as well as the
/// platform's.
///
/// The sidecar serves the relay's own certificate, which on a default
/// deployment is issued by a CA generated inside the relay container and
/// trusted nowhere else. [`crate::session::EXTRA_CA_ENV`] is the same
/// variable the IMAP and SMTP sessions read, so one file covers every
/// connection this crate makes to the relay.
///
/// Reports rather than fails, matching the transports: an unusable CA
/// file surfaces as a handshake failure naming an untrusted issuer,
/// which is a better diagnosis than a client that could not be built.
fn client_trusting_the_relay() -> reqwest::Client {
    let mut builder = reqwest::Client::builder();

    if let Some(path) = std::env::var_os(crate::session::EXTRA_CA_ENV) {
        match std::fs::read(&path) {
            Ok(pem) => match reqwest::Certificate::from_pem_bundle(&pem) {
                Ok(certificates) => {
                    for certificate in certificates {
                        builder = builder.add_root_certificate(certificate);
                    }
                }
                Err(error) => {
                    error!(?path, %error, "NOOMBAT_EXTRA_CA_FILE holds no usable certificate")
                }
            },
            Err(error) => error!(?path, %error, "NOOMBAT_EXTRA_CA_FILE could not be read"),
        }
    }

    builder.build().unwrap_or_else(|error| {
        error!(%error, "falling back to a client trusting only the platform roots");
        reqwest::Client::new()
    })
}

/// Client for the Chatmail admin sidecar.
#[derive(Debug, Clone)]
pub struct ChatmailAdminClient {
    /// Base URL of the sidecar (e.g. `https://chat.example.com:9100`).
    base_url: String,
    /// Shared secret for the `Authorization: Bearer` header.
    secret: String,
    /// Reusable HTTP client.
    http: reqwest::Client,
}

/// Response from the `rotate-password` endpoint.
#[derive(Debug, Deserialize)]
pub struct RotatePasswordResponse {
    pub address: String,
    pub password: String,
}

/// Response from the `exists` endpoint.
#[derive(Debug, Deserialize)]
pub struct AccountExistsResponse {
    pub address: String,
    pub exists: bool,
}

impl ChatmailAdminClient {
    /// Create a new client.
    ///
    /// Returns `None` if either `base_url` or `secret` is `None`
    /// (sidecar not configured).
    pub fn new(base_url: Option<&str>, secret: Option<&str>) -> Option<Self> {
        let base_url = base_url?.trim_end_matches('/').to_owned();
        let secret = secret?.to_owned();
        Some(Self {
            base_url,
            secret,
            http: client_trusting_the_relay(),
        })
    }

    /// `POST /admin/v1/accounts/{address}/rotate-password`
    ///
    /// Rotates the Chatmail password for the given address. Returns
    /// the new password.
    pub async fn rotate_password(&self, address: &str) -> Result<RotatePasswordResponse> {
        check_segment(address)?;
        let url = format!(
            "{}/admin/v1/accounts/{}/rotate-password",
            self.base_url, address
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(NoombatError::Internal(format!(
                "admin sidecar rotate-password returned {status}: {body}"
            )));
        }

        resp.json::<RotatePasswordResponse>()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar response parse error: {e}")))
    }

    /// `POST /admin/v1/accounts/{address}/kick`
    ///
    /// Terminates all active IMAP sessions for the address.
    pub async fn kick_sessions(&self, address: &str) -> Result<()> {
        check_segment(address)?;
        let url = format!("{}/admin/v1/accounts/{}/kick", self.base_url, address);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(address = %address, %status, "kick_sessions failed: {body}");
        } else {
            info!(address = %address, "IMAP sessions terminated via sidecar");
        }
        Ok(())
    }

    /// `DELETE /admin/v1/accounts/{address}`
    ///
    /// Deletes the account's maildir and password file. Blocks the
    /// address in the recipient access map.
    pub async fn delete_account(&self, address: &str) -> Result<()> {
        check_segment(address)?;
        let url = format!("{}/admin/v1/accounts/{}", self.base_url, address);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(NoombatError::Internal(format!(
                "admin sidecar delete-account returned {status}: {body}"
            )));
        }

        info!(address = %address, "account deleted via sidecar");
        Ok(())
    }

    /// `POST /admin/v1/access-maps/recipients/{address}/block`
    pub async fn block_recipient(&self, address: &str) -> Result<()> {
        check_segment(address)?;
        let url = format!(
            "{}/admin/v1/access-maps/recipients/{}/block",
            self.base_url, address
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(address = %address, %status, "block_recipient failed: {body}");
        }
        Ok(())
    }

    /// `DELETE /admin/v1/access-maps/recipients/{address}/block`
    pub async fn unblock_recipient(&self, address: &str) -> Result<()> {
        check_segment(address)?;
        let url = format!(
            "{}/admin/v1/access-maps/recipients/{}/block",
            self.base_url, address
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(address = %address, %status, "unblock_recipient failed: {body}");
        }
        Ok(())
    }

    /// `POST /admin/v1/access-maps/senders/{sender}/block-to/{recipient}`
    pub async fn block_sender_pair(&self, sender: &str, recipient: &str) -> Result<()> {
        check_segment(sender)?;
        check_segment(recipient)?;
        let url = format!(
            "{}/admin/v1/access-maps/senders/{}/block-to/{}",
            self.base_url, sender, recipient
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(sender = %sender, recipient = %recipient, %status, "block_sender_pair failed: {body}");
        }
        Ok(())
    }

    /// `DELETE /admin/v1/access-maps/senders/{sender}/block-to/{recipient}`
    pub async fn unblock_sender_pair(&self, sender: &str, recipient: &str) -> Result<()> {
        check_segment(sender)?;
        check_segment(recipient)?;
        let url = format!(
            "{}/admin/v1/access-maps/senders/{}/block-to/{}",
            self.base_url, sender, recipient
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(sender = %sender, recipient = %recipient, %status, "unblock_sender_pair failed: {body}");
        }
        Ok(())
    }

    /// `GET /admin/v1/accounts/{address}/exists`
    pub async fn account_exists(&self, address: &str) -> Result<bool> {
        check_segment(address)?;
        let url = format!("{}/admin/v1/accounts/{}/exists", self.base_url, address);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| NoombatError::Internal(format!("admin sidecar request failed: {e}")))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let body = resp.json::<AccountExistsResponse>().await.map_err(|e| {
            NoombatError::Internal(format!("admin sidecar response parse error: {e}"))
        })?;
        Ok(body.exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An address whose only fault is the separator, so a test failing
    /// here names the rule that lapsed rather than the whole validator.
    const PATH_CHANGING: &str = "victim@example.test/x";
    const SAFE: &str = "someone@example.test";

    /// Port 1 refuses immediately, which is what makes the assertions
    /// below meaningful: with the check gone the call reaches the
    /// network and fails as `Internal`, never as `BadRequest`.
    fn client() -> ChatmailAdminClient {
        ChatmailAdminClient::new(Some("http://127.0.0.1:1"), Some("test-secret"))
            .expect("a base URL and a secret produce a client")
    }

    /// Assert the call was refused *for the right reason*.
    ///
    /// Asserting only that it failed would pass with no validator at
    /// all, because the sidecar address is unroutable either way.
    fn assert_refused<T: std::fmt::Debug>(result: Result<T>, what: &str) {
        match result {
            Err(NoombatError::BadRequest(message)) => assert!(
                message.contains("cannot appear in a request path"),
                "{what} refused for the wrong reason: {message}"
            ),
            other => panic!("{what} accepted an address that changes the path: {other:?}"),
        }
    }

    #[test]
    fn an_ordinary_address_is_accepted() {
        assert!(check_segment(SAFE).is_ok());
    }

    #[test]
    fn a_separator_or_an_escape_is_refused() {
        for value in [
            "a/b", "a\\b", "a?b", "a#b", "a%2Fb", "a;b", "a b", "a\nb", "a\tb",
        ] {
            assert!(
                check_segment(value).is_err(),
                "{value:?} should not be allowed in a path segment"
            );
        }
    }

    #[test]
    fn an_empty_or_traversing_segment_is_refused() {
        assert!(check_segment("").is_err());
        assert!(check_segment("..").is_err());
        assert!(check_segment("a..b").is_err());
    }

    // ..... Every method reaches the validator .....
    //
    // The validator existing is not the same as it being called, and a
    // dropped `check_segment(...)?` is a bare statement whose removal
    // compiles clean. One test per argument, so losing either half of a
    // pair is caught too.

    #[tokio::test]
    async fn rotate_password_refuses_a_path_changing_address() {
        assert_refused(
            client().rotate_password(PATH_CHANGING).await,
            "rotate_password",
        );
    }

    #[tokio::test]
    async fn kick_sessions_refuses_a_path_changing_address() {
        assert_refused(client().kick_sessions(PATH_CHANGING).await, "kick_sessions");
    }

    #[tokio::test]
    async fn delete_account_refuses_a_path_changing_address() {
        assert_refused(
            client().delete_account(PATH_CHANGING).await,
            "delete_account",
        );
    }

    #[tokio::test]
    async fn block_recipient_refuses_a_path_changing_address() {
        assert_refused(
            client().block_recipient(PATH_CHANGING).await,
            "block_recipient",
        );
    }

    #[tokio::test]
    async fn unblock_recipient_refuses_a_path_changing_address() {
        assert_refused(
            client().unblock_recipient(PATH_CHANGING).await,
            "unblock_recipient",
        );
    }

    #[tokio::test]
    async fn block_sender_pair_refuses_either_side() {
        assert_refused(
            client().block_sender_pair(PATH_CHANGING, SAFE).await,
            "block_sender_pair sender",
        );
        assert_refused(
            client().block_sender_pair(SAFE, PATH_CHANGING).await,
            "block_sender_pair recipient",
        );
    }

    #[tokio::test]
    async fn unblock_sender_pair_refuses_either_side() {
        assert_refused(
            client().unblock_sender_pair(PATH_CHANGING, SAFE).await,
            "unblock_sender_pair sender",
        );
        assert_refused(
            client().unblock_sender_pair(SAFE, PATH_CHANGING).await,
            "unblock_sender_pair recipient",
        );
    }

    #[tokio::test]
    async fn account_exists_refuses_a_path_changing_address() {
        assert_refused(
            client().account_exists(PATH_CHANGING).await,
            "account_exists",
        );
    }
}
