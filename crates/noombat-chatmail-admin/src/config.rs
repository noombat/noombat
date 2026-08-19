// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Configuration for the sidecar daemon.

use std::env;

/// Sidecar configuration, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address (default `0.0.0.0`).
    pub listen_host: String,
    /// Listen port (default `9100`).
    pub listen_port: u16,
    /// Shared secret for authenticating requests from the Noombat
    /// application server (`Authorization: Bearer <secret>`).
    pub admin_secret: String,
    /// Path to the vmail home directory (default `/home/vmail`).
    pub vmail_home: String,
    /// Path to the access-maps persistence file
    /// (default `/home/vmail/.noombat-admin/access-maps.json`).
    pub access_maps_path: String,
    /// Path to the Postfix `check_recipient_access` map file
    /// (default `/etc/postfix/noombat_recipient_access`).
    pub recipient_access_path: String,
    /// Path to the Postfix `check_sender_access` map file
    /// (default `/etc/postfix/noombat_sender_access`).
    pub sender_access_path: String,
    /// Debounce interval in seconds for Postfix reloads (default `2`).
    pub reload_debounce_secs: u64,
    /// URL of the published Chatmail allowlist JSON document
    /// Empty by default, which disables allowlist synchronisation.
    /// Set it to enable closed-federation routing, conventionally
    /// `https://noombat.org/chatmail-allowlist.json`.
    pub allowlist_url: String,
    /// Polling interval in seconds for the allowlist (default `21600`,
    /// i.e. 6 hours).
    pub allowlist_poll_interval_secs: u64,
    /// Path to the Postfix `transport_maps` file
    /// (default `/etc/postfix/noombat_transport_maps`).
    pub transport_maps_path: String,
    /// Path to the inbound sender-domain allowlist
    /// (default `/etc/postfix/noombat_sender_domains`).
    ///
    /// `transport_maps` closes the outbound direction; this closes the
    /// inbound one. Both are generated from the same allowlist.
    pub sender_domains_path: String,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Panics
    ///
    /// Panics if `CHATMAIL_ADMIN_SECRET` is not set, or if any
    /// configured filesystem path fails validation.
    pub fn from_env() -> Self {
        let config = Self {
            listen_host: env::var("CHATMAIL_ADMIN_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            listen_port: env::var("CHATMAIL_ADMIN_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(9100),
            admin_secret: env::var("CHATMAIL_ADMIN_SECRET")
                .expect("CHATMAIL_ADMIN_SECRET must be set"),
            vmail_home: env::var("VMAIL_HOME").unwrap_or_else(|_| "/home/vmail".into()),
            access_maps_path: env::var("CHATMAIL_ACCESS_MAPS_PATH")
                .unwrap_or_else(|_| "/home/vmail/.noombat-admin/access-maps.json".into()),
            recipient_access_path: env::var("CHATMAIL_RECIPIENT_ACCESS_PATH")
                .unwrap_or_else(|_| "/etc/postfix/noombat_recipient_access".into()),
            sender_access_path: env::var("CHATMAIL_SENDER_ACCESS_PATH")
                .unwrap_or_else(|_| "/etc/postfix/noombat_sender_access".into()),
            reload_debounce_secs: env::var("CHATMAIL_RELOAD_DEBOUNCE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            // Empty by default: an instance contacts noombat.org only
            // when its operator sets this, which is the moment they
            // register their domain. Defaulting to the URL would make
            // every relay poll a third party without anyone choosing it,
            // and would tie a beacon to a crash fix.
            allowlist_url: env::var("CHATMAIL_ALLOWLIST_URL").unwrap_or_default(),
            // Six hours, not fifteen minutes. A curated federation list
            // changes on a timescale of days, transport_maps is persisted
            // so a stale poll delays discovering a peer rather than
            // breaking delivery, and 900s was 2,880 requests a month, each
            // one disclosing this relay's address and uptime.
            allowlist_poll_interval_secs: env::var("CHATMAIL_ALLOWLIST_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(21_600),
            transport_maps_path: env::var("CHATMAIL_TRANSPORT_MAPS_PATH")
                .unwrap_or_else(|_| "/etc/postfix/noombat_transport_maps".into()),
            sender_domains_path: env::var("CHATMAIL_SENDER_DOMAINS_PATH")
                .unwrap_or_else(|_| "/etc/postfix/noombat_sender_domains".into()),
        };
        config.validate();
        config
    }

    /// Verify that all configured filesystem paths are absolute and free
    /// of traversal sequences. Panics on failure, i.e. configuration errors
    /// are caught at startup, not at request time.
    fn validate(&self) {
        for (name, path) in [
            ("VMAIL_HOME", &self.vmail_home),
            ("CHATMAIL_ACCESS_MAPS_PATH", &self.access_maps_path),
            (
                "CHATMAIL_RECIPIENT_ACCESS_PATH",
                &self.recipient_access_path,
            ),
            ("CHATMAIL_SENDER_ACCESS_PATH", &self.sender_access_path),
            ("CHATMAIL_TRANSPORT_MAPS_PATH", &self.transport_maps_path),
            ("CHATMAIL_SENDER_DOMAINS_PATH", &self.sender_domains_path),
        ] {
            assert!(
                std::path::Path::new(path).is_absolute(),
                "{name} must be an absolute path, got: {path}"
            );
            assert!(
                !path.contains(".."),
                "{name} must not contain '..' traversal sequences, got: {path}"
            );
            assert!(!path.contains('\0'), "{name} must not contain null bytes");
        }
    }
}
