// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Encryption recommendation algorithm per the Autocrypt Level 1
//! specification.
//!
//! Given a set of recipient addresses and the peer state table,
//! produces one of four recommendations: `Disable`, `Discourage`,
//! `Available`, or `Encrypt`.

use crate::peer::{PeerStateTable, PreferEncrypt};

/// The encryption recommendation for a set of recipients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    /// Encryption is not possible: at least one recipient has no
    /// known key.
    Disable,
    /// Encryption is possible but the key data is stale (the most
    /// recent message from at least one recipient did not carry an
    /// Autocrypt header).
    Discourage,
    /// Encryption is possible and all keys are current, but at least
    /// one recipient has not expressed `prefer-encrypt: mutual`.
    Available,
    /// Encryption is possible, all keys are current, and all
    /// recipients (and the sender) express `prefer-encrypt: mutual`.
    Encrypt,
}

/// Compute the encryption recommendation for the given recipients.
///
/// # Arguments
///
/// * `table`: the sender's peer state table.
/// * `recipients`: the canonicalised email addresses of all
///   recipients.
/// * `sender_prefers_mutual`: whether the sender has set
///   `prefer-encrypt: mutual` in their own Autocrypt header.
pub fn recommend(
    table: &PeerStateTable,
    recipients: &[&str],
    sender_prefers_mutual: bool,
) -> Recommendation {
    if recipients.is_empty() {
        return Recommendation::Disable;
    }

    let mut all_mutual = sender_prefers_mutual;
    let mut any_stale = false;

    for &addr in recipients {
        let Some(peer) = table.get(addr) else {
            // No peer state at all: encryption is not possible.
            return Recommendation::Disable;
        };

        if peer.public_key.is_empty() {
            // No key available.
            return Recommendation::Disable;
        }

        // A key is considered stale if the most recent message from
        // the peer (with or without an Autocrypt header) is newer
        // than the most recent message that carried an Autocrypt
        // header.
        if peer.last_seen > peer.last_seen_autocrypt {
            any_stale = true;
        }

        if peer.prefer_encrypt != PreferEncrypt::Mutual {
            all_mutual = false;
        }
    }

    if any_stale {
        return Recommendation::Discourage;
    }

    if all_mutual {
        Recommendation::Encrypt
    } else {
        Recommendation::Available
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{AutocryptHeader, IncomingMessage};

    fn setup_table() -> PeerStateTable {
        let mut table = PeerStateTable::new();
        let msg = IncomingMessage {
            from: "alice@example.com".into(),
            effective_date: 100,
            autocrypt_header: Some(AutocryptHeader {
                addr: "alice@example.com".into(),
                public_key: alloc::vec![1, 2, 3],
                prefer_encrypt: PreferEncrypt::Mutual,
            }),
        };
        table.update(&msg);
        table
    }

    #[test]
    fn empty_recipients_disables() {
        let table = PeerStateTable::new();
        assert_eq!(recommend(&table, &[], true), Recommendation::Disable);
    }

    #[test]
    fn unknown_recipient_disables() {
        let table = PeerStateTable::new();
        assert_eq!(
            recommend(&table, &["unknown@example.com"], true),
            Recommendation::Disable
        );
    }

    #[test]
    fn mutual_preference_recommends_encrypt() {
        let table = setup_table();
        assert_eq!(
            recommend(&table, &["alice@example.com"], true),
            Recommendation::Encrypt
        );
    }

    #[test]
    fn sender_not_mutual_recommends_available() {
        let table = setup_table();
        assert_eq!(
            recommend(&table, &["alice@example.com"], false),
            Recommendation::Available
        );
    }

    #[test]
    fn stale_key_recommends_discourage() {
        let mut table = setup_table();
        // A newer message without an Autocrypt header makes the key stale.
        let msg = IncomingMessage {
            from: "alice@example.com".into(),
            effective_date: 200,
            autocrypt_header: None,
        };
        table.update(&msg);

        assert_eq!(
            recommend(&table, &["alice@example.com"], true),
            Recommendation::Discourage
        );
    }
}
