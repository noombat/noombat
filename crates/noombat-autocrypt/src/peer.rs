// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Peer state table and deterministic update algorithm per the
//! Autocrypt Level 1 specification.
//!
//! Each entry is indexed by canonicalised email address and holds the
//! peer's public key, preference flags, and timestamps.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// The peer's stated encryption preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreferEncrypt {
    Mutual,
    NoPreference,
}

/// State entry for a single peer (indexed by canonicalised email).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    /// Timestamp of the most recent message from this peer
    /// (regardless of whether it carried an Autocrypt header).
    pub last_seen: u64,
    /// Timestamp of the most recent message that carried a valid
    /// Autocrypt header.
    pub last_seen_autocrypt: u64,
    /// The peer's public key (opaque bytes; the WASM layer
    /// interprets these as an rPGP `SignedPublicKey`).
    pub public_key: Vec<u8>,
    /// The peer's stated encryption preference.
    pub prefer_encrypt: PreferEncrypt,
    /// Gossip key (from `Autocrypt-Gossip` headers in group messages).
    pub gossip_key: Option<Vec<u8>>,
    /// Timestamp of the most recent gossip header.
    pub gossip_timestamp: Option<u64>,
}

/// The complete peer state table, serialisable for blob inclusion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerStateTable {
    peers: BTreeMap<String, PeerState>,
}

/// An incoming Autocrypt header, parsed by the WASM bridge from the
/// raw MIME header bytes.
#[derive(Debug, Clone)]
pub struct AutocryptHeader {
    /// The canonicalised sender address (e.g. `alice@example.com`).
    pub addr: String,
    /// The sender's public key bytes.
    pub public_key: Vec<u8>,
    /// The sender's `prefer-encrypt` attribute.
    pub prefer_encrypt: PreferEncrypt,
}

/// Metadata about an incoming message, supplied by the WASM bridge.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// The canonicalised sender address.
    pub from: String,
    /// Effective date of the message (Unix timestamp, in seconds).
    pub effective_date: u64,
    /// The parsed Autocrypt header, if present and valid.
    pub autocrypt_header: Option<AutocryptHeader>,
}

impl PeerStateTable {
    /// Create an empty peer state table.
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }

    /// Apply the Autocrypt Level 1 update algorithm on receipt of an
    /// incoming message, the core deterministic update rule.
    pub fn update(&mut self, msg: &IncomingMessage) {
        let addr = canonicalise(&msg.from);

        // If no Autocrypt header is present, update only `last_seen`.
        let Some(ref header) = msg.autocrypt_header else {
            if let Some(entry) = self.peers.get_mut(&addr)
                && msg.effective_date > entry.last_seen
            {
                entry.last_seen = msg.effective_date;
            }
            return;
        };

        // Ignore the header if the `addr` attribute does not match
        // the sender.
        if canonicalise(&header.addr) != addr {
            // Treat as a message without an Autocrypt header.
            if let Some(entry) = self.peers.get_mut(&addr)
                && msg.effective_date > entry.last_seen
            {
                entry.last_seen = msg.effective_date;
            }
            return;
        }

        let entry = self.peers.entry(addr).or_insert_with(|| PeerState {
            last_seen: 0,
            last_seen_autocrypt: 0,
            public_key: Vec::new(),
            prefer_encrypt: PreferEncrypt::NoPreference,
            gossip_key: None,
            gossip_timestamp: None,
        });

        // Update timestamps and key only if the message is newer.
        if msg.effective_date > entry.last_seen {
            entry.last_seen = msg.effective_date;
        }

        if msg.effective_date > entry.last_seen_autocrypt {
            entry.last_seen_autocrypt = msg.effective_date;
            entry.public_key = header.public_key.clone();
            entry.prefer_encrypt = header.prefer_encrypt;
        }
    }

    /// Apply a gossip header update (from `Autocrypt-Gossip`).
    pub fn update_gossip(&mut self, addr: &str, key: Vec<u8>, timestamp: u64) {
        let addr = canonicalise(addr);
        let entry = self.peers.entry(addr).or_insert_with(|| PeerState {
            last_seen: 0,
            last_seen_autocrypt: 0,
            public_key: Vec::new(),
            prefer_encrypt: PreferEncrypt::NoPreference,
            gossip_key: None,
            gossip_timestamp: None,
        });

        let dominated = entry
            .gossip_timestamp
            .map(|t| timestamp > t)
            .unwrap_or(true);
        if dominated {
            entry.gossip_key = Some(key);
            entry.gossip_timestamp = Some(timestamp);
        }
    }

    /// Retrieve the peer state for the given address.
    pub fn get(&self, addr: &str) -> Option<&PeerState> {
        self.peers.get(&canonicalise(addr))
    }

    /// Return the number of peers in the table.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Return an iterator over all (address, state) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PeerState)> {
        self.peers.iter()
    }

    /// Serialise the entire table to a JSON byte vector for inclusion
    /// in the encrypted credential blob.
    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialise a table from a JSON byte vector.
    pub fn deserialize(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Canonicalise an email address: lowercase, trim whitespace.
fn canonicalise(addr: &str) -> String {
    addr.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_without_header_only_touches_last_seen() {
        let mut table = PeerStateTable::new();
        let msg = IncomingMessage {
            from: "Bob@Example.COM".into(),
            effective_date: 100,
            autocrypt_header: None,
        };
        table.update(&msg);
        // No entry is created when no header is present and no prior
        // state exists.
        assert!(table.get("bob@example.com").is_none());
    }

    #[test]
    fn update_with_header_creates_entry() {
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

        let entry = table.get("alice@example.com").unwrap();
        assert_eq!(entry.last_seen, 100);
        assert_eq!(entry.last_seen_autocrypt, 100);
        assert_eq!(entry.public_key, alloc::vec![1, 2, 3]);
        assert_eq!(entry.prefer_encrypt, PreferEncrypt::Mutual);
    }

    #[test]
    fn newer_message_updates_key() {
        let mut table = PeerStateTable::new();
        let msg1 = IncomingMessage {
            from: "alice@example.com".into(),
            effective_date: 100,
            autocrypt_header: Some(AutocryptHeader {
                addr: "alice@example.com".into(),
                public_key: alloc::vec![1],
                prefer_encrypt: PreferEncrypt::NoPreference,
            }),
        };
        table.update(&msg1);

        let msg2 = IncomingMessage {
            from: "alice@example.com".into(),
            effective_date: 200,
            autocrypt_header: Some(AutocryptHeader {
                addr: "alice@example.com".into(),
                public_key: alloc::vec![2],
                prefer_encrypt: PreferEncrypt::Mutual,
            }),
        };
        table.update(&msg2);

        let entry = table.get("alice@example.com").unwrap();
        assert_eq!(entry.public_key, alloc::vec![2]);
        assert_eq!(entry.prefer_encrypt, PreferEncrypt::Mutual);
    }

    #[test]
    fn older_message_does_not_overwrite_key() {
        let mut table = PeerStateTable::new();
        let msg1 = IncomingMessage {
            from: "alice@example.com".into(),
            effective_date: 200,
            autocrypt_header: Some(AutocryptHeader {
                addr: "alice@example.com".into(),
                public_key: alloc::vec![2],
                prefer_encrypt: PreferEncrypt::Mutual,
            }),
        };
        table.update(&msg1);

        let msg2 = IncomingMessage {
            from: "alice@example.com".into(),
            effective_date: 100,
            autocrypt_header: Some(AutocryptHeader {
                addr: "alice@example.com".into(),
                public_key: alloc::vec![1],
                prefer_encrypt: PreferEncrypt::NoPreference,
            }),
        };
        table.update(&msg2);

        let entry = table.get("alice@example.com").unwrap();
        assert_eq!(entry.public_key, alloc::vec![2]);
    }

    #[test]
    fn addr_mismatch_ignores_header() {
        let mut table = PeerStateTable::new();
        let msg = IncomingMessage {
            from: "alice@example.com".into(),
            effective_date: 100,
            autocrypt_header: Some(AutocryptHeader {
                addr: "mallory@evil.com".into(),
                public_key: alloc::vec![99],
                prefer_encrypt: PreferEncrypt::NoPreference,
            }),
        };
        table.update(&msg);
        // No entry should be created from the mismatched header.
        assert!(table.get("alice@example.com").is_none());
    }

    #[test]
    fn serialise_roundtrip() {
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

        let bytes = table.serialize().unwrap();
        let restored = PeerStateTable::deserialize(&bytes).unwrap();
        let entry = restored.get("alice@example.com").unwrap();
        assert_eq!(entry.public_key, alloc::vec![1, 2, 3]);
    }
}
