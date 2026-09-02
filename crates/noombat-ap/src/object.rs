// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! ActivityPub object serialisation helpers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An ActivityPub actor object (Person, Organization, or Group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApActor {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub actor_type: String,
    #[serde(rename = "preferredUsername")]
    pub preferred_username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<MediaLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<MediaLink>,
    pub inbox: String,
    pub outbox: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub following: Option<String>,
    #[serde(rename = "publicKey")]
    pub public_key: ApPublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Value>,
    /// Ed25519 public key for FEP-8b32 Object Integrity Proofs
    /// (FEP-521a `assertionMethod`).
    #[serde(rename = "assertionMethod", skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<ApMultikey>>,
    /// Target actor URI when this actor has migrated (Move activity).
    #[serde(rename = "movedTo", skip_serializing_if = "Option::is_none")]
    pub moved_to: Option<String>,
    /// Prior actor URIs (aliases) that this actor claims as prior
    /// identities, enabling inbound Move verification.
    #[serde(rename = "alsoKnownAs", skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    /// Whether this actor consents to appearing in directories and
    /// profile search (`toot:discoverable`).
    ///
    /// `Option` because absent and `false` are different facts on the
    /// wire and only the reader may collapse them. Readers here collapse
    /// absent to *withheld*: see
    /// [`crate::object::ApActor::consents_to_discovery`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<bool>,
    /// Whether this actor consents to its posts being indexed for
    /// full-text search (`toot:indexable`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexable: Option<bool>,
}

impl ApActor {
    /// Whether this actor consents to appearing in directories.
    ///
    /// **An absent property is not consent.** Mastodon reads its own
    /// equivalents the same way, and the alternative is to treat silence
    /// from a server that has never heard of the property as agreement
    /// to be listed by a service the actor has never seen.
    pub fn consents_to_discovery(&self) -> bool {
        self.discoverable.unwrap_or(false)
    }

    /// Whether this actor consents to its posts being indexed.
    pub fn consents_to_indexing(&self) -> bool {
        self.indexable.unwrap_or(false)
    }
}

#[cfg(test)]
mod consent_tests {
    use super::*;

    fn actor(json: &str) -> ApActor {
        serde_json::from_str(json).expect("an actor document")
    }

    const MINIMAL: &str = r#"{
        "id": "https://peer.example/users/x",
        "type": "Person",
        "preferredUsername": "x",
        "inbox": "https://peer.example/users/x/inbox",
        "outbox": "https://peer.example/users/x/outbox",
        "publicKey": {
            "id": "https://peer.example/users/x#main-key",
            "owner": "https://peer.example/users/x",
            "publicKeyPem": "KEY"
        }
    }"#;

    #[test]
    fn a_document_that_says_nothing_consents_to_nothing() {
        // The whole polarity decision, in one assertion. A server that
        // has never heard of these properties has not agreed on its
        // users' behalf to appear in a hiring service's index.
        let actor = actor(MINIMAL);
        assert!(actor.discoverable.is_none());
        assert!(actor.indexable.is_none());
        assert!(!actor.consents_to_discovery());
        assert!(!actor.consents_to_indexing());
    }

    #[test]
    fn an_explicit_answer_is_taken_as_given() {
        let yes = actor(&MINIMAL.replace(
            "\"type\": \"Person\",",
            "\"type\": \"Person\", \"discoverable\": true, \"indexable\": true,",
        ));
        assert!(yes.consents_to_discovery());
        assert!(yes.consents_to_indexing());

        let no = actor(&MINIMAL.replace(
            "\"type\": \"Person\",",
            "\"type\": \"Person\", \"discoverable\": false, \"indexable\": false,",
        ));
        assert!(!no.consents_to_discovery());
        assert!(!no.consents_to_indexing());
    }

    #[test]
    fn the_two_are_independent() {
        // Agreeing to be listed in a directory is not agreeing to have
        // one's posts indexed, and a reader must not infer either from
        // the other.
        let listed_only = actor(&MINIMAL.replace(
            "\"type\": \"Person\",",
            "\"type\": \"Person\", \"discoverable\": true, \"indexable\": false,",
        ));
        assert!(listed_only.consents_to_discovery());
        assert!(!listed_only.consents_to_indexing());
    }

    #[test]
    fn an_absent_property_is_not_serialised_back() {
        // Round-tripping must not turn silence into an explicit `false`
        // and republish it as though the actor had answered.
        let actor = actor(MINIMAL);
        let out = serde_json::to_value(&actor).expect("serialised");
        assert!(out.get("discoverable").is_none());
        assert!(out.get("indexable").is_none());
    }
}

/// An Ed25519 multikey entry for `assertionMethod` (FEP-521a).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApMultikey {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    /// Multibase-encoded Ed25519 public key (`z` + Base58btc).
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// The `publicKey` sub-object embedded in an actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApPublicKey {
    pub id: String,
    pub owner: String,
    #[serde(rename = "publicKeyPem")]
    pub public_key_pem: String,
}

/// A media link (icon, image).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaLink {
    #[serde(rename = "type")]
    pub media_type: String,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub url: String,
}

/// An ActivityPub Note object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApNote {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(rename = "attributedTo")]
    pub attributed_to: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<ApSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::addressing::one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub to: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "crate::addressing::one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub cc: Option<Vec<String>>,
    #[serde(rename = "inReplyTo", skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// The Mastodon-convention `source` property for Markdown-aware clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApSource {
    pub content: String,
    #[serde(rename = "mediaType")]
    pub media_type: String,
}
