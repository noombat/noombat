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
    /// Target actor URI when this actor has migrated (Move activity).
    #[serde(rename = "movedTo", skip_serializing_if = "Option::is_none")]
    pub moved_to: Option<String>,
    /// Prior actor URIs (aliases) that this actor claims as prior
    /// identities, enabling inbound Move verification.
    #[serde(rename = "alsoKnownAs", skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
