// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! ActivityPub activity types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A generic ActivityPub activity envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub activity_type: String,
    pub actor: String,
    pub object: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
}

/// Known activity type strings.
pub mod types {
    pub const CREATE: &str = "Create";
    pub const UPDATE: &str = "Update";
    pub const DELETE: &str = "Delete";
    pub const FOLLOW: &str = "Follow";
    pub const ACCEPT: &str = "Accept";
    pub const REJECT: &str = "Reject";
    pub const UNDO: &str = "Undo";
    pub const ANNOUNCE: &str = "Announce";
    pub const LIKE: &str = "Like";
    pub const BLOCK: &str = "Block";
}
