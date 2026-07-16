// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Actor domain types (Individual, Company, Group).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::privacy::ActorPrivacy;

/// Discriminant for the three actor kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    Individual,
    Company,
    Group,
}

/// Instance-level role assigned to a local actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum InstanceRole {
    User,
    Moderator,
    Admin,
}

/// Moderation state of an actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ActorStatus {
    Active,
    Silenced,
    Suspended,
}

/// A Noombat actor: the central identity entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub id: Uuid,
    pub actor_type: ActorType,
    /// Fully-qualified ActivityPub identifier, e.g. `https://noombat.social/users/alice`.
    pub ap_id: String,
    pub username: String,
    pub display_name: Option<String>,
    /// Professional headline (e.g. "Senior Rust Engineer at Acme Corp").
    pub headline: Option<String>,
    pub avatar_url: Option<String>,
    pub header_url: Option<String>,
    /// (Markdown and KaTeX) source for the profile summary.
    pub summary_md: Option<String>,
    /// Pre-rendered HTML for the profile summary.
    pub summary_html: Option<String>,
    pub public_key_pem: String,
    /// `None` for remote actors. Never serialised to API responses.
    #[serde(skip_serializing)]
    pub private_key_pem: Option<String>,
    pub domain: String,
    pub is_local: bool,
    /// Remote actors only: their declared ActivityPub inbox URI.
    pub inbox_url: Option<String>,
    /// Instance-level role (compile-time exhaustive via [`InstanceRole`]).
    pub instance_role: InstanceRole,
    /// Moderation state (compile-time exhaustive via [`ActorStatus`]).
    pub actor_status: ActorStatus,
    pub chatmail_addr: Option<String>,
    pub orcid: Option<String>,
    /// Target actor URI if this actor has migrated via a `Move` activity.
    pub moved_to: Option<String>,
    pub actor_privacy: ActorPrivacy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters required to create a new local actor.
#[derive(Debug, Clone)]
pub struct NewActor {
    pub actor_type: ActorType,
    pub username: String,
    pub display_name: Option<String>,
    pub domain: String,
    pub public_key_pem: String,
    pub private_key_pem: String,
}
