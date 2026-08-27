// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Actor domain types (Individual, Organization, Group).

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
    Organization,
    Group,
}

impl ActorType {
    /// The ActivityStreams type a peer sees for this actor.
    ///
    /// One mapping, because three copies of it disagreed: a profile
    /// update answered `Person` for an organisation while both
    /// federation paths answered `Organization`.
    pub fn ap_type(self) -> &'static str {
        match self {
            Self::Individual => "Person",
            Self::Organization => "Organization",
            Self::Group => "Group",
        }
    }

    /// The stored form, matching the `actor_type` check constraint.
    ///
    /// Derived by `sqlx::Type` for reads. This exists because the write
    /// paths spell the same strings out by hand, and a variant renamed
    /// in one place and not the other is a row the check constraint
    /// rejects at runtime rather than a compile error.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Organization => "organization",
            Self::Group => "group",
        }
    }

    /// The actor kind an ActivityStreams `type` names.
    ///
    /// Anything unrecognised is an individual: a peer may send a type
    /// this instance has no concept of, and treating it as a person is
    /// the reading that grants nothing.
    pub fn from_ap_type(ap_type: &str) -> Self {
        match ap_type {
            "Organization" => Self::Organization,
            "Group" => Self::Group,
            _ => Self::Individual,
        }
    }
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

/// Lifecycle state of an actor.
///
/// Three of these are moderation outcomes. [`ActorStatus::Pending`] is not:
/// it is an admission state, held by an account that exists and owns its
/// username but has never been admitted, and it is reachable only where
/// `instance_settings.registration_mode` is `approval`. It is not a fourth
/// degree of [`ActorStatus::Silenced`], and a moderator action never
/// produces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ActorStatus {
    Pending,
    Active,
    Silenced,
    Suspended,
}

impl ActorStatus {
    /// The stored form, as the `actor_status` check constraint spells it.
    ///
    /// The derive already produces these strings for sqlx and serde. This
    /// exists so hand-written SQL has one place to take them from: a value
    /// spelled here and not in the migration is a row the constraint
    /// rejects at runtime rather than a compile error.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Silenced => "silenced",
            Self::Suspended => "suspended",
        }
    }
}

/// A Noombat actor: the central identity entity.
///
/// # Deliberately Excluded Schema Columns
///
/// The following columns from the `actors` table are intentionally
/// absent from this struct. Each is handled by a specialised
/// subsystem that loads the column directly via SQL, avoiding
/// leakage of sensitive or scope-limited data into the general
/// domain model.
///
/// - **`shared_inbox_url`**: used only for delivery-inbox resolution.
///   Carried by `RemoteActor` (in `noombat-identity::repo`) during
///   upsert and queried directly via SQL in
///   `get_follower_inboxes` (in `noombat-identity::repo`).
/// - **`auth_key_hash`**: the Argon2id hash of the authentication key
///   (split key derivation). Must never cross the authentication
///   boundary into the general domain model.
/// - **`chatmail_cred`**: the encrypted credential blob (Chatmail
///   password + OpenPGP private key + Autocrypt peer state). Handled
///   exclusively by the chat subsystem.
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
    /// Free-text location (e.g. "Berlin, Germany").
    pub location: Option<String>,
    pub avatar_url: Option<String>,
    pub header_url: Option<String>,
    /// (Markdown and LaTeX) source for the profile summary.
    pub summary_md: Option<String>,
    /// Pre-rendered HTML for the profile summary.
    pub summary_html: Option<String>,
    pub public_key_pem: String,
    /// The `publicKey.id` a remote actor publishes, which a peer may
    /// serve at its own URL rather than as a fragment of the actor
    /// document. `None` for local actors, whose key id is derived.
    pub public_key_id: Option<String>,
    /// `None` for remote actors. Never serialised to API responses.
    #[serde(skip_serializing)]
    pub private_key_pem: Option<String>,
    /// Multibase-encoded Ed25519 public key (FEP-521a `assertionMethod`).
    /// NOT NULL for local actors (generated at creation); nullable for
    /// remote actors (populated only if the remote actor publishes one).
    pub ed25519_public_key: Option<String>,
    /// Ed25519 private key. NOT NULL for local actors; NULL for remote actors.
    #[serde(skip_serializing)]
    pub ed25519_private_key: Option<String>,
    pub domain: String,
    pub is_local: bool,
    /// Remote actors only: their declared ActivityPub inbox URI.
    pub inbox_url: Option<String>,
    /// Instance-level role (compile-time exhaustive via [`InstanceRole`]).
    pub instance_role: InstanceRole,
    /// Moderation state (compile-time exhaustive via [`ActorStatus`]).
    pub actor_status: ActorStatus,
    /// Set on unsuspension; cleared after chat credential
    /// re-provisioning. The browser detects this flag on
    /// login and guides the user through re-provisioning.
    pub chat_requires_reprovisioning: bool,
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
    /// Multibase-encoded Ed25519 public key.
    pub ed25519_public_key: String,
    /// Ed25519 private key (PEM or raw encoding).
    pub ed25519_private_key: String,
}

#[cfg(test)]
mod tests {
    use super::{ActorStatus, ActorType};

    /// Every variant, so adding one to the enum and not to this list is
    /// a compile error rather than a gap in the tests below.
    const ALL: [ActorType; 3] = [
        ActorType::Individual,
        ActorType::Organization,
        ActorType::Group,
    ];

    /// The same, for the status enum.
    const ALL_STATUSES: [ActorStatus; 4] = [
        ActorStatus::Pending,
        ActorStatus::Active,
        ActorStatus::Silenced,
        ActorStatus::Suspended,
    ];

    #[test]
    fn stored_status_matches_the_check_constraint() {
        let migration = include_str!("../../../migrations/0001_foundation.sql");
        let line = migration
            .lines()
            .find(|line| line.contains("actor_status") && line.contains("CHECK"))
            .expect("no actor_status check constraint in the migration");

        // Everything before CHECK is discarded first. Unlike the actor_type
        // line, this one carries `DEFAULT 'active'`, so splitting the whole
        // line on quotes counts that as an allowed value: it yields five
        // entries with 'active' twice, which passes the membership loop
        // below while making the count assertion wrong.
        let constraint = line
            .split("CHECK")
            .nth(1)
            .expect("the actor_status line has no CHECK clause");
        let allowed: Vec<&str> = constraint.split('\'').skip(1).step_by(2).collect();

        assert_eq!(
            allowed.len(),
            ALL_STATUSES.len(),
            "the constraint allows {allowed:?}, which is not one value per variant"
        );

        for status in ALL_STATUSES {
            assert!(
                allowed.contains(&status.as_str()),
                "{:?} stores as {:?}; the constraint allows {:?}",
                status,
                status.as_str(),
                allowed
            );
        }
    }

    #[test]
    fn stored_form_matches_the_check_constraint() {
        // Read from the migration rather than restated here. A copy of
        // the allowed values in this file would agree with itself while
        // disagreeing with the database, which is the failure: a variant
        // renamed on one side is a row rejected at runtime, and no test
        // that quotes its own expectation can see it.
        let migration = include_str!("../../../migrations/0001_foundation.sql");
        let constraint = migration
            .lines()
            .find(|line| line.contains("actor_type") && line.contains("CHECK"))
            .expect("no actor_type check constraint in the migration");
        let allowed: Vec<&str> = constraint.split('\'').skip(1).step_by(2).collect();
        assert_eq!(
            allowed.len(),
            ALL.len(),
            "the constraint allows {allowed:?}, which is not one value per variant"
        );

        for actor_type in ALL {
            assert!(
                allowed.contains(&actor_type.as_str()),
                "{:?} stores as {:?}; the constraint allows {:?}",
                actor_type,
                actor_type.as_str(),
                allowed
            );
        }
    }

    #[test]
    fn ap_type_round_trips() {
        for actor_type in ALL {
            assert_eq!(ActorType::from_ap_type(actor_type.ap_type()), actor_type);
        }
    }

    #[test]
    fn an_unknown_ap_type_is_an_individual() {
        assert_eq!(ActorType::from_ap_type("Service"), ActorType::Individual);
        assert_eq!(ActorType::from_ap_type(""), ActorType::Individual);
    }
}
