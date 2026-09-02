// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Privacy control types.

use serde::{Deserialize, Serialize};

/// Profile-level privacy controls, stored as `actor_privacy` JSONB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorPrivacy {
    /// Whether the profile appears in local search and the public directory.
    #[serde(default = "default_true")]
    pub discoverable: bool,
    /// Whether the profile page emits a `noindex` meta tag.
    #[serde(default = "default_true")]
    pub indexable: bool,
    /// Whether inbound `Follow` activities require manual approval.
    #[serde(default)]
    pub require_follow_approval: bool,
    /// Whether the full profile is included in outbound ActivityPub responses.
    #[serde(default = "default_true")]
    pub federate_profile: bool,
    /// Whether the Chatmail address is publicly visible.
    #[serde(default = "default_true")]
    pub chatmail_visible: bool,
    /// Whether follower and following counts are publicly visible.
    #[serde(default = "default_true")]
    pub show_followers_count: bool,
    /// Who may trigger the CV PDF download.
    #[serde(default)]
    pub cv_download: CvDownload,
}

impl Default for ActorPrivacy {
    fn default() -> Self {
        Self {
            discoverable: true,
            indexable: true,
            require_follow_approval: false,
            federate_profile: true,
            chatmail_visible: true,
            show_followers_count: true,
            cv_download: CvDownload::default(),
        }
    }
}

/// CV download visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CvDownload {
    #[default]
    Public,
    Followers,
    #[serde(rename = "self")]
    SelfOnly,
}

/// Per-section visibility.
///
/// Written in narrowing order. `Connections` sits inside `Followers`
/// rather than beside it: an accepted connection counts as a follower
/// wherever followers are admitted, so the connections tier admits
/// strictly fewer people.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SectionVisibility {
    #[default]
    Public,
    Followers,
    Connections,
    Private,
}

/// Per-post visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PostVisibility {
    #[default]
    Public,
    Unlisted,
    Followers,
    Connections,
}

impl PostVisibility {
    /// The stored form, as the check constraint spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Unlisted => "unlisted",
            Self::Followers => "followers",
            Self::Connections => "connections",
        }
    }

    /// Read a stored value.
    ///
    /// An unrecognised string is the **narrowest** tier, not the
    /// widest: a value this build does not understand must not be the
    /// reason a post is published.
    pub fn from_stored(s: &str) -> Self {
        match s {
            "public" => Self::Public,
            "unlisted" => Self::Unlisted,
            "followers" => Self::Followers,
            _ => Self::Connections,
        }
    }
}

impl SectionVisibility {
    /// The stored form, as the check constraint spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Followers => "followers",
            Self::Connections => "connections",
            Self::Private => "private",
        }
    }

    /// Read a stored value, failing to the narrowest tier.
    pub fn from_stored(s: &str) -> Self {
        match s {
            "public" => Self::Public,
            "followers" => Self::Followers,
            "connections" => Self::Connections,
            _ => Self::Private,
        }
    }
}

/// Who may read one of an actor's relationship lists.
///
/// The same four values as [`SectionVisibility`], and a separate type
/// because the defaults differ: a profile section is public unless the
/// owner says otherwise, and a list is private unless they do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListVisibility {
    Public,
    Followers,
    Connections,
    #[default]
    Private,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_privacy_is_open() {
        let privacy = ActorPrivacy::default();
        assert!(privacy.discoverable);
        assert!(privacy.indexable);
        assert!(!privacy.require_follow_approval);
        assert!(privacy.federate_profile);
        assert!(privacy.chatmail_visible);
        assert!(privacy.show_followers_count);
        assert_eq!(privacy.cv_download, CvDownload::Public);
    }

    #[test]
    fn a_stored_visibility_round_trips() {
        for v in [
            PostVisibility::Public,
            PostVisibility::Unlisted,
            PostVisibility::Followers,
            PostVisibility::Connections,
        ] {
            assert_eq!(PostVisibility::from_stored(v.as_str()), v);
        }
        for v in [
            SectionVisibility::Public,
            SectionVisibility::Followers,
            SectionVisibility::Connections,
            SectionVisibility::Private,
        ] {
            assert_eq!(SectionVisibility::from_stored(v.as_str()), v);
        }
    }

    #[test]
    fn an_unknown_visibility_reads_as_the_narrowest_tier() {
        // Never `Public`. A value this build cannot parse must not be
        // the reason something is published.
        assert_eq!(
            PostVisibility::from_stored("mutuals"),
            PostVisibility::Connections
        );
        assert_eq!(PostVisibility::from_stored(""), PostVisibility::Connections);
        assert_eq!(
            SectionVisibility::from_stored("mutuals"),
            SectionVisibility::Private
        );
    }

    #[test]
    fn privacy_roundtrip_json() {
        let privacy = ActorPrivacy::default();
        let json = serde_json::to_string(&privacy).unwrap();
        let parsed: ActorPrivacy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.discoverable, privacy.discoverable);
        assert_eq!(parsed.cv_download, privacy.cv_download);
    }
}
