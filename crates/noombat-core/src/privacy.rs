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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SectionVisibility {
    #[default]
    Public,
    Followers,
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
    fn privacy_roundtrip_json() {
        let privacy = ActorPrivacy::default();
        let json = serde_json::to_string(&privacy).unwrap();
        let parsed: ActorPrivacy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.discoverable, privacy.discoverable);
        assert_eq!(parsed.cv_download, privacy.cv_download);
    }
}
