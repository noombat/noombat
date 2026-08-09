// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Domain-method authorisation: compile-time-checked visibility,
//! role dispatch, and interaction predicates.
//!
//! This module is the default authorisation code path. Every decision is
//! expressed as a method on the relevant domain type, with exhaustive
//! `match` on Rust enums so that adding a new variant produces a compilation
//! failure at every check site.

use crate::actor::{Actor, ActorStatus, InstanceRole};
use crate::privacy::{CvDownload, PostVisibility, SectionVisibility};

// ..... Follow status .....

/// The relationship of a viewer to the content owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowStatus {
    /// The viewer is an accepted follower of the owner.
    Accepted,
    /// The viewer has a pending (not yet accepted) follow request.
    Pending,
    /// The viewer does not follow the owner.
    None,
}

// ..... Section visibility .....

/// Trait implemented by profile section types that carry a
/// `visibility` field and support viewer-dependent access control.
pub trait VisibilityControlled {
    fn visibility(&self) -> SectionVisibility;

    /// Whether this section is visible to the given viewer.
    fn visible_to(
        &self,
        viewer: Option<&Actor>,
        owner_id: uuid::Uuid,
        follow_status: FollowStatus,
    ) -> bool {
        match self.visibility() {
            SectionVisibility::Public => true,
            SectionVisibility::Followers => follow_status == FollowStatus::Accepted,
            SectionVisibility::Private => {
                matches!(viewer, Some(v) if v.id == owner_id)
            }
        }
    }
}

// ..... Post visibility .....

/// Whether a post is visible to the given viewer.
pub fn post_visible_to(
    visibility: PostVisibility,
    viewer: Option<&Actor>,
    author_id: uuid::Uuid,
    follow_status: FollowStatus,
) -> bool {
    match visibility {
        PostVisibility::Public | PostVisibility::Unlisted => true,
        PostVisibility::Followers => {
            follow_status == FollowStatus::Accepted
                || matches!(viewer, Some(v) if v.id == author_id)
        }
    }
}

// ..... Actor role dispatch .....

impl Actor {
    /// Whether this actor may perform moderation actions (moderator or admin).
    pub fn may_moderate(&self) -> bool {
        matches!(
            self.instance_role,
            InstanceRole::Moderator | InstanceRole::Admin
        )
    }

    /// Whether this actor may perform administration actions (admin only).
    pub fn may_administer(&self) -> bool {
        matches!(self.instance_role, InstanceRole::Admin)
    }

    /// Whether this actor's account is active (not suspended).
    ///
    /// A silenced actor is still active: they may log in, post, and
    /// interact. They are merely excluded from public timelines and
    /// search indices (see [`Actor::is_silenced`]). A suspended actor
    /// is fully deactivated.
    pub fn is_active(&self) -> bool {
        match self.actor_status {
            ActorStatus::Active | ActorStatus::Silenced => true,
            ActorStatus::Suspended => false,
        }
    }

    /// Whether this actor has been silenced by a moderator.
    ///
    /// A silenced actor is excluded from public timelines, trending
    /// lists, and search indices, but remains accessible to users who
    /// explicitly follow them. The actor may still log in, post, and
    /// interact normally.
    pub fn is_silenced(&self) -> bool {
        matches!(self.actor_status, ActorStatus::Silenced)
    }

    /// Whether this actor has been suspended by a moderator.
    ///
    /// A suspended actor is fully deactivated: login is disabled, and
    /// federation requests receive `410 Gone`.
    pub fn is_suspended(&self) -> bool {
        matches!(self.actor_status, ActorStatus::Suspended)
    }

    /// Whether this actor's profile is discoverable in local search.
    pub fn is_discoverable(&self) -> bool {
        self.actor_privacy.discoverable
    }

    /// Whether the profile page emits a `noindex` meta tag.
    pub fn is_indexable(&self) -> bool {
        self.actor_privacy.indexable
    }

    /// Whether the full profile is included in outbound AP responses.
    pub fn should_federate_profile(&self) -> bool {
        self.actor_privacy.federate_profile
    }

    /// Whether inbound Follow activities require manual approval.
    pub fn requires_follow_approval(&self) -> bool {
        self.actor_privacy.require_follow_approval
    }

    /// Whether follower and following counts are publicly visible.
    pub fn shows_followers_count(&self) -> bool {
        self.actor_privacy.show_followers_count
    }

    /// Whether the CV may be downloaded by the given viewer.
    ///
    /// The owner always passes, as in [`Self::chatmail_visible_to`].
    /// Without that exemption `CvDownload::Followers` would deny owners
    /// their own CV, since nobody is an accepted follower of themselves.
    pub fn cv_downloadable_by(&self, viewer: Option<&Actor>, follow_status: FollowStatus) -> bool {
        if matches!(viewer, Some(v) if v.id == self.id) {
            return true;
        }

        match self.actor_privacy.cv_download {
            CvDownload::Public => true,
            CvDownload::Followers => follow_status == FollowStatus::Accepted,
            // The owner is the only viewer this admits, and the check
            // above has already returned for them.
            CvDownload::SelfOnly => false,
        }
    }

    /// Whether the Chatmail address is visible to the given viewer.
    pub fn chatmail_visible_to(&self, viewer: Option<&Actor>, follow_status: FollowStatus) -> bool {
        self.actor_privacy.chatmail_visible
            || matches!(viewer, Some(v) if v.id == self.id)
            || follow_status == FollowStatus::Accepted
    }
}

// ..... Interaction predicates .....

/// The result of checking whether a content owner has blocked the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRestriction {
    None,
    Blocked,
}

impl OwnerRestriction {
    pub fn may_view_profile(&self) -> bool {
        *self != OwnerRestriction::Blocked
    }

    pub fn may_send_message(&self) -> bool {
        *self != OwnerRestriction::Blocked
    }
}

/// The result of checking whether the viewer has muted the content author.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerRestriction {
    None,
    Muted,
}

impl ViewerRestriction {
    pub fn appears_in_feed(&self) -> bool {
        *self != ViewerRestriction::Muted
    }
}

/// Trait for querying block and mute relationships.
///
/// Defined in `noombat-core`; the database-backed implementation
/// resides in `noombat-api` (where connection pools are available).
#[async_trait::async_trait]
pub trait InteractionService: Send + Sync {
    /// Has `owner` blocked `viewer`? (access-control direction).
    async fn owner_restriction(&self, owner: &uuid::Uuid, viewer: &uuid::Uuid) -> OwnerRestriction;

    /// Has `viewer` muted `author`? (feed-filtering direction).
    async fn viewer_restriction(
        &self,
        viewer: &uuid::Uuid,
        author: &uuid::Uuid,
    ) -> ViewerRestriction;
}

// ..... Group roles .....

/// Role of a member within a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GroupRole {
    Member,
    Moderator,
    Admin,
}

/// Whether a group member may post, given the group's settings.
pub fn may_post_to_group(role: GroupRole, moderators_only: bool) -> bool {
    match (moderators_only, role) {
        (false, _) => true,
        (true, GroupRole::Moderator | GroupRole::Admin) => true,
        (true, GroupRole::Member) => false,
    }
}

/// Whether a group member may moderate the group.
pub fn may_moderate_group(role: GroupRole) -> bool {
    matches!(role, GroupRole::Moderator | GroupRole::Admin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::SectionVisibility;

    struct TestSection(SectionVisibility);
    impl VisibilityControlled for TestSection {
        fn visibility(&self) -> SectionVisibility {
            self.0
        }
    }

    fn make_actor(id: uuid::Uuid) -> Actor {
        use crate::privacy::ActorPrivacy;
        Actor {
            id,
            actor_type: crate::actor::ActorType::Individual,
            ap_id: String::new(),
            username: String::new(),
            display_name: None,
            headline: None,
            location: None,
            avatar_url: None,
            header_url: None,
            summary_md: None,
            summary_html: None,
            public_key_pem: String::new(),
            private_key_pem: None,
            ed25519_public_key: None,
            ed25519_private_key: None,
            domain: String::new(),
            is_local: true,
            inbox_url: None,
            instance_role: InstanceRole::User,
            actor_status: ActorStatus::Active,
            chat_requires_reprovisioning: false,
            chatmail_addr: None,
            orcid: None,
            moved_to: None,
            actor_privacy: ActorPrivacy::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn public_section_visible_to_anyone() {
        let s = TestSection(SectionVisibility::Public);
        let owner_id = uuid::Uuid::new_v4();
        assert!(s.visible_to(None, owner_id, FollowStatus::None));
    }

    #[test]
    fn followers_section_visible_to_accepted_follower() {
        let s = TestSection(SectionVisibility::Followers);
        let owner_id = uuid::Uuid::new_v4();
        assert!(s.visible_to(None, owner_id, FollowStatus::Accepted));
        assert!(!s.visible_to(None, owner_id, FollowStatus::None));
    }

    #[test]
    fn private_section_visible_only_to_owner() {
        let s = TestSection(SectionVisibility::Private);
        let owner_id = uuid::Uuid::new_v4();
        let owner = make_actor(owner_id);
        let other = make_actor(uuid::Uuid::new_v4());
        assert!(s.visible_to(Some(&owner), owner_id, FollowStatus::None));
        assert!(!s.visible_to(Some(&other), owner_id, FollowStatus::Accepted));
        assert!(!s.visible_to(None, owner_id, FollowStatus::None));
    }

    #[test]
    fn may_moderate_requires_moderator_or_admin() {
        let mut a = make_actor(uuid::Uuid::new_v4());
        a.instance_role = InstanceRole::User;
        assert!(!a.may_moderate());
        a.instance_role = InstanceRole::Moderator;
        assert!(a.may_moderate());
        a.instance_role = InstanceRole::Admin;
        assert!(a.may_moderate());
    }

    #[test]
    fn may_administer_requires_admin() {
        let mut a = make_actor(uuid::Uuid::new_v4());
        a.instance_role = InstanceRole::Moderator;
        assert!(!a.may_administer());
        a.instance_role = InstanceRole::Admin;
        assert!(a.may_administer());
    }

    #[test]
    fn cv_downloadable_respects_setting() {
        let owner_id = uuid::Uuid::new_v4();
        let mut owner = make_actor(owner_id);
        let other = make_actor(uuid::Uuid::new_v4());

        owner.actor_privacy.cv_download = CvDownload::Public;
        assert!(owner.cv_downloadable_by(Some(&other), FollowStatus::None));

        owner.actor_privacy.cv_download = CvDownload::Followers;
        assert!(!owner.cv_downloadable_by(Some(&other), FollowStatus::None));
        assert!(owner.cv_downloadable_by(Some(&other), FollowStatus::Accepted));

        owner.actor_privacy.cv_download = CvDownload::SelfOnly;
        assert!(!owner.cv_downloadable_by(Some(&other), FollowStatus::Accepted));
        assert!(owner.cv_downloadable_by(Some(&owner), FollowStatus::None));
    }

    #[test]
    fn cv_owner_is_exempt_from_every_setting() {
        let owner_id = uuid::Uuid::new_v4();
        let mut owner = make_actor(owner_id);

        // `Followers` is the case that bites: an owner does not follow
        // themselves, so without the exemption the setting would lock
        // them out of their own CV.
        for setting in [
            CvDownload::Public,
            CvDownload::Followers,
            CvDownload::SelfOnly,
        ] {
            owner.actor_privacy.cv_download = setting;
            assert!(
                owner.cv_downloadable_by(Some(&owner), FollowStatus::None),
                "the owner must reach their own CV under {setting:?}"
            );
        }
    }

    #[test]
    fn block_restriction() {
        assert!(OwnerRestriction::None.may_view_profile());
        assert!(!OwnerRestriction::Blocked.may_view_profile());
    }

    #[test]
    fn mute_restriction() {
        assert!(ViewerRestriction::None.appears_in_feed());
        assert!(!ViewerRestriction::Muted.appears_in_feed());
    }

    #[test]
    fn is_active_includes_silenced_excludes_suspended() {
        let mut a = make_actor(uuid::Uuid::new_v4());

        a.actor_status = ActorStatus::Active;
        assert!(a.is_active());
        assert!(!a.is_silenced());
        assert!(!a.is_suspended());

        // A silenced actor is still active (they can log in, post,
        // and interact), but excluded from public timelines.
        a.actor_status = ActorStatus::Silenced;
        assert!(a.is_active());
        assert!(a.is_silenced());
        assert!(!a.is_suspended());

        // A suspended actor is fully deactivated.
        a.actor_status = ActorStatus::Suspended;
        assert!(!a.is_active());
        assert!(!a.is_silenced());
        assert!(a.is_suspended());
    }

    #[test]
    fn group_role_posting() {
        assert!(may_post_to_group(GroupRole::Member, false));
        assert!(!may_post_to_group(GroupRole::Member, true));
        assert!(may_post_to_group(GroupRole::Moderator, true));
        assert!(may_post_to_group(GroupRole::Admin, true));
    }
}
