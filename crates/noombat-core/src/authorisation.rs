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
use crate::privacy::{CvDownload, ListVisibility, PostVisibility, SectionVisibility};

// ..... The two axes of the social graph .....

/// The viewer's follow standing towards the content owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowStatus {
    /// The viewer is an accepted follower of the owner.
    Accepted,
    /// The viewer has a pending (not yet accepted) follow request.
    Pending,
    /// The viewer does not follow the owner.
    None,
}

/// The viewer's connection standing with the content owner.
///
/// Undirected once accepted, which is why there is no `Requested`
/// variant distinct from `Received`: for an access decision the only
/// thing that matters is whether the pair is joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// The invitation was accepted, by either side.
    Accepted,
    /// An invitation exists and nobody has answered it.
    Pending,
    /// No invitation exists.
    None,
}

/// A viewer's standing towards one other actor, on both axes at once.
///
/// The two states are **independent**, not a ladder, and that
/// independence is the safety property: a connection is granted by an
/// act and revoked by an act, so what it admits cannot drift with
/// follow churn. Somebody who unfollows a connection keeps the
/// connection, and somebody who withdraws a connection keeps the
/// follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relationship {
    pub follow: FollowStatus,
    pub connection: ConnectionState,
}

impl Default for Relationship {
    fn default() -> Self {
        Self::NONE
    }
}

impl Relationship {
    /// A stranger, and the value to use for an anonymous viewer.
    pub const NONE: Self = Self {
        follow: FollowStatus::None,
        connection: ConnectionState::None,
    };

    /// Whether the viewer is admitted wherever followers are.
    ///
    /// **This is the nesting rule, and it lives here on purpose.** An
    /// accepted connection counts as a follower for followers-tier
    /// content whatever the follow state says. Written once it is a
    /// rule; written at each call site it is one chance per site to get
    /// it wrong.
    pub fn is_follower(&self) -> bool {
        self.follow == FollowStatus::Accepted || self.connection == ConnectionState::Accepted
    }

    /// Whether the viewer holds an accepted connection.
    pub fn is_connection(&self) -> bool {
        self.connection == ConnectionState::Accepted
    }
}

// ..... Section visibility .....

/// Trait implemented by profile section types that carry a
/// `visibility` field and support viewer-dependent access control.
///
/// The viewer is a bare `Option<uuid::Uuid>` because identity is the
/// only thing any of these predicates reads. Taking `Option<&Actor>`
/// obliged a route holding a session to load a whole actor, key
/// material included, to answer a comparison of two UUIDs, and that
/// cost is why the routes stopped calling them.
pub trait VisibilityControlled {
    fn visibility(&self) -> SectionVisibility;

    /// Whether this section is visible to the given viewer.
    fn visible_to(
        &self,
        viewer: Option<uuid::Uuid>,
        owner_id: uuid::Uuid,
        relationship: &Relationship,
    ) -> bool {
        // The owner reaches their own section under every setting, as
        // in `cv_downloadable_by`. Without this, `Followers` and
        // `Connections` would lock an owner out of their own profile,
        // since nobody follows or connects to themselves.
        if viewer == Some(owner_id) {
            return true;
        }

        match self.visibility() {
            SectionVisibility::Public => true,
            SectionVisibility::Followers => relationship.is_follower(),
            SectionVisibility::Connections => relationship.is_connection(),
            SectionVisibility::Private => false,
        }
    }
}

/// The widest section tier a viewer qualifies for.
///
/// Section queries take a maximum tier and return everything at or
/// below it, so this is the one place that decides how far down a given
/// viewer sees. The profile page, the CV and the federated document all
/// ask it, which is what stops them disagreeing: the profile page used
/// to pass `Public` unconditionally, so an owner could not see their own
/// followers-only sections on their own profile.
pub fn section_tier_for(
    viewer: Option<uuid::Uuid>,
    owner_id: uuid::Uuid,
    relationship: &Relationship,
) -> SectionVisibility {
    if viewer == Some(owner_id) {
        SectionVisibility::Private
    } else if relationship.is_connection() {
        SectionVisibility::Connections
    } else if relationship.is_follower() {
        SectionVisibility::Followers
    } else {
        SectionVisibility::Public
    }
}

// ..... List visibility .....

/// Whether one of an actor's relationship lists is visible to a viewer.
///
/// A free function rather than a method, because the three lists differ
/// only by which column supplies the setting.
pub fn list_visible_to(
    visibility: ListVisibility,
    viewer: Option<uuid::Uuid>,
    owner_id: uuid::Uuid,
    relationship: &Relationship,
) -> bool {
    if viewer == Some(owner_id) {
        return true;
    }

    match visibility {
        ListVisibility::Public => true,
        ListVisibility::Followers => relationship.is_follower(),
        ListVisibility::Connections => relationship.is_connection(),
        ListVisibility::Private => false,
    }
}

// ..... Post visibility .....

/// Whether a post is visible to the given viewer.
pub fn post_visible_to(
    visibility: PostVisibility,
    viewer: Option<uuid::Uuid>,
    author_id: uuid::Uuid,
    relationship: &Relationship,
) -> bool {
    if viewer == Some(author_id) {
        return true;
    }

    match visibility {
        PostVisibility::Public | PostVisibility::Unlisted => true,
        PostVisibility::Followers => relationship.is_follower(),
        PostVisibility::Connections => relationship.is_connection(),
    }
}

// ..... Role and status dispatch .....

/// The two role predicates, on the enum rather than on [`Actor`].
///
/// A request holds a role without holding an actor, so a rule that
/// could only be asked of a loaded `Actor` was re-implemented inline at
/// every guard. Both holders now delegate here, so there is one rule.
impl InstanceRole {
    /// Whether this role may perform moderation actions.
    pub fn may_moderate(self) -> bool {
        matches!(self, InstanceRole::Moderator | InstanceRole::Admin)
    }

    /// Whether this role may perform administration actions.
    pub fn may_administer(self) -> bool {
        matches!(self, InstanceRole::Admin)
    }
}

/// The status predicates, on the enum for the same reason as
/// [`InstanceRole`]'s.
impl ActorStatus {
    /// Whether the account is active (not suspended, not pending).
    ///
    /// A silenced account is still active: it may log in, post, and
    /// interact. It is merely excluded from public timelines and
    /// search indices (see [`ActorStatus::is_silenced`]). A suspended
    /// account is fully deactivated, and a pending one has not been
    /// admitted yet, so neither is active.
    ///
    /// The arms are written out rather than ending in a wildcard: a
    /// later variant should be a compile error here, not a silent
    /// admission.
    pub fn is_active(self) -> bool {
        match self {
            ActorStatus::Active | ActorStatus::Silenced => true,
            ActorStatus::Pending | ActorStatus::Suspended => false,
        }
    }

    /// Whether the account is awaiting admission.
    ///
    /// True only where `registration_mode` is `approval` and no
    /// administrator has acted yet. Distinct from suspension: nothing
    /// has been taken away, because nothing was granted.
    pub fn is_pending(self) -> bool {
        matches!(self, ActorStatus::Pending)
    }

    /// Whether the account has been silenced by a moderator.
    ///
    /// A silenced account is excluded from public timelines, trending
    /// lists, and search indices, but remains accessible to users who
    /// explicitly follow it. It may still log in, post, and interact
    /// normally.
    pub fn is_silenced(self) -> bool {
        matches!(self, ActorStatus::Silenced)
    }

    /// Whether the account has been suspended by a moderator.
    ///
    /// A suspended account is fully deactivated: login is disabled, and
    /// federation requests receive `410 Gone`.
    pub fn is_suspended(self) -> bool {
        matches!(self, ActorStatus::Suspended)
    }
}

impl Actor {
    /// Whether this actor may perform moderation actions (moderator or admin).
    pub fn may_moderate(&self) -> bool {
        self.instance_role.may_moderate()
    }

    /// Whether this actor may perform administration actions (admin only).
    pub fn may_administer(&self) -> bool {
        self.instance_role.may_administer()
    }

    /// Whether this actor's account is active (not suspended, not pending).
    pub fn is_active(&self) -> bool {
        self.actor_status.is_active()
    }

    /// Whether this actor is awaiting admission.
    pub fn is_pending(&self) -> bool {
        self.actor_status.is_pending()
    }

    /// Whether this actor has been silenced by a moderator.
    pub fn is_silenced(&self) -> bool {
        self.actor_status.is_silenced()
    }

    /// Whether this actor has been suspended by a moderator.
    pub fn is_suspended(&self) -> bool {
        self.actor_status.is_suspended()
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
    pub fn cv_downloadable_by(
        &self,
        viewer: Option<uuid::Uuid>,
        relationship: &Relationship,
    ) -> bool {
        if viewer == Some(self.id) {
            return true;
        }

        match self.actor_privacy.cv_download {
            CvDownload::Public => true,
            CvDownload::Followers => relationship.is_follower(),
            // The owner is the only viewer this admits, and the check
            // above has already returned for them.
            CvDownload::SelfOnly => false,
        }
    }

    /// Whether the Chatmail address is visible to the given viewer.
    pub fn chatmail_visible_to(
        &self,
        viewer: Option<uuid::Uuid>,
        relationship: &Relationship,
    ) -> bool {
        self.actor_privacy.chatmail_visible || viewer == Some(self.id) || relationship.is_follower()
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

/// Standing of an actor within an organisation actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OrganizationRole {
    /// Acts for the organisation on every posting, and sets who else may.
    Owner,
    /// Acts on the postings they created, and on those a posting has
    /// been opened to.
    Recruiter,
}

/// Who, besides the owners and the creator, may read a posting's
/// job_applications. Set per posting by an owner or by its creator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PostingAccess {
    /// Nobody. The default: a recruiter's posting is not every
    /// recruiter's business until somebody says so.
    CreatorOnly,
    /// Every recruiter in the organisation.
    AllRecruiters,
    /// The recruiters named in the posting's reader set.
    Listed,
}

/// Whether an actor may read and act on a posting's job_applications.
///
/// `is_creator` is the member who created the posting, `is_listed` is
/// membership of its reader set. A non-member is refused whatever those
/// say, so naming an outsider in a reader set grants nothing.
pub fn may_access_job_applications(
    role: Option<OrganizationRole>,
    access: PostingAccess,
    is_creator: bool,
    is_listed: bool,
) -> bool {
    match role {
        None => false,
        // Never lockable out: the account that fixes a mistake cannot be
        // the one a mistake locks out.
        Some(OrganizationRole::Owner) => true,
        Some(OrganizationRole::Recruiter) => {
            is_creator
                || match access {
                    PostingAccess::CreatorOnly => false,
                    PostingAccess::AllRecruiters => true,
                    PostingAccess::Listed => is_listed,
                }
        }
    }
}

/// Whether an actor may change who reads a posting's job_applications.
///
/// Owners, and the recruiter who created it. A recruiter opening their
/// own posting to colleagues does not need an owner to do it for them,
/// and cannot widen anybody else's.
pub fn may_delegate_posting(role: Option<OrganizationRole>, is_creator: bool) -> bool {
    matches!(role, Some(OrganizationRole::Owner)) || (role.is_some() && is_creator)
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
            public_key_id: None,
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

    /// A viewer who follows and is not connected.
    fn follower() -> Relationship {
        Relationship {
            follow: FollowStatus::Accepted,
            connection: ConnectionState::None,
        }
    }

    /// A viewer who is connected and does not follow. The case the
    /// nesting rule exists for.
    fn connection() -> Relationship {
        Relationship {
            follow: FollowStatus::None,
            connection: ConnectionState::Accepted,
        }
    }

    #[test]
    fn public_section_visible_to_anyone() {
        let s = TestSection(SectionVisibility::Public);
        let owner_id = uuid::Uuid::new_v4();
        assert!(s.visible_to(None, owner_id, &Relationship::NONE));
    }

    #[test]
    fn followers_section_visible_to_accepted_follower() {
        let s = TestSection(SectionVisibility::Followers);
        let owner_id = uuid::Uuid::new_v4();
        assert!(s.visible_to(None, owner_id, &follower()));
        assert!(!s.visible_to(None, owner_id, &Relationship::NONE));
    }

    #[test]
    fn private_section_visible_only_to_owner() {
        let s = TestSection(SectionVisibility::Private);
        let owner_id = uuid::Uuid::new_v4();
        let other_id = uuid::Uuid::new_v4();
        assert!(s.visible_to(Some(owner_id), owner_id, &Relationship::NONE));
        assert!(!s.visible_to(Some(other_id), owner_id, &follower()));
        assert!(!s.visible_to(None, owner_id, &Relationship::NONE));
    }

    #[test]
    fn a_connection_is_admitted_wherever_followers_are() {
        // The nesting rule. A connection who does not follow still
        // reaches followers-tier content, and the rule lives in
        // `Relationship` so no call site has to remember it.
        let owner_id = uuid::Uuid::new_v4();
        let s = TestSection(SectionVisibility::Followers);
        assert!(s.visible_to(None, owner_id, &connection()));

        assert!(post_visible_to(
            PostVisibility::Followers,
            None,
            owner_id,
            &connection()
        ));
    }

    #[test]
    fn the_connections_tier_does_not_admit_a_mere_follower() {
        // The converse, which is the half that makes the tier worth
        // having: nesting runs one way only.
        let owner_id = uuid::Uuid::new_v4();
        let s = TestSection(SectionVisibility::Connections);
        assert!(s.visible_to(None, owner_id, &connection()));
        assert!(!s.visible_to(None, owner_id, &follower()));

        assert!(post_visible_to(
            PostVisibility::Connections,
            None,
            owner_id,
            &connection()
        ));
        assert!(!post_visible_to(
            PostVisibility::Connections,
            None,
            owner_id,
            &follower()
        ));
    }

    #[test]
    fn a_pending_relationship_grants_nothing_on_either_axis() {
        let owner_id = uuid::Uuid::new_v4();
        let pending = Relationship {
            follow: FollowStatus::Pending,
            connection: ConnectionState::Pending,
        };
        assert!(!pending.is_follower());
        assert!(!pending.is_connection());

        for tier in [SectionVisibility::Followers, SectionVisibility::Connections] {
            assert!(
                !TestSection(tier).visible_to(None, owner_id, &pending),
                "{tier:?}"
            );
        }
    }

    #[test]
    fn the_owner_reaches_every_tier_of_their_own_profile() {
        // Nobody follows or connects to themselves, so without the
        // exemption an owner is locked out of their own section by the
        // two middle tiers. Same reasoning as `cv_downloadable_by`.
        let owner_id = uuid::Uuid::new_v4();
        for tier in [
            SectionVisibility::Public,
            SectionVisibility::Followers,
            SectionVisibility::Connections,
            SectionVisibility::Private,
        ] {
            assert!(
                TestSection(tier).visible_to(Some(owner_id), owner_id, &Relationship::NONE),
                "{tier:?}"
            );
        }
    }

    #[test]
    fn the_two_axes_are_independent() {
        // Losing a follow must not lose what a connection granted, and
        // losing a connection must not lose what a follow granted.
        let dropped_follow = Relationship {
            follow: FollowStatus::None,
            connection: ConnectionState::Accepted,
        };
        assert!(dropped_follow.is_follower());
        assert!(dropped_follow.is_connection());

        let dropped_connection = Relationship {
            follow: FollowStatus::Accepted,
            connection: ConnectionState::None,
        };
        assert!(dropped_connection.is_follower());
        assert!(!dropped_connection.is_connection());
    }

    #[test]
    fn a_list_is_private_by_default_and_the_owner_still_reads_it() {
        let owner_id = uuid::Uuid::new_v4();
        let other_id = uuid::Uuid::new_v4();
        let setting = ListVisibility::default();
        assert_eq!(setting, ListVisibility::Private);

        assert!(list_visible_to(
            setting,
            Some(owner_id),
            owner_id,
            &Relationship::NONE
        ));
        assert!(!list_visible_to(
            setting,
            Some(other_id),
            owner_id,
            &connection()
        ));
        assert!(!list_visible_to(setting, None, owner_id, &follower()));
    }

    #[test]
    fn a_list_follows_the_same_tiers_as_a_section() {
        let owner_id = uuid::Uuid::new_v4();
        assert!(list_visible_to(
            ListVisibility::Public,
            None,
            owner_id,
            &Relationship::NONE
        ));
        assert!(list_visible_to(
            ListVisibility::Followers,
            None,
            owner_id,
            &connection()
        ));
        assert!(!list_visible_to(
            ListVisibility::Connections,
            None,
            owner_id,
            &follower()
        ));
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
        let other_id = uuid::Uuid::new_v4();

        owner.actor_privacy.cv_download = CvDownload::Public;
        assert!(owner.cv_downloadable_by(Some(other_id), &Relationship::NONE));

        owner.actor_privacy.cv_download = CvDownload::Followers;
        assert!(!owner.cv_downloadable_by(Some(other_id), &Relationship::NONE));
        assert!(owner.cv_downloadable_by(Some(other_id), &follower()));
        // The nesting rule reaches the CV too: a connection who does
        // not follow is admitted by a `Followers` setting.
        assert!(owner.cv_downloadable_by(Some(other_id), &connection()));

        owner.actor_privacy.cv_download = CvDownload::SelfOnly;
        assert!(!owner.cv_downloadable_by(Some(other_id), &follower()));
        assert!(owner.cv_downloadable_by(Some(owner_id), &Relationship::NONE));
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
                owner.cv_downloadable_by(Some(owner_id), &Relationship::NONE),
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

    #[test]
    fn a_non_member_is_refused_whatever_the_posting_says() {
        for access in [
            PostingAccess::CreatorOnly,
            PostingAccess::AllRecruiters,
            PostingAccess::Listed,
        ] {
            // Even flagged as creator and listed: membership comes first.
            assert!(
                !may_access_job_applications(None, access, true, true),
                "{access:?}"
            );
        }
        assert!(!may_delegate_posting(None, true));
    }

    #[test]
    fn a_recruiters_posting_is_not_every_recruiters_business() {
        // The default. Another recruiter is refused until somebody opens it.
        let other = may_access_job_applications(
            Some(OrganizationRole::Recruiter),
            PostingAccess::CreatorOnly,
            false,
            false,
        );
        assert!(!other);
        // The creator keeps their own.
        assert!(may_access_job_applications(
            Some(OrganizationRole::Recruiter),
            PostingAccess::CreatorOnly,
            true,
            false
        ));
    }

    #[test]
    fn an_owner_reads_every_posting_and_cannot_be_locked_out() {
        for access in [
            PostingAccess::CreatorOnly,
            PostingAccess::AllRecruiters,
            PostingAccess::Listed,
        ] {
            assert!(
                may_access_job_applications(Some(OrganizationRole::Owner), access, false, false),
                "{access:?}"
            );
        }
    }

    #[test]
    fn opening_a_posting_admits_recruiters_by_the_two_routes() {
        let all = may_access_job_applications(
            Some(OrganizationRole::Recruiter),
            PostingAccess::AllRecruiters,
            false,
            false,
        );
        assert!(all, "all_recruiters admits any recruiter");

        assert!(may_access_job_applications(
            Some(OrganizationRole::Recruiter),
            PostingAccess::Listed,
            false,
            true
        ));
        assert!(!may_access_job_applications(
            Some(OrganizationRole::Recruiter),
            PostingAccess::Listed,
            false,
            false
        ));
    }

    #[test]
    fn only_an_owner_or_the_creator_may_open_a_posting() {
        assert!(may_delegate_posting(Some(OrganizationRole::Owner), false));
        assert!(may_delegate_posting(
            Some(OrganizationRole::Recruiter),
            true
        ));
        // A recruiter cannot widen a colleague's posting.
        assert!(!may_delegate_posting(
            Some(OrganizationRole::Recruiter),
            false
        ));
    }
}
