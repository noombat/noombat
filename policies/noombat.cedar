// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Cedar policies for Noombat.

// ..... Ownership .....

// An actor who owns a resource may perform any action on it.
@id("owner-full-access")
permit(
    principal,
    action,
    resource
) when {
    context.is_owner == "true"
};

// ..... Public viewing .....

// Any actor may view a public resource.
@id("public-view")
permit(
    principal,
    action == Noombat::Action::"view",
    resource
) when {
    context.visibility == "public"
};

// ..... Followers-only viewing .....

// An accepted follower may view followers-only resources.
@id("followers-view")
permit(
    principal,
    action == Noombat::Action::"view",
    resource
) when {
    context.visibility == "followers" && context.is_follower == "true"
};

// ..... Post creation .....

// An actor may create a post on their own profile.
@id("self-create-post")
permit(
    principal,
    action == Noombat::Action::"create_post",
    resource
) when {
    context.is_owner == "true"
};

// ..... CV download .....

// Public CV: any actor may download.
@id("cv-download-public")
permit(
    principal,
    action == Noombat::Action::"download_cv",
    resource
) when {
    context.cv_download == "public"
};

// Followers-only CV: accepted followers may download.
@id("cv-download-followers")
permit(
    principal,
    action == Noombat::Action::"download_cv",
    resource
) when {
    context.cv_download == "followers" && context.is_follower == "true"
};

// Self-only CV: only the owner may download.
@id("cv-download-self")
permit(
    principal,
    action == Noombat::Action::"download_cv",
    resource
) when {
    context.cv_download == "self" && context.is_owner == "true"
};

// ..... Profile section management .....

// Only the profile owner may add or remove sections.
@id("self-manage-sections")
permit(
    principal,
    action == Noombat::Action::"manage_sections",
    resource
) when {
    context.is_owner == "true"
};

// ..... Job listing management .....

// Only the owner may edit or delete their job listings.
@id("self-manage-jobs")
permit(
    principal,
    action == Noombat::Action::"manage_job",
    resource
) when {
    context.is_owner == "true"
};

// ..... Job applications .....

// Any authenticated actor may apply to a job listing.
@id("authenticated-may-apply")
permit(
    principal,
    action == Noombat::Action::"apply",
    resource
) when {
    context.is_authenticated == "true"
};

// ..... Profile discoverability .....

// A profile may appear in search results only when discoverable.
@id("discoverable-search")
permit(
    principal,
    action == Noombat::Action::"search_index",
    resource
) when {
    context.discoverable == "true"
};

// ..... Profile federation .....

// Structured profile data (sections, publications, verified links)
// is included in federated AP responses only when federate_profile
// is enabled.
@id("federate-profile-data")
permit(
    principal,
    action == Noombat::Action::"federate_profile_data",
    resource
) when {
    context.federate_profile == "true"
};

// ..... Group posting .....

// A group member may post to the group.
@id("group-member-post")
permit(
    principal,
    action == Noombat::Action::"post_to_group",
    resource
) when {
    context has group_role
    && (context.group_role == "member"
        || context.group_role == "moderator"
        || context.group_role == "admin")
};

// ..... Group moderation .....

// A group moderator or admin may moderate content within the group.
@id("group-moderate")
permit(
    principal,
    action == Noombat::Action::"moderate",
    resource
) when {
    context has group_role
    && (context.group_role == "moderator" || context.group_role == "admin")
};

// A group admin may manage membership (promote, demote, ban).
@id("group-manage-members")
permit(
    principal,
    action == Noombat::Action::"manage_members",
    resource
) when {
    context has group_role && context.group_role == "admin"
};

// ..... Reporting .....

// Any authenticated actor may report content.
@id("authenticated-may-report")
permit(
    principal,
    action == Noombat::Action::"report",
    resource
) when {
    context.is_authenticated == "true"
};

// ..... Instance moderation .....

// Instance moderators and admins may resolve reports.
@id("moderator-resolve-report")
permit(
    principal,
    action == Noombat::Action::"resolve_report",
    resource
) when {
    context has instance_role
    && (context.instance_role == "moderator" || context.instance_role == "admin")
};

// Instance moderators and admins may suspend actors.
@id("moderator-suspend-actor")
permit(
    principal,
    action == Noombat::Action::"suspend_actor",
    resource
) when {
    context has instance_role
    && (context.instance_role == "moderator" || context.instance_role == "admin")
};

// Only instance admins may configure instance settings.
@id("admin-configure-instance")
permit(
    principal,
    action == Noombat::Action::"configure_instance",
    resource
) when {
    context has instance_role && context.instance_role == "admin"
};
