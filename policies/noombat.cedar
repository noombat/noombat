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
