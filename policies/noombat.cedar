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

// Self-only CV: only the owner may download.
@id("cv-download-self")
permit(
    principal,
    action == Noombat::Action::"download_cv",
    resource
) when {
    context.cv_download == "self" && context.is_owner == "true"
};
