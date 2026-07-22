// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Search index synchronisation helpers.
//!
//! These functions build Meilisearch documents from domain objects and
//! upsert them via the [`SearchBackend`] extension point. All calls
//! are fire-and-forget: a Meilisearch failure is logged but does not
//! propagate to the caller.

use std::sync::Arc;

use noombat_core::actor::Actor;
use noombat_core::extension::SearchBackend;
use serde_json::json;
use tracing::warn;

/// Flattened profile section data for the search index.
///
/// Each field contains the `public`-visibility entries only, pre-extracted
/// by the caller. The search index never includes `followers`- or
/// `private`-visibility data.
#[derive(Debug, Clone, Default)]
pub struct ProfileSearchData {
    /// Skill names (e.g. `["Rust", "ActivityPub"]`).
    pub skills: Vec<String>,
    /// Job titles from experience entries (e.g. `["Senior Engineer"]`).
    pub experience_titles: Vec<String>,
    /// Company names from experience entries.
    pub experience_companies: Vec<String>,
    /// Institution names from education entries.
    pub education_institutions: Vec<String>,
    /// Fields of study from education entries.
    pub education_fields: Vec<String>,
    /// Publication titles.
    pub publication_titles: Vec<String>,
}

/// Index a profile in Meilisearch (fire-and-forget).
///
/// `data` contains the public-visibility profile section summaries.
/// The search document includes: name, skills, education, experience,
/// publications, location, and ORCID.
///
/// Spawns a background task; the caller is not blocked.
pub fn index_profile(
    search: &Option<Arc<dyn SearchBackend>>,
    actor: &Actor,
    data: &ProfileSearchData,
) {
    let Some(backend) = search.clone() else {
        return;
    };
    if !actor.actor_privacy.discoverable {
        return;
    }
    // Silenced actors are excluded from search indices. They remain
    // accessible to explicit followers via direct URL, but should not
    // appear in public search results.
    if actor.is_silenced() {
        return;
    }
    let doc = json!({
        "id": actor.id.to_string(),
        "display_name": actor.display_name,
        "summary": actor.summary_html,
        "skills": data.skills,
        "experience_titles": data.experience_titles,
        "experience_companies": data.experience_companies,
        "education_institutions": data.education_institutions,
        "education_fields": data.education_fields,
        "publication_titles": data.publication_titles,
        // TODO: the `actors` table has no dedicated `location` column.
        // `headline` is used as a best-effort placeholder; it may contain
        // geographic tokens (e.g. "Senior Rust Engineer at Acme Corp, Berlin")
        // but is semantically a professional tagline, not a location. Replace
        // with a dedicated column when the schema is extended.
        "location": actor.headline,
        "orcid": actor.orcid,
        "actor_type": format!("{:?}", actor.actor_type),
        "username": actor.username,
        "visibility": "public",
    });
    let id = actor.id.to_string();
    tokio::spawn(async move {
        if let Err(e) = backend.upsert("profiles", &id, doc).await {
            warn!(id, error = %e, "failed to index profile");
        }
    });
}

/// Fetch the actor's current public profile sections from the database
/// and re-index the profile in Meilisearch (fire-and-forget).
///
/// This is the canonical single-point implementation. All call sites
/// that need to refresh the search index after a profile-section
/// mutation should use this function rather than inlining the
/// fetch-and-build logic.
///
/// Only `public`-visibility entries are included. Errors from the database
/// queries are silently swallowed (the index update is best-effort);
/// Meilisearch errors are logged by [`index_profile`].
pub async fn reindex_profile_from_db(
    pool: &sqlx::PgPool,
    search: &Option<Arc<dyn SearchBackend>>,
    actor: &Actor,
) {
    use noombat_core::privacy::SectionVisibility;

    let vis = &SectionVisibility::Public;

    let skills = noombat_identity::profile::list_skills(pool, actor.id, false)
        .await
        .unwrap_or_default();
    let experiences = noombat_identity::profile::list_experiences(pool, actor.id, vis)
        .await
        .unwrap_or_default();
    let educations = noombat_identity::profile::list_educations(pool, actor.id, vis)
        .await
        .unwrap_or_default();
    let publications = noombat_identity::profile::list_publications(pool, actor.id, vis)
        .await
        .unwrap_or_default();

    let data = ProfileSearchData {
        skills: skills.into_iter().map(|s| s.name).collect(),
        experience_titles: experiences.iter().map(|e| e.title.clone()).collect(),
        experience_companies: experiences.iter().map(|e| e.company.clone()).collect(),
        education_institutions: educations.iter().map(|e| e.institution.clone()).collect(),
        education_fields: educations
            .iter()
            .filter_map(|e| e.field_of_study.clone())
            .collect(),
        publication_titles: publications.iter().map(|p| p.title.clone()).collect(),
    };

    index_profile(search, actor, &data);
}

/// Index a post in Meilisearch (fire-and-forget).
///
/// Only public posts are indexed; non-public posts are silently skipped.
/// Articles are indexed with their title and post type to enable
/// differentiated search results (e.g. displaying article titles in
/// search hits rather than content snippets).
pub fn index_post(
    search: &Option<Arc<dyn SearchBackend>>,
    post_id: &str,
    actor_id: &str,
    content_html: &str,
    visibility: &str,
    post_type: &str,
    title: Option<&str>,
) {
    if visibility != "public" {
        return;
    }
    let Some(backend) = search.clone() else {
        return;
    };
    let doc = json!({
        "id": post_id,
        "ap_id": post_id,
        "content": content_html,
        "actor_id": actor_id,
        "visibility": visibility,
        "post_type": post_type,
        "title": title,
    });
    let id = post_id.to_owned();
    tokio::spawn(async move {
        if let Err(e) = backend.upsert("posts", &id, doc).await {
            warn!(id, error = %e, "failed to index post");
        }
    });
}

/// Index a job listing in Meilisearch (fire-and-forget).
pub fn index_job(search: &Option<Arc<dyn SearchBackend>>, job: &noombat_jobs::JobListing) {
    let Some(backend) = search.clone() else {
        return;
    };
    let doc = json!({
        "id": job.id.to_string(),
        "title": job.title,
        "description": job.description_html,
        "actor_id": job.actor_id.to_string(),
        "location": job.location,
        "remote": job.remote,
        "status": if job.published_at.is_some() { "published" } else { "draft" },
        "created_at": job.created_at.to_rfc3339(),
    });
    let id = job.id.to_string();
    tokio::spawn(async move {
        if let Err(e) = backend.upsert("jobs", &id, doc).await {
            warn!(id, error = %e, "failed to index job listing");
        }
    });
}

/// Remove a document from a Meilisearch index (fire-and-forget).
pub fn remove_from_index(search: &Option<Arc<dyn SearchBackend>>, index: &str, id: &str) {
    let Some(backend) = search.clone() else {
        return;
    };
    let index = index.to_owned();
    let id = id.to_owned();
    tokio::spawn(async move {
        if let Err(e) = backend.delete(&index, &id).await {
            warn!(index, id, error = %e, "failed to remove from index");
        }
    });
}
