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
use tracing::{error, warn};

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
    /// Organisation names from experience entries.
    pub experience_organizations: Vec<String>,
    /// Institution names from education entries.
    pub education_institutions: Vec<String>,
    /// Fields of study from education entries.
    pub education_fields: Vec<String>,
    /// ScholarlyArticle titles.
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
    if !actor.is_discoverable() {
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
        "experience_organizations": data.experience_organizations,
        "education_institutions": data.education_institutions,
        "education_fields": data.education_fields,
        "publication_titles": data.publication_titles,
        "location": actor.location,
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

    let skills = noombat_identity::profile::list_skills(
        pool,
        actor.id,
        &noombat_core::privacy::SectionVisibility::Public,
    )
    .await
    .unwrap_or_default();
    let work_experiences = noombat_identity::profile::list_work_experiences(pool, actor.id, vis)
        .await
        .unwrap_or_default();
    let education_entries = noombat_identity::profile::list_education_entries(pool, actor.id, vis)
        .await
        .unwrap_or_default();
    let scholarly_articles =
        noombat_identity::profile::list_scholarly_articles(pool, actor.id, vis)
            .await
            .unwrap_or_default();

    let data = ProfileSearchData {
        skills: skills.into_iter().map(|s| s.name).collect(),
        experience_titles: work_experiences.iter().map(|e| e.title.clone()).collect(),
        experience_organizations: work_experiences
            .iter()
            .map(|e| e.organization.clone())
            .collect(),
        education_institutions: education_entries
            .iter()
            .map(|e| e.institution.clone())
            .collect(),
        education_fields: education_entries
            .iter()
            .filter_map(|e| e.field_of_study.clone())
            .collect(),
        publication_titles: scholarly_articles.iter().map(|p| p.title.clone()).collect(),
    };

    index_profile(search, actor, &data);
}

/// Index a post in Meilisearch (fire-and-forget).
///
/// Only public posts are indexed; non-public posts are silently skipped.
/// Articles are indexed with their title and post type to enable
/// differentiated search results (e.g. displaying article titles in
/// search hits rather than content snippets).
///
/// Keyed on the post's primary key. Meilisearch document ids admit only
/// alphanumerics, hyphens and underscores, so the AP id (a URL) is
/// rejected outright: `add_or_replace` enqueues a task that then fails,
/// which the fire-and-forget spawn below reports as a warning and
/// nothing else. Passing the URL here meant no post was ever indexed.
///
/// `erasure::erase_actor` withdraws documents under this same key. The
/// two have to agree, so change them together.
pub struct IndexedPost<'a> {
    /// Primary key, and the search document id.
    pub id: uuid::Uuid,
    pub ap_id: &'a str,
    pub actor_id: &'a str,
    pub content_html: &'a str,
    pub visibility: &'a str,
    pub post_type: &'a str,
    pub title: Option<&'a str>,
    /// Whether the author is an account on this instance.
    ///
    /// Carried into the document as a filterable attribute so a reader
    /// can ask for this instance's own writing or for everything the
    /// index holds. Without it the two corpora are one and the choice
    /// cannot be offered.
    pub is_local: bool,
}

/// The document id and body sent to Meilisearch for a post.
///
/// Split out so a test can assert Meilisearch accepts it. The bug this
/// guards against was invisible from inside the process: `upsert`
/// returns as soon as the task is *enqueued*, so an identifier the
/// server rejects still looks like success to the caller.
pub fn post_document(post: &IndexedPost<'_>) -> (String, serde_json::Value) {
    (
        post.id.to_string(),
        json!({
            "id": post.id.to_string(),
            "ap_id": post.ap_id,
            "content": post.content_html,
            "actor_id": post.actor_id,
            "visibility": post.visibility,
            "post_type": post.post_type,
            "title": post.title,
            "is_local": post.is_local,
        }),
    )
}

pub fn index_post(search: &Option<Arc<dyn SearchBackend>>, post: &IndexedPost<'_>) {
    if post.visibility != "public" {
        return;
    }
    let Some(backend) = search.clone() else {
        return;
    };
    let (id, doc) = post_document(post);
    tokio::spawn(async move {
        if let Err(e) = backend.upsert("posts", &id, doc).await {
            warn!(id, error = %e, "failed to index post");
        }
    });
}

/// Index a job posting in Meilisearch (fire-and-forget).
pub fn index_job(search: &Option<Arc<dyn SearchBackend>>, job: &noombat_jobs::JobPosting) {
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
            warn!(id, error = %e, "failed to index job posting");
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

/// Remove a document, and record the work so a failure is not lost.
///
/// The durable counterpart to [`remove_from_index`], for the removals
/// that carry a rights consequence. A search document outlives the row
/// it was built from, so a removal dropped on the floor leaves erased
/// writing searchable by its full text and nothing says so.
///
/// The immediate attempt still happens, because the common case is that
/// it works and a queue round trip would only delay it. What changes is
/// the failure: the row stays pending and the worker retries it, and an
/// exhausted removal is shown to an administrator instead of appearing
/// once in a log nobody reads.
pub async fn remove_from_index_durably(
    pool: &sqlx::PgPool,
    search: &Option<Arc<dyn SearchBackend>>,
    index: &str,
    id: &str,
) {
    if let Err(e) = crate::search_ops::enqueue_removal(pool, index, id).await {
        // The enqueue itself failing is the one case with nowhere left
        // to record it, so it is loud.
        error!(index, id, error = %e, "search removal could not be recorded and may be lost");
    }

    let Some(backend) = search.as_ref() else {
        return;
    };

    // Cleared straight away on success, so the queue holds only what is
    // actually outstanding and the administration page means something.
    match backend.delete(index, id).await {
        Ok(()) => {
            if let Err(e) = sqlx::query(
                "UPDATE search_index_operations \
                 SET state = 'succeeded', completed_at = now() \
                 WHERE index_name = $1 AND document_id = $2 AND operation = 'remove'",
            )
            .bind(index)
            .bind(id)
            .execute(pool)
            .await
            {
                warn!(index, id, error = %e, "removal succeeded and could not be marked");
            }
        }
        // Left pending deliberately: the worker owns the retry, and
        // recording the reason here as well would race it.
        Err(e) => warn!(index, id, error = %e, "removal failed; queued for retry"),
    }
}
