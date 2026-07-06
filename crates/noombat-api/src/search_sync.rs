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

/// Index a profile in Meilisearch (fire-and-forget).
///
/// `skill_names` should contain the public skill names for the actor.
/// Passing an empty slice is valid, i.e. the document is still indexed, but
/// skill-based searches will not match it.
///
/// Spawns a background task; the caller is not blocked.
pub fn index_profile(
    search: &Option<Arc<dyn SearchBackend>>,
    actor: &Actor,
    skill_names: &[String],
) {
    let Some(backend) = search.clone() else {
        return;
    };
    if !actor.actor_privacy.discoverable {
        return;
    }
    let doc = json!({
        "id": actor.id.to_string(),
        "display_name": actor.display_name,
        "summary": actor.summary_html,
        "skills": skill_names,
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

/// Index a post in Meilisearch (fire-and-forget).
///
/// Only public posts are indexed; non-public posts are silently skipped.
pub fn index_post(
    search: &Option<Arc<dyn SearchBackend>>,
    post_id: &str,
    actor_id: &str,
    content_html: &str,
    visibility: &str,
) {
    if visibility != "public" {
        return;
    }
    let Some(backend) = search.clone() else {
        return;
    };
    let doc = json!({
        "id": post_id,
        "content": content_html,
        "actor_id": actor_id,
        "visibility": visibility,
    });
    let id = post_id.to_owned();
    tokio::spawn(async move {
        if let Err(e) = backend.upsert("posts", &id, doc).await {
            warn!(id, error = %e, "failed to index post");
        }
    });
}

/// Index a job listing in Meilisearch (fire-and-forget).
pub fn index_job(
    search: &Option<Arc<dyn SearchBackend>>,
    job: &noombat_jobs::JobListing,
) {
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
    });
    let id = job.id.to_string();
    tokio::spawn(async move {
        if let Err(e) = backend.upsert("jobs", &id, doc).await {
            warn!(id, error = %e, "failed to index job listing");
        }
    });
}

/// Remove a document from a Meilisearch index (fire-and-forget).
pub fn remove_from_index(
    search: &Option<Arc<dyn SearchBackend>>,
    index: &str,
    id: &str,
) {
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
