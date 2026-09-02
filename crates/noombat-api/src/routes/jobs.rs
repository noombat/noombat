// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Job posting routes: CRUD endpoints for job postings.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::{require_acts_for, require_local_actor};
use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/jobs", get(list_jobs))
        .route(
            "/jobs/{id}",
            get(get_job).patch(patch_job).delete(delete_job),
        )
        .route(
            "/users/{username}/jobs",
            get(list_user_jobs).post(create_job),
        )
}

// ..... List all published jobs .....

#[derive(Deserialize)]
struct PaginationQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    20
}

async fn list_jobs(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let jobs = noombat_jobs::list_published_jobs(&state.pool, query.limit, query.offset).await?;
    Ok((StatusCode::OK, Json(jobs)))
}

// ..... List jobs by a specific user .....

async fn list_user_jobs(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let jobs =
        noombat_jobs::list_jobs_by_actor(&state.pool, actor.id, query.limit, query.offset).await?;
    Ok((StatusCode::OK, Json(jobs)))
}

// ..... Get a single job .....

async fn get_job(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let job = noombat_jobs::get_job(&state.pool, id).await?;
    Ok((StatusCode::OK, Json(job)))
}

// ..... Create a job posting .....

async fn create_job(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(params): Json<noombat_jobs::NewJobPosting>,
) -> Result<impl IntoResponse, ApiError> {
    // An organisation is posted for by its members, never by itself, so
    // this admits both the account and anyone holding a role in it.
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    // An organisation publishes only once it has proved it controls the
    // domain it claims. Domain control is not identity verification, and
    // the refusal says so: it proves who runs a website at a point in
    // time, which is what stops a posting claiming an employer it has no
    // connection to.
    if actor.actor_type == noombat_core::actor::ActorType::Organization
        && !noombat_identity::verification::controls_claimed_domain(&state.pool, actor.id).await?
    {
        return Err(ApiError(noombat_core::error::NoombatError::Forbidden));
    }

    let job = noombat_jobs::create_job(
        &state.pool,
        actor.id,
        viewer.as_ref().map(|v| v.actor_id),
        &state.domain,
        &params,
    )
    .await?;

    // Synchronise search index (fire-and-forget).
    crate::search_sync::index_job(&state.search, &job);

    // The listing stays here; what travels is a Note. Fires on the
    // `published_at` transition, which is also the verification gate:
    // an unpublished posting publicises nothing.
    crate::jobs_federation::announce_published(&state.pool, &state.domain, &actor, &job).await;

    Ok((StatusCode::CREATED, Json(job)))
}

// ..... Edit a job posting .....

/// `PATCH /jobs/{id}`
///
/// The posting had no edit route at all: `update_job` was written,
/// tested and reachable from nowhere, and the edit form pointed at the
/// create route. Authorisation is the same as deletion's, settled
/// against the posting's own actor rather than anything the caller
/// supplies.
async fn patch_job(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(params): Json<noombat_jobs::UpdateJobPosting>,
) -> Result<impl IntoResponse, ApiError> {
    let job = noombat_jobs::get_job(&state.pool, id).await?;
    require_acts_for(&state.pool, job.actor_id, &viewer).await?;

    let updated = noombat_jobs::update_job(&state.pool, job.actor_id, id, &params).await?;

    // The index carries the title, description and location, so an edit
    // that does not reach it leaves search answering with the old text.
    crate::search_sync::index_job(&state.search, &updated);

    Ok((StatusCode::OK, Json(updated)))
}

// ..... Delete a job posting .....

async fn delete_job(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<StatusCode, ApiError> {
    // The posting names its own actor, so ownership is settled against
    // that rather than against anything the caller supplies.
    let job = noombat_jobs::get_job(&state.pool, id).await?;
    require_acts_for(&state.pool, job.actor_id, &viewer).await?;

    // Withdrawn before the row goes, because the Delete is built from
    // the posting's own AP id and the actor it names.
    let was_published = job.published_at.is_some();
    noombat_jobs::delete_job(&state.pool, job.actor_id, id).await?;

    // Remove from search index (fire-and-forget).
    crate::search_sync::remove_from_index(&state.search, "jobs", &id.to_string());

    if was_published {
        let organisation = noombat_identity::repo::find_by_id(&state.pool, job.actor_id).await?;
        let activity = crate::jobs_federation::withdrawing_delete(&organisation.ap_id, &job.ap_id);
        crate::jobs_federation::deliver(&state.pool, &organisation, &activity).await;
    }

    Ok(StatusCode::NO_CONTENT)
}
