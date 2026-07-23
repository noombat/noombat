// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Job listing routes: CRUD endpoints for job listings.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::verify_bearer_token;
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/jobs", get(list_jobs))
        .route("/jobs/{id}", get(get_job).delete(delete_job))
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

// ..... Create a job listing .....

async fn create_job(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(params): Json<noombat_jobs::NewJobListing>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let job = noombat_jobs::create_job(&state.pool, actor.id, &state.domain, &params).await?;

    // Synchronise search index (fire-and-forget).
    crate::search_sync::index_job(&state.search, &job);

    Ok((StatusCode::CREATED, Json(job)))
}

// ..... Delete a job listing .....

async fn delete_job(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    // Development only: Require the admin token; proper ownership check will
    // use the authenticated principal from the authentication middleware.
    // Fetch the job to get the actor_id, then delete.
    let job = noombat_jobs::get_job(&state.pool, id).await?;
    noombat_jobs::delete_job(&state.pool, job.actor_id, id).await?;

    // Remove from search index (fire-and-forget).
    crate::search_sync::remove_from_index(&state.search, "jobs", &id.to_string());

    Ok(StatusCode::NO_CONTENT)
}
