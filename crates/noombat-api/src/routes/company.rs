// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Company features routes: candidate search and applicant management.
//!
//! - `GET  /api/v1/candidates`                              search candidates
//! - `GET  /api/v1/jobs/{id}/applications`                  list applications
//! - `POST /api/v1/jobs/{id}/applications/{app_id}/status`  update status
//!
//! Candidate search queries the Meilisearch `profiles` index filtered
//! by actor_type=Individual, returning only `public`-visibility data
//! from `discoverable` profiles (enforced at indexing time by
//! [`search_sync::index_profile`]).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use noombat_core::error::NoombatError;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/candidates", get(search_candidates))
        .route(
            "/api/v1/jobs/{job_id}/applications",
            get(list_applications),
        )
        .route(
            "/api/v1/jobs/{job_id}/applications/{app_id}/status",
            axum::routing::post(update_application_status),
        )
}

// ..... Candidate search .....

/// Query parameters for candidate search.
#[derive(Debug, Deserialize)]
struct CandidateSearchQuery {
    /// Free-text search query (skills, name, education, etc.).
    q: String,
    /// Maximum results (default: 20).
    #[serde(default = "default_limit")]
    limit: usize,
    /// Pagination offset (default: 0).
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    20
}

/// `GET /api/v1/candidates?q=rust&limit=10`
///
/// Searches the Meilisearch `profiles` index with an `actor_type =
/// Individual` filter. Only `public`-visibility data from
/// `discoverable` profiles is indexed (enforced at indexing time).
async fn search_candidates(
    State(state): State<AppState>,
    _principal: Option<axum::Extension<Principal>>,
    Query(query): Query<CandidateSearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let backend = state
        .search
        .as_ref()
        .ok_or_else(|| ApiError(NoombatError::ServiceUnavailable(
            "search is not configured".into(),
        )))?;

    let filter = r#"actor_type = "Individual""#;
    let results = backend
        .search("profiles", &query.q, Some(filter), query.limit, query.offset)
        .await?;

    debug!(
        query = query.q,
        results = results.len(),
        "candidate search completed"
    );

    Ok(Json(results))
}

// ..... Applicant management .....

/// A job application row for the management dashboard.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct ApplicationSummary {
    id: uuid::Uuid,
    applicant_id: uuid::Uuid,
    #[sqlx(rename = "applicant_username")]
    applicant_username: String,
    #[sqlx(rename = "applicant_display_name")]
    applicant_display_name: Option<String>,
    status: String,
    include_cv: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /api/v1/jobs/{job_id}/applications`
///
/// List all applications for a job listing. Requires that the
/// authenticated principal owns the job listing (or has a moderator
/// or admin role).
async fn list_applications(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Path(job_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let principal = principal
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?;

    // Verify the principal owns the job listing or is a moderator.
    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    let is_owner = principal
        .actor_uuid
        .map(|id| id == job.actor_id)
        .unwrap_or(false);
    let is_moderator = matches!(
        principal.instance_role,
        Some(noombat_core::actor::InstanceRole::Moderator | noombat_core::actor::InstanceRole::Admin)
    );

    if !is_owner && !is_moderator {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let applications = sqlx::query_as::<_, ApplicationSummary>(
        r#"
        SELECT
            a.id,
            a.applicant_id,
            act.username AS applicant_username,
            act.display_name AS applicant_display_name,
            a.status,
            a.include_cv,
            a.created_at,
            a.updated_at
        FROM applications a
        INNER JOIN actors act ON act.id = a.applicant_id
        WHERE a.job_listing_id = $1
        ORDER BY a.created_at DESC
        "#,
    )
    .bind(job_id)
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok(Json(applications))
}

/// Request body for updating application status.
#[derive(Debug, Deserialize)]
struct UpdateStatusRequest {
    /// New status: `reviewed`, `shortlisted`, `rejected`, `withdrawn`.
    status: String,
}

/// `POST /api/v1/jobs/{job_id}/applications/{app_id}/status`
///
/// Transition an application's status. Permitted transitions are
/// validated against the schema CHECK constraint.
async fn update_application_status(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Path((job_id, app_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(body): Json<UpdateStatusRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let principal = principal
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?;

    // Validate status value.
    let valid_statuses = ["submitted", "reviewed", "shortlisted", "rejected", "withdrawn"];
    if !valid_statuses.contains(&body.status.as_str()) {
        return Err(ApiError(NoombatError::BadRequest(format!(
            "invalid status: {} (expected one of: {})",
            body.status,
            valid_statuses.join(", ")
        ))));
    }

    // Verify the principal owns the job listing.
    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    let is_owner = principal
        .actor_uuid
        .map(|id| id == job.actor_id)
        .unwrap_or(false);

    if !is_owner {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let rows_affected = sqlx::query(
        "UPDATE applications SET status = $1, updated_at = NOW() \
         WHERE id = $2 AND job_listing_id = $3",
    )
    .bind(&body.status)
    .bind(app_id)
    .bind(job_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?
    .rows_affected();

    if rows_affected == 0 {
        return Err(ApiError(NoombatError::NotFound {
            entity: "application",
            id: app_id,
        }));
    }

    Ok(StatusCode::OK)
}
