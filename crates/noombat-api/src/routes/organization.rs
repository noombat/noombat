// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Organization features routes: candidate search and applicant management.
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
use noombat_core::authorisation::{ListingAccess, OrganizationRole, may_access_applications};
use noombat_core::error::NoombatError;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/candidates", get(search_candidates))
        .route("/api/v1/jobs/{job_id}/applications", get(list_applications))
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
    let backend = state.search.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "search is not configured".into(),
        ))
    })?;

    let filter = r#"actor_type = "Individual""#;
    let results = backend
        .search(
            "profiles",
            &query.q,
            Some(filter),
            query.limit,
            query.offset,
        )
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
/// List all applications for a job listing. Requires an owner of the
/// publishing company, the recruiter who created the listing, or a
/// recruiter the listing has been opened to.
///
/// Moderators are **not** admitted here. They read one application at a
/// time through `moderation::review_application`, which states a reason
/// and writes it to the applicant's own access log.
async fn list_applications(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Path(job_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let principal = principal
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?;

    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    let permitted = match principal.actor_uuid {
        Some(actor_id) => {
            let s = company_standing(&state.pool, job.actor_id, job_id, actor_id).await?;
            may_access_applications(s.role, s.access, s.is_creator, s.is_listed)
        }
        // An admin-token principal carries no actor.
        None => false,
    };

    if !permitted {
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

/// An actor's standing for one listing. The publishing actor counts as
/// `Owner` without a membership row, so a company posting as itself is
/// not locked out of its own applications.
struct Standing {
    role: Option<OrganizationRole>,
    access: ListingAccess,
    is_creator: bool,
    is_listed: bool,
}

async fn company_standing(
    pool: &sqlx::PgPool,
    organization_id: uuid::Uuid,
    listing_id: uuid::Uuid,
    actor_id: uuid::Uuid,
) -> Result<Standing, NoombatError> {
    let (access, created_by): (ListingAccess, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT application_readers, created_by FROM job_listings WHERE id = $1")
            .bind(listing_id)
            .fetch_one(pool)
            .await
            .map_err(|e| NoombatError::Internal(e.to_string()))?;

    let is_creator = created_by == Some(actor_id);

    if actor_id == organization_id {
        return Ok(Standing {
            role: Some(OrganizationRole::Owner),
            access,
            is_creator,
            is_listed: true,
        });
    }

    let role: Option<OrganizationRole> = sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND member_id = $2",
    )
    .bind(organization_id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| NoombatError::Internal(e.to_string()))?;

    let is_listed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM job_listing_readers \
         WHERE job_listing_id = $1 AND member_id = $2)",
    )
    .bind(listing_id)
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .map_err(|e| NoombatError::Internal(e.to_string()))?;

    Ok(Standing {
        role,
        access,
        is_creator,
        is_listed,
    })
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
    let valid_statuses = [
        "submitted",
        "reviewed",
        "shortlisted",
        "rejected",
        "withdrawn",
    ];
    if !valid_statuses.contains(&body.status.as_str()) {
        return Err(ApiError(NoombatError::BadRequest(format!(
            "invalid status: {} (expected one of: {})",
            body.status,
            valid_statuses.join(", ")
        ))));
    }

    // No moderator override: moving an application is the company's
    // decision.
    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    let permitted = match principal.actor_uuid {
        Some(actor_id) => {
            let s = company_standing(&state.pool, job.actor_id, job_id, actor_id).await?;
            may_access_applications(s.role, s.access, s.is_creator, s.is_listed)
        }
        None => false,
    };

    if !permitted {
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
