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
use noombat_core::authorisation::{
    OrganizationRole, PostingAccess, may_access_job_applications, may_delegate_posting,
};
use noombat_core::error::NoombatError;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::auth::require_acts_for;
use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/organizations",
            axum::routing::post(enrol_organization),
        )
        .route(
            "/api/v1/organizations/{id}/employment-claims",
            get(list_employment_claims),
        )
        .route(
            "/api/v1/organizations/{id}/employment-claims/{work_experience_id}",
            axum::routing::post(confirm_employment).delete(withdraw_employment),
        )
        .route("/api/v1/candidates", get(search_candidates))
        .route(
            "/api/v1/jobs/{job_id}/applications",
            get(list_job_applications),
        )
        .route(
            "/api/v1/jobs/{job_id}/applications/{app_id}/status",
            axum::routing::post(update_job_application_status),
        )
        .route(
            "/api/v1/jobs/{job_id}/readers",
            get(list_posting_readers).put(set_posting_readers),
        )
}

// ..... Who may read a posting's applications .....

/// The reader set of one posting.
#[derive(Debug, Deserialize)]
struct ReaderSet {
    /// `creator_only`, `all_recruiters` or `listed`.
    access: PostingAccess,
    /// The recruiters named when `access` is `listed`. Ignored
    /// otherwise, and stored anyway, so switching to `listed` and back
    /// does not silently lose the list somebody assembled.
    #[serde(default)]
    members: Vec<uuid::Uuid>,
}

/// `GET /api/v1/jobs/{job_id}/readers`
async fn list_posting_readers(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path(job_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    let standing = company_standing(&state.pool, job.actor_id, job_id, viewer.actor_id).await?;

    // Reading the set is part of reading the applications, so it takes
    // the same predicate rather than a looser one of its own.
    if !may_access_job_applications(
        standing.role,
        standing.access,
        standing.is_creator,
        standing.is_listed,
    ) {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let members = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT member_id FROM job_posting_readers WHERE job_posting_id = $1",
    )
    .bind(job_id)
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok(Json(serde_json::json!({
        "access": standing.access,
        "members": members,
        // Whether this caller may change it, so the interface does not
        // offer a control that will be refused.
        "may_delegate": may_delegate_posting(standing.role, standing.is_creator),
    })))
}

/// `PUT /api/v1/jobs/{job_id}/readers`
///
/// The first caller of `may_delegate_posting`, and the first writer of
/// `job_posting_readers`: membership was checked here and granted
/// nowhere, so `listed` named an empty set forever.
async fn set_posting_readers(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path(job_id): Path<uuid::Uuid>,
    Json(body): Json<ReaderSet>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    let standing = company_standing(&state.pool, job.actor_id, job_id, viewer.actor_id).await?;

    // Owners, and the recruiter who created it. A recruiter opening
    // their own posting to colleagues does not need an owner to do it,
    // and cannot widen anybody else's.
    if !may_delegate_posting(standing.role, standing.is_creator) {
        return Err(ApiError(NoombatError::Forbidden));
    }

    // Naming an outsider grants nothing, because the predicate refuses a
    // non-member whatever the set says. Refused here as well, so a
    // mistake is reported rather than stored as a row that does nothing.
    for member_id in &body.members {
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM organization_members \
             WHERE organization_id = $1 AND member_id = $2)",
        )
        .bind(job.actor_id)
        .bind(member_id)
        .fetch_one(&state.pool)
        .await
        .map_err(NoombatError::from)?;

        if !is_member {
            return Err(ApiError(NoombatError::BadRequest(format!(
                "{member_id} is not a member of this organisation"
            ))));
        }
    }

    let mut tx = state.pool.begin().await.map_err(NoombatError::from)?;

    sqlx::query("UPDATE job_postings SET job_application_readers = $2 WHERE id = $1")
        .bind(job_id)
        .bind(match body.access {
            PostingAccess::CreatorOnly => "creator_only",
            PostingAccess::AllRecruiters => "all_recruiters",
            PostingAccess::Listed => "listed",
        })
        .execute(&mut *tx)
        .await
        .map_err(NoombatError::from)?;

    sqlx::query("DELETE FROM job_posting_readers WHERE job_posting_id = $1")
        .bind(job_id)
        .execute(&mut *tx)
        .await
        .map_err(NoombatError::from)?;

    for member_id in &body.members {
        sqlx::query(
            "INSERT INTO job_posting_readers (job_posting_id, member_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(job_id)
        .bind(member_id)
        .execute(&mut *tx)
        .await
        .map_err(NoombatError::from)?;
    }

    tx.commit().await.map_err(NoombatError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

// ..... Employment claims .....

/// `GET /api/v1/organizations/{id}/employment-claims`
///
/// The employer's work list: everyone claiming to work here, unconfirmed
/// first. Confirmed rows stay on the list so a confirmation can be
/// withdrawn later.
async fn list_employment_claims(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_acts_for(&state.pool, id, &viewer).await?;
    let claims = noombat_identity::profile::list_employment_claims(&state.pool, id).await?;
    Ok(Json(claims))
}

/// `POST /api/v1/organizations/{id}/employment-claims/{work_experience_id}`
///
/// Establish the employer side of a claim.
async fn confirm_employment(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path((id, work_experience_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    require_acts_for(&state.pool, id, &viewer).await?;
    let claim = noombat_identity::profile::confirm_employment(
        &state.pool,
        work_experience_id,
        id,
        noombat_identity::profile::ConfirmedVia::Organisation,
    )
    .await?;
    Ok(Json(claim))
}

/// `DELETE /api/v1/organizations/{id}/employment-claims/{work_experience_id}`
///
/// Withdraw a confirmation. The claim itself survives as self-asserted:
/// disputing that somebody worked here is a moderation matter, not a
/// licence to edit their history.
async fn withdraw_employment(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path((id, work_experience_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    require_acts_for(&state.pool, id, &viewer).await?;
    let claim = noombat_identity::profile::withdraw_employment_confirmation(
        &state.pool,
        work_experience_id,
        id,
    )
    .await?;
    Ok(Json(claim))
}

// ..... Enrolment .....

/// Request body for `POST /api/v1/organizations`.
#[derive(Debug, Deserialize)]
struct EnrolRequest {
    username: String,
    display_name: Option<String>,
    /// The corporate domain claimed. Publishing is gated on proving
    /// control of it; without one the organisation can never publish.
    claimed_domain: Option<String>,
}

/// `POST /api/v1/organizations`
///
/// Enrol an organisation, owned by the authenticated actor. Self-serve
/// by decision: an administrator cannot adjudicate employment at any
/// scale, so no route lets them try.
///
/// The organisation is enrolled but not verified. What it may publish is
/// gated on a `rel="me"` link to its own domain, added afterwards.
async fn enrol_organization(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<EnrolRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let owner_id = viewer
        .as_ref()
        .map(|p| p.actor_id)
        .ok_or(ApiError(NoombatError::Forbidden))?;

    let actor = noombat_identity::registration::enrol_organization(
        &state.pool,
        &state.domain,
        owner_id,
        body.username.trim(),
        body.display_name.clone(),
        body.claimed_domain.as_deref(),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": actor.id,
            "ap_id": actor.ap_id,
            "username": actor.username,
            "actor_type": actor.actor_type.as_str(),
        })),
    ))
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
    _viewer: Option<axum::Extension<Viewer>>,
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
struct JobApplicationSummary {
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
/// List all applications for a job posting. Requires an owner of the
/// publishing organisation, the recruiter who created the posting, or a
/// recruiter the posting has been opened to.
///
/// Moderators are **not** admitted here. They read one application at a
/// time through `moderation::review_job_application`, which states a reason
/// and writes it to the applicant's own access log.
async fn list_job_applications(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path(job_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;

    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    // An anonymous request carries no actor to have standing, and is
    // already refused above by the absent extension.
    let standing = company_standing(&state.pool, job.actor_id, job_id, viewer.actor_id).await?;
    let permitted = may_access_job_applications(
        standing.role,
        standing.access,
        standing.is_creator,
        standing.is_listed,
    );

    if !permitted {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let applications = sqlx::query_as::<_, JobApplicationSummary>(
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
        FROM job_applications a
        INNER JOIN actors act ON act.id = a.applicant_id
        WHERE a.job_posting_id = $1
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

/// An actor's standing for one posting. The publishing actor counts as
/// `Owner` without a membership row, so an organisation posting as itself is
/// not locked out of its own job_applications.
struct Standing {
    role: Option<OrganizationRole>,
    access: PostingAccess,
    is_creator: bool,
    is_listed: bool,
}

async fn company_standing(
    pool: &sqlx::PgPool,
    organization_id: uuid::Uuid,
    posting_id: uuid::Uuid,
    actor_id: uuid::Uuid,
) -> Result<Standing, NoombatError> {
    let (access, created_by): (PostingAccess, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT job_application_readers, created_by FROM job_postings WHERE id = $1",
    )
    .bind(posting_id)
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
        "SELECT EXISTS (SELECT 1 FROM job_posting_readers \
         WHERE job_posting_id = $1 AND member_id = $2)",
    )
    .bind(posting_id)
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
async fn update_job_application_status(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path((job_id, app_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(body): Json<UpdateStatusRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;

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

    // No moderator override: moving an application is the organisation's
    // decision.
    let job = noombat_jobs::get_job(&state.pool, job_id).await?;
    let standing = company_standing(&state.pool, job.actor_id, job_id, viewer.actor_id).await?;
    let permitted = may_access_job_applications(
        standing.role,
        standing.access,
        standing.is_creator,
        standing.is_listed,
    );

    if !permitted {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let rows_affected = sqlx::query(
        "UPDATE job_applications SET status = $1, updated_at = NOW() \
         WHERE id = $2 AND job_posting_id = $3",
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
