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
            "/api/v1/organizations/{id}",
            axum::routing::patch(declare_org_kind),
        )
        .route(
            "/api/v1/organizations/{id}/employment-claims",
            get(list_employment_claims),
        )
        .route(
            "/api/v1/organizations/{id}/employment-claims/{work_experience_id}",
            axum::routing::post(confirm_employment).delete(withdraw_employment),
        )
        .route(
            "/api/v1/organizations/{id}/members",
            get(list_members).post(invite_member),
        )
        .route(
            "/api/v1/organizations/{id}/members/{username}",
            axum::routing::delete(remove_member),
        )
        .route(
            "/api/v1/organizations/{id}/members/me/acceptance",
            axum::routing::post(accept_invitation),
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
             WHERE organization_id = $1 AND member_id = $2 AND accepted_at IS NOT NULL)",
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
    /// Whether it hires for itself or recruits for a client. Optional
    /// here and required to publish a job posting, so an organisation
    /// enrolled only to hold a profile is never asked.
    org_kind: Option<noombat_core::actor::OrgKind>,
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
        body.org_kind,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": actor.id,
            "ap_id": actor.ap_id,
            "username": actor.username,
            "actor_type": actor.actor_type.as_str(),
            "org_kind": actor.org_kind.map(|k| k.as_str()),
        })),
    ))
}

/// Refuse anyone but an owner of `organization_id`.
///
/// The organisation acting as itself counts as an owner, which is the
/// same reading [`company_standing`] takes. That one cannot serve here
/// because it settles standing on a posting, and this question is about
/// the organisation with no posting in hand.
async fn require_owner(
    pool: &sqlx::PgPool,
    organization_id: uuid::Uuid,
    actor_id: uuid::Uuid,
) -> Result<(), ApiError> {
    if actor_id == organization_id {
        return Ok(());
    }

    let role: Option<OrganizationRole> = sqlx::query_scalar(
        "SELECT role FROM organization_members \
         WHERE organization_id = $1 AND member_id = $2 AND accepted_at IS NOT NULL",
    )
    .bind(organization_id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError(NoombatError::Internal(e.to_string())))?;

    match role {
        Some(OrganizationRole::Owner) => Ok(()),
        _ => Err(ApiError(NoombatError::Forbidden)),
    }
}

/// Request body for `PATCH /api/v1/organizations/{id}`.
#[derive(Debug, Deserialize)]
struct DeclareKindRequest {
    org_kind: noombat_core::actor::OrgKind,
}

/// `PATCH /api/v1/organizations/{id}`
///
/// Declare, or correct, whether the organisation hires for itself or
/// recruits for a client. Separate from enrolment because the answer can
/// change: an employer that starts recruiting on behalf of others is the
/// same organisation, and re-enrolling to say so would strand its
/// postings and its members.
///
/// Owners only, by the same rule that governs the organisation's other
/// settings. A recruiter who could re-label the organisation could make
/// every one of its postings claim a direct employer.
async fn declare_org_kind(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<DeclareKindRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let member_id = viewer
        .as_ref()
        .map(|p| p.actor_id)
        .ok_or(ApiError(NoombatError::Forbidden))?;

    require_owner(&state.pool, id, member_id).await?;

    let actor = noombat_identity::repo::set_org_kind(&state.pool, id, body.org_kind).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": actor.id,
            "org_kind": actor.org_kind.map(|k| k.as_str()),
        })),
    ))
}

// ..... Membership .....

#[derive(Deserialize)]
struct InviteMemberRequest {
    /// The local username to invite. Trimmed, because the neighbouring
    /// routes that take a username trim at the call site.
    username: String,
}

#[derive(Serialize)]
struct MemberSummary {
    username: String,
    role: OrganizationRole,
    /// `false` while the invitation is outstanding. An owner needs to see
    /// the difference: an unaccepted row grants nothing.
    accepted: bool,
}

/// `GET /api/v1/organizations/{id}/members`
///
/// Who acts for this organisation, and who has been asked to.
///
/// Any accepted member may read it, because standing is shared: a
/// recruiter acting on a posting is answerable to the same people.
async fn list_members(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    require_acts_for(&state.pool, id, &viewer).await?;

    let rows = sqlx::query_as::<
        _,
        (
            String,
            OrganizationRole,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT a.username, m.role, m.accepted_at FROM organization_members m \
         JOIN actors a ON a.id = m.member_id \
         WHERE m.organization_id = $1 ORDER BY m.created_at",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    let members: Vec<MemberSummary> = rows
        .into_iter()
        .map(|(username, role, accepted_at)| MemberSummary {
            username,
            role,
            accepted: accepted_at.is_some(),
        })
        .collect();

    Ok((StatusCode::OK, Json(members)))
}

/// `POST /api/v1/organizations/{id}/members`
///
/// Invite a local account to act for this organisation as a recruiter.
///
/// **Guarded by `require_owner`, not `require_acts_for`.** Every
/// neighbouring route on this organisation uses the latter, which is
/// role-blind; using it here would let a recruiter invite colleagues and
/// promote themselves the moment this route existed.
///
/// The invitation grants nothing until it is accepted. What it will grant
/// is larger than the word "recruiter" suggests: acting for the
/// organisation means posting as it, patching its profile, and confirming
/// the employment claims that federate as a public credibility signal,
/// none of it attributed to the person in any response. That is why the
/// person being added has to agree rather than simply be added.
///
/// Only `recruiter` is issuable here. A second owner would be able to
/// dissolve the organisation, which is not a thing to hand over through
/// the same door as help with hiring.
async fn invite_member(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<InviteMemberRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let inviter = viewer
        .as_ref()
        .map(|p| p.actor_id)
        .ok_or(ApiError(NoombatError::Forbidden))?;

    require_owner(&state.pool, id, inviter).await?;

    let invitee =
        noombat_identity::repo::find_local_by_username(&state.pool, body.username.trim()).await?;

    // An organisation cannot act for another organisation: standing is a
    // record of which person did something, and a nested actor erases
    // exactly that.
    if invitee.actor_type != noombat_core::actor::ActorType::Individual {
        return Err(ApiError(NoombatError::BadRequest(
            "only a person can be invited to act for an organisation".into(),
        )));
    }
    if invitee.id == id {
        return Err(ApiError(NoombatError::BadRequest(
            "an organisation cannot be invited to act for itself".into(),
        )));
    }

    // `ON CONFLICT DO NOTHING` and then a check, rather than a prior
    // lookup: two concurrent invitations for the same person would both
    // pass a lookup, and the primary key is the only thing that decides.
    let inserted = sqlx::query(
        "INSERT INTO organization_members (organization_id, member_id, role) \
         VALUES ($1, $2, 'recruiter') ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(invitee.id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError(NoombatError::BadRequest(
            "that account is already a member of this organisation, or already invited".into(),
        )));
    }

    debug!(organization = %id, invitee = %invitee.id, "recruiter invited");
    Ok(StatusCode::CREATED)
}

/// `POST /api/v1/organizations/{id}/members/me/acceptance`
///
/// Accept an invitation to act for this organisation.
///
/// Only the invited account can call it, and only for itself: the path
/// says `me` rather than taking a username, so there is no parameter an
/// owner could pass to accept on somebody's behalf.
async fn accept_invitation(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let member_id = viewer
        .as_ref()
        .map(|p| p.actor_id)
        .ok_or(ApiError(NoombatError::Forbidden))?;

    // `accepted_at IS NULL` in the predicate, so accepting twice is a 404
    // rather than a silent refresh of the timestamp.
    let updated = sqlx::query(
        "UPDATE organization_members SET accepted_at = now() \
         WHERE organization_id = $1 AND member_id = $2 AND accepted_at IS NULL",
    )
    .bind(id)
    .bind(member_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    if updated.rows_affected() == 0 {
        return Err(ApiError(NoombatError::ActorNotFound(
            "no outstanding invitation for this account".into(),
        )));
    }

    debug!(organization = %id, member = %member_id, "invitation accepted");
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/organizations/{id}/members/{username}`
///
/// Withdraw an invitation, remove a member, or leave.
///
/// One route for all three because they are one row and one effect. An
/// owner may remove anybody; anybody may remove themselves, which is what
/// makes declining an invitation possible without a second endpoint.
///
/// An owner cannot be removed. Ownership comes from enrolment and ends
/// with the organisation, so a route that could take the last owner out
/// would leave an organisation nobody can act for, and it has no login to
/// fall back on.
async fn remove_member(
    State(state): State<AppState>,
    Path((id, username)): Path<(uuid::Uuid, String)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor_id = viewer
        .as_ref()
        .map(|p| p.actor_id)
        .ok_or(ApiError(NoombatError::Forbidden))?;

    let target =
        noombat_identity::repo::find_local_by_username(&state.pool, username.trim()).await?;

    if target.id != actor_id {
        require_owner(&state.pool, id, actor_id).await?;
    }

    let removed = sqlx::query(
        "DELETE FROM organization_members \
         WHERE organization_id = $1 AND member_id = $2 AND role <> 'owner'",
    )
    .bind(id)
    .bind(target.id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    if removed.rows_affected() == 0 {
        return Err(ApiError(NoombatError::ActorNotFound(
            "no removable membership for that account in this organisation".into(),
        )));
    }

    debug!(organization = %id, member = %target.id, "membership removed");
    Ok(StatusCode::NO_CONTENT)
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
        "SELECT role FROM organization_members \
         WHERE organization_id = $1 AND member_id = $2 AND accepted_at IS NOT NULL",
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
