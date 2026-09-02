// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Applying to a posting, withdrawing, and the capability dereference.
//!
//! - `POST   /jobs/{id}/apply`           apply, and mint a grant
//! - `GET    /applications`              the applicant's own applications
//! - `GET    /applications/{id}/disclosures`  who read it, and when
//! - `DELETE /applications/{id}`         withdraw, revoking the grant
//! - `GET    /applications/{id}`         the employer's dereference
//!
//! The dereference is the only unauthenticated route here, because the
//! bearer token *is* the authorisation. It is checked against the
//! audience origin the grant was minted for, so a token that leaks to
//! another host dereferences nowhere.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use noombat_core::error::NoombatError;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/jobs/{id}/apply", post(apply))
        .route("/applications", get(list_own_applications))
        .route(
            "/applications/{id}",
            get(dereference).delete(withdraw_application),
        )
        .route("/applications/{id}/disclosures", get(list_disclosures))
}

// ..... POST /jobs/{id}/apply .....

/// Apply to a posting.
///
/// Returns the capability token exactly once. It is not stored in a form
/// the server can recover, so an applicant who loses it revokes and
/// applies again rather than asking for it back.
async fn apply(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<noombat_jobs::applications::NewApplication>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;

    // Captured now, so the employer reads the CV the applicant sent
    // rather than whatever the profile says later. Not fatal if it
    // fails: an application without a CV is still an application, and
    // `include_cv` records what was intended either way.
    let cv_snapshot = if body.include_cv {
        match noombat_identity::cv::generate_cv_pdf(
            &state.pool,
            viewer.actor_id,
            &noombat_core::privacy::SectionVisibility::Private,
            std::path::Path::new("templates"),
            "default",
            "apa",
        )
        .await
        {
            Ok(pdf) => Some(pdf),
            Err(e) => {
                tracing::warn!(actor = %viewer.actor_id, error = %e, "CV snapshot failed");
                None
            }
        }
    } else {
        None
    };

    let application = noombat_jobs::applications::apply(
        &state.pool,
        viewer.actor_id,
        job_id,
        &state.domain,
        &body,
        cv_snapshot,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": application.id,
            "ap_id": application.ap_id,
            // Shown once. The database holds only its hash.
            "grant_token": application.grant_token,
            "grant_expires_at": application.grant_expires_at,
        })),
    ))
}

// ..... GET /applications .....

/// The applicant's own applications.
async fn list_own_applications(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;

    let rows = sqlx::query_as::<_, (Uuid, String, String, chrono::NaiveDate, String)>(
        r#"SELECT id, posting_title, posting_organization, applied_on, status
           FROM job_applications
           WHERE applicant_id = $1
           ORDER BY applied_on DESC, created_at DESC"#,
    )
    .bind(viewer.actor_id)
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    let applications: Vec<_> = rows
        .into_iter()
        .map(|(id, title, organisation, applied_on, status)| {
            json!({
                "id": id,
                "posting_title": title,
                "posting_organization": organisation,
                "applied_on": applied_on,
                "status": status,
            })
        })
        .collect();

    Ok(Json(json!({ "applications": applications })))
}

// ..... GET /applications/{id}/disclosures .....

/// Every read of one application, shown to the applicant.
///
/// A moderator's review appears here beside an employer's dereference,
/// because it is a disclosure like any other and the applicant is owed
/// the same account of both.
async fn list_disclosures(
    State(state): State<AppState>,
    Path(application_id): Path<Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    require_applicant(&state, application_id, viewer.actor_id).await?;

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        r#"SELECT acc.kind, acc.outcome, acc.reason,
                  COALESCE(reader.display_name, reader.username),
                  acc.occurred_at
           FROM job_application_accesses acc
           LEFT JOIN actors reader ON reader.id = acc.reader_id
           WHERE acc.job_application_id = $1
           ORDER BY acc.occurred_at DESC"#,
    )
    .bind(application_id)
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    let disclosures: Vec<_> = rows
        .into_iter()
        .map(|(kind, outcome, reason, reader, occurred_at)| {
            json!({
                "kind": kind,
                "outcome": outcome,
                "reason": reason,
                "reader": reader,
                "occurred_at": occurred_at,
            })
        })
        .collect();

    Ok(Json(json!({ "disclosures": disclosures })))
}

// ..... DELETE /applications/{id} .....

/// Withdraw an application, revoking the employer's capability.
///
/// The row stays, with `status = 'withdrawn'`: it is the applicant's
/// record of having applied, and deleting it would erase their own
/// history to end somebody else's access. What ends is the grant.
async fn withdraw_application(
    State(state): State<AppState>,
    Path(application_id): Path<Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    require_applicant(&state, application_id, viewer.actor_id).await?;

    noombat_jobs::applications::revoke_for_application(
        &state.pool,
        viewer.actor_id,
        application_id,
        "applicant_withdrew",
    )
    .await?;

    sqlx::query(
        "UPDATE job_applications SET status = 'withdrawn', updated_at = now() WHERE id = $1",
    )
    .bind(application_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

// ..... GET /applications/{id}?token=... .....

#[derive(Deserialize)]
struct Dereference {
    token: String,
    /// `cv` to spend the CV budget instead of the document budget.
    #[serde(default)]
    document: Option<String>,
}

/// Dereference a capability grant.
///
/// Unauthenticated by design: the token is the authorisation, and it is
/// bound to one audience origin. The path id must match the application
/// the grant points at, so a valid token cannot be walked onto another
/// application by editing the URL.
async fn dereference(
    State(state): State<AppState>,
    Path(application_id): Path<Uuid>,
    Query(query): Query<Dereference>,
) -> Result<impl IntoResponse, ApiError> {
    let document = match query.document.as_deref() {
        Some("cv") => noombat_jobs::applications::Document::Cv,
        None | Some("application") => noombat_jobs::applications::Document::Application,
        Some(other) => {
            return Err(ApiError(NoombatError::BadRequest(format!(
                "document must be 'application' or 'cv', not {other:?}"
            ))));
        }
    };

    // The reader's origin is this instance's own, because the employer
    // dereferences over the web here. A remote employer's request would
    // carry its origin through a signed fetch, which job federation does
    // not do in v1.
    let reader_origin = crate::middleware::http_origin(&state.domain, state.public_port);

    let redeemed =
        noombat_jobs::applications::redeem(&state.pool, &query.token, &reader_origin, document)
            .await?;

    // A grant is for one application. Matching the path against it is
    // what stops a live token being pointed at a different row.
    if redeemed.job_application_id != application_id {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            bool,
            chrono::NaiveDate,
            String,
        ),
    >(
        r#"SELECT posting_title, posting_organization, cover_letter_html,
                  include_cv, applied_on, status
           FROM job_applications WHERE id = $1"#,
    )
    .bind(application_id)
    .fetch_one(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    match document {
        noombat_jobs::applications::Document::Cv => {
            if !row.3 {
                return Err(ApiError(NoombatError::Forbidden));
            }
            // The snapshot taken when they applied, never a fresh
            // render: an employer reading an application months later
            // must see what was sent, not what the profile says now.
            let pdf: Vec<u8> = sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT cv_snapshot FROM job_applications WHERE id = $1",
            )
            .bind(application_id)
            .fetch_one(&state.pool)
            .await
            .map_err(NoombatError::from)?
            .ok_or(ApiError(NoombatError::NotFound {
                entity: "cv_snapshot",
                id: application_id,
            }))?;
            Ok((
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/pdf".to_owned(),
                )],
                pdf,
            )
                .into_response())
        }
        noombat_jobs::applications::Document::Application => Ok(Json(json!({
            "id": application_id,
            "posting_title": row.0,
            "posting_organization": row.1,
            "cover_letter_html": row.2,
            "include_cv": row.3,
            "applied_on": row.4,
            "status": row.5,
        }))
        .into_response()),
    }
}

/// Refuse where the caller is not the application's applicant.
async fn require_applicant(
    state: &AppState,
    application_id: Uuid,
    actor_id: Uuid,
) -> Result<(), ApiError> {
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT applicant_id FROM job_applications WHERE id = $1")
            .bind(application_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(NoombatError::from)?;

    // A missing application and somebody else's are the same refusal, so
    // the route does not report which applications exist.
    match owner {
        Some(id) if id == actor_id => Ok(()),
        _ => Err(ApiError(NoombatError::Forbidden)),
    }
}
