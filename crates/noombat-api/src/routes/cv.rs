// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! CV PDF download endpoint.

use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use noombat_core::error::NoombatError;
use noombat_core::privacy::{CvDownload, SectionVisibility};
use serde::Deserialize;

use crate::auth::verify_bearer_token;
use crate::error::ApiError;
use crate::state::AppState;

/// Query parameters for `GET /users/{username}/cv`.
#[derive(Debug, Deserialize)]
pub struct CvParams {
    /// Typst template name (default: `"default"`).
    #[serde(default = "default_template")]
    pub template: String,
    /// Citation style for publications: `apa`, `ieee`, or `vancouver`
    /// (default: `"apa"`).
    #[serde(default = "default_citation_style")]
    pub citation_style: String,
}

fn default_template() -> String {
    "default".to_owned()
}

fn default_citation_style() -> String {
    "apa".to_owned()
}

pub fn router() -> Router<AppState> {
    Router::new().route("/users/{username}/cv", get(download_cv))
}

/// `GET /users/{username}/cv?template=default`
///
/// Generates and streams a PDF curriculum vitae. Access is governed by
/// the `cv_download` privacy setting: `public` (anyone), `followers`
/// (accepted followers only), or `self` (profile owner only).
async fn download_cv(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Query(params): Query<CvParams>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // Reject template names that could escape the templates directory.
    if params.template.contains('/')
        || params.template.contains('\\')
        || params.template.contains("..")
        || params.template.is_empty()
    {
        return Err(ApiError(NoombatError::BadRequest(
            "template name must not contain path separators or '..'".into(),
        )));
    }

    // Determine the requester's relationship to the actor.
    let (max_vis, is_owner) = match actor.actor_privacy.cv_download {
        CvDownload::Public => {
            // Anyone may download; include only public sections.
            (SectionVisibility::Public, false)
        }
        CvDownload::Followers => {
            // Must be an accepted follower (or the owner).
            let is_owner = verify_bearer_token(&headers, &state.admin_token).is_ok();
            if !is_owner {
                // TODO: Verify the requester's follow
                // relationship via HTTP Signatures.
                return Err(ApiError(NoombatError::Forbidden));
            }
            (SectionVisibility::Private, true)
        }
        CvDownload::SelfOnly => {
            if verify_bearer_token(&headers, &state.admin_token).is_err() {
                return Err(ApiError(NoombatError::Forbidden));
            }
            (SectionVisibility::Private, true)
        }
    };

    // When the owner downloads their own CV, include all sections
    // (including private ones intended solely for the CV).
    let effective_vis = if is_owner {
        SectionVisibility::Private
    } else {
        max_vis
    };

    let template_dir = std::path::Path::new("templates");
    let pdf_bytes = noombat_identity::cv::generate_cv_pdf(
        &state.pool,
        actor.id,
        &effective_vis,
        template_dir,
        &params.template,
        &params.citation_style,
    )
    .await?;

    let filename = format!("{}_cv.pdf", actor.username);
    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/pdf".to_owned()),
            (
                CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        pdf_bytes,
    ))
}
