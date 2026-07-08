// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! CV PDF download endpoint.
//!
//! Access control is enforced by the authorisation middleware via the
//! `download_cv` Cedar policy (see `policies/noombat.cedar`). This
//! handler determines *which sections* to include based on the
//! requester's relationship to the profile owner.

use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use noombat_core::error::NoombatError;
use noombat_core::privacy::SectionVisibility;
use serde::Deserialize;

use crate::error::ApiError;
use crate::middleware::Principal;
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
/// Generates and streams a PDF curriculum vitae.
///
/// The authorisation middleware has already evaluated the `download_cv`
/// Cedar policy before this handler runs. The handler determines the
/// maximum section visibility to include:
///
/// | Requester   | Sections included                  |
/// |-------------|------------------------------------|
/// | Owner       | `public` + `followers` + `private` |
/// | Follower    | `public` + `followers`             |
/// | Anyone else | `public`                           |
async fn download_cv(
    State(state): State<AppState>,
    Path(username): Path<String>,
    principal: Option<axum::Extension<Principal>>,
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

    // Determine the maximum section visibility based on the
    // requester's relationship to the profile owner.
    //
    // The middleware has already populated `Principal.is_follower_of_target`
    // via `fetch_privacy_context`, so no additional database query is
    // required here.
    let principal_username = principal.as_ref().and_then(|p| p.username.as_deref());

    let is_owner = principal_username.map(|u| u == username).unwrap_or(false);

    let is_follower = principal
        .as_ref()
        .and_then(|p| p.is_follower_of_target)
        .unwrap_or(false);

    let effective_vis = if is_owner {
        // The owner's own CV includes all sections, including
        // `private` entries intended solely for the CV.
        SectionVisibility::Private
    } else if is_follower {
        SectionVisibility::Followers
    } else {
        SectionVisibility::Public
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
