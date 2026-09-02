// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Hashtag follow and unfollow API routes.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};

use noombat_identity::hashtags;

use crate::auth::require_local_actor;
use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/users/{username}/hashtags",
            get(list_followed).post(follow),
        )
        .route("/users/{username}/hashtags/{tag}", delete(unfollow))
}

/// `GET /users/{username}/hashtags`
///
/// List all hashtags followed by the actor. Public endpoint.
async fn list_followed(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    let tags = hashtags::list_followed_hashtags(&state.pool, actor.id).await?;
    Ok(Json(tags))
}

/// `POST /users/{username}/hashtags`
///
/// Follow a hashtag. Expects JSON body `{ "name": "rust" }`.
/// Development only: Requires bearer-token authentication.
async fn follow(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<FollowRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    let tag = hashtags::follow_hashtag(&state.pool, actor.id, &body.name).await?;
    Ok((StatusCode::OK, Json(tag)))
}

/// `DELETE /users/{username}/hashtags/{tag}`
///
/// Unfollow a hashtag.
/// Development only: Requires bearer-token authentication.
async fn unfollow(
    State(state): State<AppState>,
    Path((username, tag)): Path<(String, String)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    hashtags::unfollow_hashtag(&state.pool, actor.id, &tag).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// JSON body for the follow request.
#[derive(serde::Deserialize)]
struct FollowRequest {
    name: String,
}
