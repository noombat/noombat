// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Chat report API route.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/chat/reports", post(submit_chat_report))
}

async fn submit_chat_report(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Json(req): Json<noombat_chat::report::ChatReportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let principal = principal.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = principal
        .actor_id()
        .ok_or(ApiError(NoombatError::Forbidden))?;

    let result = noombat_chat::report::submit_report(&state.pool, actor_id, &req).await?;

    Ok((StatusCode::CREATED, Json(result)))
}
