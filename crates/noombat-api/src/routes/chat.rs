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
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/chat/reports", post(submit_chat_report))
        .route(
            "/users/{username}/chat/blocks/{address}",
            axum::routing::delete(unblock_chat_sender),
        )
}

// ..... Undoing a Chatmail block .....

/// `DELETE /users/{username}/chat/blocks/{address}`
///
/// Blocking a Chatmail sender was a one-way door: `block_sender` is
/// called when a chat report is resolved, `unblock_sender` had no caller
/// and no surface, and nothing listed the blocks either, so a user could
/// neither see nor undo one.
///
/// Both halves are undone here. The row in `chatmail_blocks` is this
/// instance's own record; the sidecar access map is the mail server's,
/// and leaving that in place would keep the mail bouncing however the
/// database read.
async fn unblock_chat_sender(
    State(state): State<AppState>,
    axum::extract::Path((username, address)): axum::extract::Path<(String, String)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = crate::auth::require_local_actor(&state.pool, &viewer, &username).await?;

    // The path guards the username and says nothing about the address, and
    // the delete below matches no row rather than failing, so without this
    // an arbitrary path segment reaches the Chatmail admin client.
    noombat_core::email_address::qualify(&address, "address")?;

    noombat_chat::relay::unblock_sender(&state.pool, actor.id, &address).await?;

    // The pair block is keyed on this actor's own address, so there is
    // nothing to lift where they have none.
    if let Some(ref recipient) = actor.chatmail_addr
        && let Some(client) = state.chatmail_admin_client.as_ref()
        && let Err(e) = client.unblock_sender_pair(&address, recipient).await
    {
        // Not fatal: the local row is gone either way, and the sidecar
        // is retried by an administrator rather than by holding the
        // user's request open.
        tracing::warn!(error = %e, "the sidecar access-map block could not be lifted");
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn submit_chat_report(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(req): Json<noombat_chat::report::ChatReportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;

    let result = noombat_chat::report::submit_report(&state.pool, actor_id, &req).await?;

    Ok((StatusCode::CREATED, Json(result)))
}
