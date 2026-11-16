// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Chat API routes: reports, Chatmail blocks and published chat keys.

use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use noombat_core::actor::{Actor, ActorStatus};
use noombat_core::error::NoombatError;
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/chat/reports", post(submit_chat_report))
        // No larger than a key may be, so nothing bigger is buffered
        // before the session is even checked.
        .route(
            "/api/v1/me/chat_key",
            put(put_chat_key).layer(DefaultBodyLimit::max(
                noombat_chat::keys::MAX_PUBLIC_KEY_LEN,
            )),
        )
        .route("/api/v1/chat/keys/{address}", get(get_chat_key))
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

// ..... Published chat keys .....

/// The signed-in member, refused unless they may chat: a suspended member's
/// session can outlive the suspension.
async fn chat_member(
    state: &AppState,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<Actor, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor = noombat_identity::repo::find_by_id(&state.pool, viewer.actor_id).await?;
    if !matches!(
        actor.actor_status,
        ActorStatus::Active | ActorStatus::Silenced
    ) {
        return Err(ApiError(NoombatError::Forbidden));
    }
    Ok(actor)
}

/// `PUT /api/v1/me/chat_key`
///
/// The member's OpenPGP public key for chat, binary, as their client made
/// it. Refused unless it is one public key naming their chat address. A
/// changed key is pushed to followers on other instances.
async fn put_chat_key(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    let actor = chat_member(&state, viewer).await?;
    // Set when a suspension ends: chat is set up again, with a new key,
    // before one is published.
    if actor.chat_requires_reprovisioning {
        return Err(ApiError(NoombatError::BadRequest(
            "chat must be set up again for this account".into(),
        )));
    }
    let address = actor.chatmail_addr.as_deref().ok_or_else(|| {
        ApiError(NoombatError::BadRequest(
            "chat is not set up for this account".into(),
        ))
    })?;
    if noombat_chat::keys::publish(&state.pool, actor.id, address, &body).await? {
        noombat_federation::update::enqueue_actor_update(&state.pool, &actor, &state.domain).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/chat/keys/{address}`
///
/// A local member's published key, for a signed-in member who may see
/// their chat address and whom they have not blocked. Every refusal about
/// the member looked up is the same 404 as no key at all, so a hidden key
/// cannot be told from a missing one.
async fn get_chat_key(
    State(state): State<AppState>,
    Path(address): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = chat_member(&state, viewer).await?;
    noombat_core::email_address::qualify(&address, "address")?;
    let published = noombat_chat::keys::find_visible_local(&state.pool, &address, viewer.id)
        .await?
        .ok_or_else(no_chat_key)?;
    Ok(key_answer(&published.address, &published.key))
}

/// The one refusal every chat key lookup gives.
fn no_chat_key() -> ApiError {
    ApiError(NoombatError::ActorNotFound("no chat key".into()))
}

fn key_answer(address: &str, key: &[u8]) -> axum::response::Response {
    (
        // The answer depends on who asks.
        [(CACHE_CONTROL, "private, no-store")],
        Json(json!({
            "address": address,
            "key": STANDARD.encode(key),
        })),
    )
        .into_response()
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
