// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Block and mute interaction routes with outbound federation.
//!
//! - `POST   /users/{username}/blocks`: block a remote or local actor.
//! - `DELETE /users/{username}/blocks/{ap_id}`: unblock an actor.
//! - `POST   /users/{username}/mutes`: mute an actor.
//! - `DELETE /users/{username}/mutes/{id}`: unmute an actor.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, post};
use axum::{Json, Router};
use noombat_ap::context::default_context;
use noombat_core::error::NoombatError;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::require_local_actor;
use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users/{username}/blocks", post(create_block))
        .route(
            "/users/{username}/blocks/{target_ap_id}",
            delete(delete_block),
        )
        .route("/users/{username}/mutes", post(create_mute))
        .route("/users/{username}/mutes/{id}", delete(delete_mute))
}

// ..... Block .....

#[derive(Deserialize)]
struct BlockRequest {
    /// ActivityPub URI of the actor to block.
    target_ap_id: String,
}

/// Block an actor and federate the `Block` activity.
async fn create_block(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<BlockRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let local_actor = require_local_actor(&state.pool, &viewer, &username).await?;

    // Resolve the target actor (may be remote).
    let target = noombat_federation::inbox::resolve_actor(
        &state.pool,
        &state.http_client,
        &body.target_ap_id,
    )
    .await?;

    // Persist the block (idempotent).
    sqlx::query(
        r#"INSERT INTO blocks (id, actor_id, target_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (actor_id, target_id) DO NOTHING"#,
    )
    .bind(Uuid::new_v4())
    .bind(local_actor.id)
    .bind(target.id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    // Read the outbound Follow's AP id before deleting the row, because
    // the `Undo` below has to name the activity it undoes and the row is
    // the only place that id is kept.
    let outbound_follow_ap_id =
        noombat_identity::repo::get_follow_ap_id(&state.pool, local_actor.id, target.id).await?;

    // Sever any follow relationships in both directions.
    noombat_identity::repo::delete_follow(&state.pool, local_actor.id, target.id).await?;
    noombat_identity::repo::delete_follow(&state.pool, target.id, local_actor.id).await?;

    // Federate the Block activity to the target's inbox.
    let block_id = format!(
        "{}#block-{}",
        local_actor.ap_id,
        chrono::Utc::now().timestamp_millis()
    );
    let block_activity = json!({
        "@context": default_context(),
        "id": block_id,
        "type": "Block",
        "actor": local_actor.ap_id,
        "object": target.ap_id,
    });

    let target_inbox = target
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{}/inbox", target.ap_id));
    noombat_federation::delivery::enqueue(
        &state.pool,
        local_actor.id,
        &block_activity,
        &target_inbox,
    )
    .await?;

    // The Block alone does not stop delivery. Severing the follow here
    // and not there leaves the peer believing this actor still follows
    // theirs, so it keeps sending posts from the account that was just
    // blocked. Mastodon expects the `Undo { Follow }` as well.
    if let Some(follow_ap_id) = outbound_follow_ap_id {
        let undo_follow = json!({
            "@context": default_context(),
            "id": format!(
                "{}#undo-follow-{}",
                local_actor.ap_id,
                chrono::Utc::now().timestamp_millis()
            ),
            "type": "Undo",
            "actor": local_actor.ap_id,
            "object": {
                // The original Follow's own id, which is what lets the
                // peer match this to the request it accepted.
                "id": follow_ap_id,
                "type": "Follow",
                "actor": local_actor.ap_id,
                "object": target.ap_id,
            },
        });

        noombat_federation::delivery::enqueue(
            &state.pool,
            local_actor.id,
            &undo_follow,
            &target_inbox,
        )
        .await?;
    }

    Ok(StatusCode::CREATED)
}

/// Unblock an actor and federate `Undo { Block }`.
async fn delete_block(
    State(state): State<AppState>,
    Path((username, target_ap_id)): Path<(String, String)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<StatusCode, ApiError> {
    let local_actor = require_local_actor(&state.pool, &viewer, &username).await?;

    // URL-decode the target AP ID (it appears in the path).
    let target_ap_id = urlencoding::decode(&target_ap_id)
        .map(|s| s.into_owned())
        .unwrap_or(target_ap_id);

    let target = noombat_identity::repo::find_by_ap_id(&state.pool, &target_ap_id)
        .await?
        .ok_or_else(|| NoombatError::ActorNotFound(target_ap_id.clone()))?;

    sqlx::query("DELETE FROM blocks WHERE actor_id = $1 AND target_id = $2")
        .bind(local_actor.id)
        .bind(target.id)
        .execute(&state.pool)
        .await
        .map_err(NoombatError::from)?;

    // Federate Undo { Block }. The inner Block carries an id so that
    // the remote instance can correlate the undo with the original block.
    let block_ref_id = format!(
        "{}#block-ref-{}",
        local_actor.ap_id,
        chrono::Utc::now().timestamp_millis()
    );
    let undo_id = format!(
        "{}#undo-block-{}",
        local_actor.ap_id,
        chrono::Utc::now().timestamp_millis()
    );
    let undo_activity = json!({
        "@context": default_context(),
        "id": undo_id,
        "type": "Undo",
        "actor": local_actor.ap_id,
        "object": {
            "id": block_ref_id,
            "type": "Block",
            "actor": local_actor.ap_id,
            "object": target.ap_id,
        },
    });

    let target_inbox = target
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{}/inbox", target.ap_id));
    noombat_federation::delivery::enqueue(
        &state.pool,
        local_actor.id,
        &undo_activity,
        &target_inbox,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ..... Mute .....

#[derive(Deserialize)]
struct MuteRequest {
    /// ActivityPub URI of the actor to mute.
    target_ap_id: String,
    /// Optional: mute duration in seconds. `None` = permanent.
    duration_secs: Option<i64>,
}

/// Mute an actor (local only, not federated).
async fn create_mute(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<MuteRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let local_actor = require_local_actor(&state.pool, &viewer, &username).await?;

    let target = noombat_federation::inbox::resolve_actor(
        &state.pool,
        &state.http_client,
        &body.target_ap_id,
    )
    .await?;

    let expires_at = body
        .duration_secs
        .map(|secs| chrono::Utc::now() + chrono::TimeDelta::seconds(secs));

    sqlx::query(
        r#"INSERT INTO mutes (id, actor_id, target_id, expires_at)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (actor_id, target_id)
           DO UPDATE SET expires_at = EXCLUDED.expires_at"#,
    )
    .bind(Uuid::new_v4())
    .bind(local_actor.id)
    .bind(target.id)
    .bind(expires_at)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok(StatusCode::CREATED)
}

/// Unmute an actor.
async fn delete_mute(
    State(state): State<AppState>,
    Path((username, mute_id)): Path<(String, Uuid)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<StatusCode, ApiError> {
    let local_actor = require_local_actor(&state.pool, &viewer, &username).await?;

    sqlx::query("DELETE FROM mutes WHERE id = $1 AND actor_id = $2")
        .bind(mute_id)
        .bind(local_actor.id)
        .execute(&state.pool)
        .await
        .map_err(NoombatError::from)?;

    Ok(StatusCode::NO_CONTENT)
}
