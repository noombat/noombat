// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Follow management routes.
//!
//! - `POST /users/{username}/following`: initiate an outbound follow.
//! - `GET  /users/{username}/pending_follows`: list pending inbound follows.
//! - `POST /users/{username}/pending_follows/{id}/accept`: accept a pending follow.
//! - `POST /users/{username}/pending_follows/{id}/reject`: reject a pending follow.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use noombat_ap::context::default_context;
use noombat_core::error::NoombatError;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::require_local_actor;
use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users/{username}/following", post(initiate_follow))
        .route(
            "/users/{username}/pending_follows",
            get(list_pending_follows),
        )
        .route(
            "/users/{username}/pending_follows/{id}/accept",
            post(accept_pending_follow),
        )
        .route(
            "/users/{username}/pending_follows/{id}/reject",
            post(reject_pending_follow),
        )
}

// ..... Outbound follow .....

#[derive(Deserialize)]
struct FollowTarget {
    /// ActivityPub URI of the actor to follow (e.g. `https://mastodon.social/users/alice`).
    target_ap_id: String,
}

/// Initiate an outbound follow of a remote actor.
async fn initiate_follow(
    State(state): State<AppState>,
    Path(username): Path<String>,
    principal: Option<axum::Extension<Principal>>,
    Json(body): Json<FollowTarget>,
) -> Result<impl IntoResponse, ApiError> {
    let local_actor = require_local_actor(&state.pool, &principal, &username).await?;

    // Resolve (and cache) the remote actor.
    let remote_actor = noombat_federation::inbox::resolve_actor(
        &state.pool,
        &state.http_client,
        &body.target_ap_id,
    )
    .await?;

    // Persist a pending follow (not yet accepted).
    noombat_identity::repo::create_follow(&state.pool, local_actor.id, remote_actor.id, false)
        .await?;

    // Construct the Follow activity.
    let follow_id = format!(
        "{}#follow-{}",
        local_actor.ap_id,
        chrono::Utc::now().timestamp()
    );
    let follow_activity = json!({
        "@context": default_context(),
        "id": follow_id,
        "type": "Follow",
        "actor": local_actor.ap_id,
        "object": remote_actor.ap_id,
    });

    // Enqueue for delivery.
    let remote_inbox = remote_actor
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{}/inbox", remote_actor.ap_id));
    noombat_federation::delivery::enqueue(
        &state.pool,
        local_actor.id,
        &follow_activity,
        &remote_inbox,
    )
    .await?;

    Ok(StatusCode::ACCEPTED)
}

// ..... Pending-follow management .....

/// A pending (not yet accepted) inbound follow relationship.
#[derive(sqlx::FromRow, serde::Serialize)]
struct PendingFollow {
    id: Uuid,
    follower_id: Uuid,
    follower_ap_id: String,
    follower_username: String,
}

/// List pending inbound follow requests for a local actor.
async fn list_pending_follows(
    State(state): State<AppState>,
    Path(username): Path<String>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let local_actor = require_local_actor(&state.pool, &principal, &username).await?;

    let rows = sqlx::query_as::<_, PendingFollow>(
        r#"SELECT f.id, f.follower_id,
                  a.ap_id AS follower_ap_id,
                  a.username AS follower_username
           FROM follows f
           JOIN actors a ON a.id = f.follower_id
           WHERE f.following_id = $1 AND f.accepted = FALSE
           ORDER BY f.created_at DESC"#,
    )
    .bind(local_actor.id)
    .fetch_all(&state.pool)
    .await
    .map_err(noombat_core::error::NoombatError::from)?;

    Ok(Json(rows))
}

/// Accept a pending inbound follow and deliver an `Accept { Follow }`.
async fn accept_pending_follow(
    State(state): State<AppState>,
    Path((username, follow_id)): Path<(String, Uuid)>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let local_actor = require_local_actor(&state.pool, &principal, &username).await?;

    // Fetch the follow row, verifying it targets this actor and is pending.
    let row = sqlx::query_as::<_, (Uuid, bool, Option<String>)>(
        r#"SELECT follower_id, accepted, ap_id FROM follows
           WHERE id = $1 AND following_id = $2"#,
    )
    .bind(follow_id)
    .bind(local_actor.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(NoombatError::from)?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "follow",
        id: follow_id,
    })?;

    if row.1 {
        return Ok(StatusCode::OK);
    }

    let follower = noombat_identity::repo::find_by_id(&state.pool, row.0).await?;
    let original_follow_ap_id = row.2;

    noombat_identity::repo::accept_follow(&state.pool, follower.id, local_actor.id).await?;

    // Deliver Accept { Follow }. Include the original Follow's AP id
    // when available so that the remote server can correlate the
    // acceptance with its pending request (required by Mastodon).
    let accept_id = format!(
        "{}#accept-follow-{}",
        local_actor.ap_id,
        chrono::Utc::now().timestamp()
    );
    let mut inner_follow = json!({
        "type": "Follow",
        "actor": follower.ap_id,
        "object": local_actor.ap_id,
    });
    if let Some(ref fid) = original_follow_ap_id {
        inner_follow["id"] = json!(fid);
    }
    let accept_activity = json!({
        "@context": default_context(),
        "id": accept_id,
        "type": "Accept",
        "actor": local_actor.ap_id,
        "object": inner_follow,
    });
    let remote_inbox = follower
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{}/inbox", follower.ap_id));
    noombat_federation::delivery::enqueue(
        &state.pool,
        local_actor.id,
        &accept_activity,
        &remote_inbox,
    )
    .await?;

    Ok(StatusCode::OK)
}

/// Reject a pending inbound follow and deliver a `Reject { Follow }`.
async fn reject_pending_follow(
    State(state): State<AppState>,
    Path((username, follow_id)): Path<(String, Uuid)>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let local_actor = require_local_actor(&state.pool, &principal, &username).await?;

    let row = sqlx::query_as::<_, (Uuid, Option<String>)>(
        r#"SELECT follower_id, ap_id FROM follows
           WHERE id = $1 AND following_id = $2 AND accepted = FALSE"#,
    )
    .bind(follow_id)
    .bind(local_actor.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(NoombatError::from)?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "follow",
        id: follow_id,
    })?;

    let follower = noombat_identity::repo::find_by_id(&state.pool, row.0).await?;
    let original_follow_ap_id = row.1;

    // Delete the pending follow.
    noombat_identity::repo::delete_follow(&state.pool, follower.id, local_actor.id).await?;

    // Deliver Reject { Follow }.
    let reject_id = format!(
        "{}#reject-follow-{}",
        local_actor.ap_id,
        chrono::Utc::now().timestamp()
    );
    let mut inner_follow = json!({
        "type": "Follow",
        "actor": follower.ap_id,
        "object": local_actor.ap_id,
    });
    if let Some(ref fid) = original_follow_ap_id {
        inner_follow["id"] = json!(fid);
    }
    let reject_activity = json!({
        "@context": default_context(),
        "id": reject_id,
        "type": "Reject",
        "actor": local_actor.ap_id,
        "object": inner_follow,
    });
    let remote_inbox = follower
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{}/inbox", follower.ap_id));
    noombat_federation::delivery::enqueue(
        &state.pool,
        local_actor.id,
        &reject_activity,
        &remote_inbox,
    )
    .await?;

    Ok(StatusCode::OK)
}
