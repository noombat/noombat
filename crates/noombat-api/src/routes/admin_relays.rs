// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Admin relay management routes.
//!
//! - `GET    /api/v1/admin/relays`          list subscriptions
//! - `POST   /api/v1/admin/relays`          subscribe to a relay
//! - `DELETE /api/v1/admin/relays/{id}`     unsubscribe
//!
//! All endpoints require the `admin` instance role.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use noombat_core::error::NoombatError;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/admin/relays",
            get(list_relays).post(subscribe_relay),
        )
        .route(
            "/api/v1/admin/relays/{id}",
            axum::routing::delete(unsubscribe_relay),
        )
}

/// Verify that the authenticated viewer holds the admin role.
fn require_admin(viewer: &Option<axum::Extension<Viewer>>) -> Result<&Viewer, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    if viewer.may_administer() {
        Ok(viewer)
    } else {
        Err(ApiError(NoombatError::Forbidden))
    }
}

/// Response for relay listing.
#[derive(Debug, Serialize)]
struct RelayInfo {
    id: Uuid,
    inbox_url: String,
    status: String,
    verification_policy: Option<String>,
}

/// `GET /api/v1/admin/relays`
async fn list_relays(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&viewer)?;

    let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>)>(
        "SELECT id, inbox_url, status, verification_policy \
         FROM relay_subscriptions ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    let relays: Vec<RelayInfo> = rows
        .into_iter()
        .map(|(id, inbox_url, status, verification_policy)| RelayInfo {
            id,
            inbox_url,
            status,
            verification_policy,
        })
        .collect();

    Ok(Json(relays))
}

/// Request body for relay subscription.
#[derive(Debug, Deserialize)]
struct SubscribeRequest {
    /// The relay's inbox URL (e.g. `https://relay.example/inbox`).
    inbox_url: String,
    /// Per-relay verification policy override. If `None`, the
    /// instance-wide default is used.
    verification_policy: Option<String>,
}

/// `POST /api/v1/admin/relays`
async fn subscribe_relay(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<SubscribeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let admin = require_admin(&viewer)?;

    // Validate the per-relay verification policy if specified.
    if let Some(ref policy) = body.verification_policy
        && noombat_federation::relay_verify::RelayVerificationPolicy::from_str_opt(policy).is_none()
    {
        return Err(ApiError(NoombatError::BadRequest(format!(
            "invalid verification policy: {policy} \
                 (expected 'verify', 'verify-or-fetch', or 'trust-relay')"
        ))));
    }

    // Find the instance actor for signing the Follow activity.
    let instance_actor_id =
        noombat_federation::signed_fetch::find_local_signing_actor(&state.pool).await?;
    let instance_actor = noombat_identity::repo::find_by_id(&state.pool, instance_actor_id).await?;

    noombat_federation::relay::subscribe(
        &state.pool,
        instance_actor_id,
        &instance_actor.ap_id,
        &body.inbox_url,
    )
    .await?;

    // Store the per-relay verification policy if specified.
    if let Some(ref policy) = body.verification_policy {
        sqlx::query("UPDATE relay_subscriptions SET verification_policy = $1 WHERE inbox_url = $2")
            .bind(policy)
            .bind(&body.inbox_url)
            .execute(&state.pool)
            .await
            .map_err(NoombatError::from)?;
    }

    info!(
        admin = ?admin.username,
        relay = body.inbox_url,
        "relay subscription initiated"
    );

    Ok(StatusCode::ACCEPTED)
}

/// `DELETE /api/v1/admin/relays/{id}`
async fn unsubscribe_relay(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Path(relay_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let admin = require_admin(&viewer)?;

    let row =
        sqlx::query_as::<_, (String,)>("SELECT inbox_url FROM relay_subscriptions WHERE id = $1")
            .bind(relay_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(NoombatError::from)?;

    let inbox_url = match row {
        Some((url,)) => url,
        None => return Err(ApiError(NoombatError::BadRequest("relay not found".into()))),
    };

    let instance_actor_id =
        noombat_federation::signed_fetch::find_local_signing_actor(&state.pool).await?;
    let instance_actor = noombat_identity::repo::find_by_id(&state.pool, instance_actor_id).await?;

    noombat_federation::relay::unsubscribe(
        &state.pool,
        instance_actor_id,
        &instance_actor.ap_id,
        &inbox_url,
    )
    .await?;

    info!(
        admin = ?admin.username,
        relay = inbox_url,
        "relay unsubscribed"
    );

    Ok(StatusCode::NO_CONTENT)
}
