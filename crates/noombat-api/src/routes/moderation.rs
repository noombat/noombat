// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Moderation routes: suspension/unsuspension orchestration, chat
//! report resolution, and report listing.
//!
//! All endpoints require the `moderator` or `admin` instance role.
//!
//! - `POST   /api/v1/admin/actors/{id}/suspend`
//! - `POST   /api/v1/admin/actors/{id}/unsuspend`
//! - `POST   /api/v1/admin/chat-reports/{id}/resolve`
//! - `GET    /api/v1/admin/chat-reports`
//! - `GET    /api/v1/admin/reports`

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use noombat_core::actor::{ActorStatus, InstanceRole};
use noombat_core::error::NoombatError;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/actors/{id}/suspend", post(suspend_actor))
        .route("/api/v1/admin/actors/{id}/unsuspend", post(unsuspend_actor))
        .route(
            "/api/v1/admin/chat-reports/{id}/resolve",
            post(resolve_chat_report),
        )
        .route("/api/v1/admin/chat-reports", get(list_chat_reports))
        .route("/api/v1/admin/reports", get(list_reports))
}

// ..... HELPERS .....

/// Verify that the authenticated principal holds the moderator or
/// admin role. Returns the principal on success.
fn require_moderator(
    principal: &Option<axum::Extension<Principal>>,
) -> Result<&Principal, ApiError> {
    let principal = principal
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?;
    match principal.instance_role {
        Some(InstanceRole::Moderator | InstanceRole::Admin) => Ok(principal),
        _ => Err(ApiError(NoombatError::Forbidden)),
    }
}

// ..... SUSPENSION .....

/// Request body for `POST /api/v1/admin/actors/{id}/suspend`.
#[derive(Debug, Deserialize)]
pub struct SuspendRequest {
    /// Optional note explaining the reason for suspension.
    pub reason: Option<String>,
}

/// Execute the full five-step suspension procedure.
///
/// Shared by the `POST .../suspend` handler and the `Suspend` action
/// in chat-report resolution, ensuring both code paths federate the
/// `Delete` activity and perform all sidecar steps.
async fn execute_suspension(state: &AppState, actor_id: Uuid) -> Result<(), ApiError> {
    // Step 1: set actor_status to suspended.
    let actor =
        noombat_identity::repo::set_actor_status(&state.pool, actor_id, ActorStatus::Suspended)
            .await?;

    // Remove from search index.
    if let Some(ref search) = state.search {
        let _ = search.delete("profiles", &actor_id.to_string()).await;
    }

    // Chatmail credential invalidation via the sidecar.
    if let Some(chatmail_addr) = &actor.chatmail_addr {
        if let Some(client) = state.chatmail_admin_client.as_ref() {
            // Step 2: rotate the Chatmail password.
            match client.rotate_password(chatmail_addr).await {
                Ok(_) => info!(address = %chatmail_addr, "chatmail password rotated (step 2)"),
                Err(e) => warn!(address = %chatmail_addr, error = %e, "password rotation failed"),
            }

            // Step 3: terminate active IMAP sessions.
            if let Err(e) = client.kick_sessions(chatmail_addr).await {
                warn!(address = %chatmail_addr, error = %e, "session kick failed");
            } else {
                info!(address = %chatmail_addr, "IMAP sessions terminated (step 3)");
            }

            // Step 4: block inbound mail to the suspended address.
            if let Err(e) = client.block_recipient(chatmail_addr).await {
                warn!(address = %chatmail_addr, error = %e, "recipient block failed");
            } else {
                info!(address = %chatmail_addr, "recipient blocked (step 4)");
            }
        } else {
            warn!(
                actor_id = %actor_id,
                "chatmail admin sidecar not configured; steps 2-4 skipped"
            );
        }
    }

    // Federate a Delete activity for the suspended actor.
    let ap_id = &actor.ap_id;
    let delete_activity = serde_json::json!({
        "@context": noombat_ap::context::default_context(),
        "id": format!("{ap_id}#suspend-{}", chrono::Utc::now().timestamp_millis()),
        "type": "Delete",
        "actor": ap_id,
        "object": ap_id,
    });

    let follower_inboxes =
        noombat_identity::repo::get_follower_inboxes(&state.pool, actor_id).await;
    if let Ok(inboxes) = follower_inboxes {
        for inbox in inboxes {
            let _ = noombat_federation::delivery::enqueue(
                &state.pool,
                actor_id,
                &delete_activity,
                &inbox,
            )
            .await;
        }
    }

    Ok(())
}

/// Axum handler for `POST /api/v1/admin/actors/{id}/suspend`.
async fn suspend_actor(
    State(state): State<AppState>,
    Path(actor_id): Path<Uuid>,
    principal: Option<axum::Extension<Principal>>,
    Json(body): Json<SuspendRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator(&principal)?;

    execute_suspension(&state, actor_id).await?;

    info!(
        actor_id = %actor_id,
        moderator = ?moderator.username,
        reason = ?body.reason,
        "actor suspended"
    );

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "actor_id": actor_id,
            "status": "suspended",
        })),
    ))
}

// ..... UNSUSPENSION .....

/// Unsuspension procedure:
///
/// 1. Set `actor_status` to `active`.
/// 2. Unblock the recipient address via the sidecar.
/// 3. Set `chat_requires_reprovisioning` flag.
async fn unsuspend_actor(
    State(state): State<AppState>,
    Path(actor_id): Path<Uuid>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator(&principal)?;

    // Step 1: set actor_status to active.
    let actor =
        noombat_identity::repo::set_actor_status(&state.pool, actor_id, ActorStatus::Active)
            .await?;

    info!(
        actor_id = %actor_id,
        moderator = ?moderator.username,
        "actor unsuspended (step 1: status set to active)"
    );

    // Step 2: unblock the recipient address.
    if let Some(chatmail_addr) = &actor.chatmail_addr
        && let Some(client) = state.chatmail_admin_client.as_ref()
    {
        if let Err(e) = client.unblock_recipient(chatmail_addr).await {
            warn!(address = %chatmail_addr, error = %e, "recipient unblock failed");
        } else {
            info!(address = %chatmail_addr, "recipient unblocked (step 2)");
        }
    }

    // Step 3: set chat_requires_reprovisioning flag.
    sqlx::query(
        "UPDATE actors SET chat_requires_reprovisioning = TRUE, updated_at = now() WHERE id = $1",
    )
    .bind(actor_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    info!(actor_id = %actor_id, "chat_requires_reprovisioning flag set (step 3)");

    // Re-index if the actor is discoverable. Re-fetch the actor to
    // capture the updated chat_requires_reprovisioning flag and
    // actor_status.
    if actor.actor_privacy.discoverable
        && let Some(ref search) = state.search
        && let Ok(fresh_actor) = noombat_identity::repo::find_by_id(&state.pool, actor_id).await
    {
        let _ = search
            .upsert(
                "profiles",
                &actor_id.to_string(),
                serde_json::to_value(&fresh_actor).unwrap_or_default(),
            )
            .await;
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "actor_id": actor_id,
            "status": "active",
            "chat_requires_reprovisioning": true,
        })),
    ))
}

// ..... CHAT REPORT RESOLUTION .....

/// Action to take when resolving a chat report.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportAction {
    /// False positive: dismiss without action.
    Dismiss,
    /// Issue a warning to the target actor (logged, no enforcement).
    Warn,
    /// Block the sender's Chatmail address at the proxy level.
    BlockSender,
    /// Block a specific sender to recipient pair at the relay level
    /// (via the sidecar).
    BlockSenderPair,
    /// Suspend the target actor's Noombat account (triggers the
    /// full five-step suspension procedure).
    Suspend,
}

/// Request body for `POST /api/v1/admin/chat-reports/{id}/resolve`.
#[derive(Debug, Deserialize)]
pub struct ResolveReportRequest {
    /// The enforcement action to take.
    pub action: ReportAction,
    /// Optional resolution note.
    pub note: Option<String>,
    /// The actor ID of the target (required for `Suspend`).
    pub target_actor_id: Option<Uuid>,
    /// The recipient Chatmail address (required for
    /// `BlockSenderPair`).
    pub recipient_addr: Option<String>,
}

async fn resolve_chat_report(
    State(state): State<AppState>,
    Path(report_id): Path<Uuid>,
    principal: Option<axum::Extension<Principal>>,
    Json(body): Json<ResolveReportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator(&principal)?;
    let moderator_id = moderator.actor_id();

    // Fetch the report.
    let (reporter_id, target_addr, status): (Uuid, String, String) =
        sqlx::query_as("SELECT reporter_id, target_addr, status FROM chat_reports WHERE id = $1")
            .bind(report_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(NoombatError::from)?
            .ok_or(NoombatError::NotFound {
                entity: "chat_report",
                id: report_id,
            })?;

    if status != "open" {
        return Err(ApiError(NoombatError::BadRequest(
            "report is already resolved".into(),
        )));
    }

    // Execute the enforcement action.
    match body.action {
        ReportAction::Dismiss => {
            info!(report_id = %report_id, "chat report dismissed");
        }

        ReportAction::Warn => {
            info!(report_id = %report_id, target = %target_addr, "warning issued");
            // A warning is logged but has no automated enforcement.
            // TODO: deliver an in-app notification to the target.
        }

        ReportAction::BlockSender => {
            // Block the sender address in the reporter's proxy-level
            // block list. The reporter is the recipient of the
            // unwanted message; target_addr is the sender.
            noombat_chat::relay::block_sender(&state.pool, reporter_id, &target_addr).await?;
            info!(
                report_id = %report_id,
                target = %target_addr,
                reporter = %reporter_id,
                "sender blocked at proxy level for reporter"
            );
        }

        ReportAction::BlockSenderPair => {
            let recipient =
                body.recipient_addr
                    .as_deref()
                    .ok_or(ApiError(NoombatError::BadRequest(
                        "recipient_addr required for block_sender_pair".into(),
                    )))?;
            if let Some(client) = state.chatmail_admin_client.as_ref() {
                client.block_sender_pair(&target_addr, recipient).await?;
                info!(
                    report_id = %report_id,
                    sender = %target_addr,
                    recipient = %recipient,
                    "sender pair blocked at relay level"
                );
            } else {
                return Err(ApiError(NoombatError::ServiceUnavailable(
                    "chatmail admin sidecar not configured".into(),
                )));
            }
        }

        ReportAction::Suspend => {
            let target_actor_id =
                body.target_actor_id
                    .ok_or(ApiError(NoombatError::BadRequest(
                        "target_actor_id required for suspend action".into(),
                    )))?;
            execute_suspension(&state, target_actor_id).await?;
            info!(
                report_id = %report_id,
                target_actor_id = %target_actor_id,
                "actor suspended via chat report resolution"
            );
        }
    }

    // Mark the report as resolved.
    let resolution_status = match body.action {
        ReportAction::Dismiss => "dismissed",
        _ => "resolved",
    };
    sqlx::query(
        r#"UPDATE chat_reports
           SET status = $1, resolved_by = $2, resolution_note = $3,
               resolved_at = now()
           WHERE id = $4"#,
    )
    .bind(resolution_status)
    .bind(moderator_id)
    .bind(&body.note)
    .bind(report_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "report_id": report_id,
            "status": resolution_status,
        })),
    ))
}

// ..... REPORT LISTING .....

/// A chat report entry for the moderation queue.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ChatReportEntry {
    pub id: Uuid,
    pub reporter_id: Uuid,
    pub target_addr: String,
    pub message_content: Option<String>,
    pub reason: String,
    pub comment: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /api/v1/admin/chat-reports`: list open chat reports.
async fn list_chat_reports(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    require_moderator(&principal)?;

    let reports: Vec<ChatReportEntry> = sqlx::query_as(
        r#"SELECT id, reporter_id, target_addr, message_content,
                      reason, comment, status, created_at
               FROM chat_reports
               WHERE status = 'open'
               ORDER BY created_at ASC
               LIMIT 100"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok(Json(reports))
}

/// An ActivityPub report entry for the moderation queue.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReportEntry {
    pub id: Uuid,
    pub reporter_id: Uuid,
    pub target_actor_id: Option<Uuid>,
    pub target_post_id: Option<Uuid>,
    pub reason: String,
    pub comment: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /api/v1/admin/reports`: list open ActivityPub reports.
async fn list_reports(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    require_moderator(&principal)?;

    let reports: Vec<ReportEntry> = sqlx::query_as(
        r#"SELECT id, reporter_id, target_actor_id, target_post_id,
                      reason, comment, status, created_at
               FROM reports
               WHERE status = 'open'
               ORDER BY created_at ASC
               LIMIT 100"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok(Json(reports))
}
