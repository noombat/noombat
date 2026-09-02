// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Moderation routes: suspension/unsuspension orchestration, chat
//! report resolution, report listing, user-facing report creation,
//! and AP report resolution.
//!
//! Moderator and admin endpoints:
//! - `POST   /api/v1/admin/actors/{id}/suspend`
//! - `POST   /api/v1/admin/actors/{id}/unsuspend`
//! - `POST   /api/v1/admin/chat-reports/{id}/resolve`
//! - `GET    /api/v1/admin/chat-reports`
//! - `GET    /api/v1/admin/reports`
//! - `POST   /api/v1/admin/reports/{id}/resolve`
//!
//! User-facing:
//! - `POST   /api/v1/reports`

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
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
        // User-facing: create a report.
        .route("/api/v1/reports", post(create_report))
        // Moderator: resolve an AP report.
        .route("/api/v1/admin/reports/{id}/resolve", post(resolve_report))
        // Moderator: read one application, stating why.
        .route(
            "/api/v1/admin/applications/{id}/review",
            post(review_job_application),
        )
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
    // `target_chat_addr IS NOT NULL` is what makes this the chat case, now
    // that one table holds every kind of report. Without it this route would
    // accept a post report and then try to block an address that is NULL.
    let (reporter_id, target_addr, status): (Uuid, String, String) = sqlx::query_as(
        "SELECT reporter_id, target_chat_addr, status FROM reports \
         WHERE id = $1 AND target_chat_addr IS NOT NULL",
    )
    .bind(report_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(NoombatError::from)?
    .ok_or(NoombatError::NotFound {
        entity: "chat report",
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
        r#"UPDATE reports
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

    // A filtered view of the one report table, not a table of its own. The
    // aliases keep the response shape the moderation queue already consumes.
    let reports: Vec<ChatReportEntry> = sqlx::query_as(
        r#"SELECT id, reporter_id,
                  target_chat_addr AS target_addr,
                  reported_message AS message_content,
                  reason, comment, status, created_at
           FROM reports
           WHERE status = 'open' AND target_chat_addr IS NOT NULL
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

// ..... REPORT CREATION (user-facing) .....

/// Request body for `POST /api/v1/reports`.
#[derive(Debug, Deserialize)]
pub struct CreateReportRequest {
    /// Target actor UUID (report a profile/actor).
    pub target_actor_id: Option<Uuid>,
    /// Target post UUID (report a post).
    pub target_post_id: Option<Uuid>,
    /// Reason category.
    pub reason: String,
    /// Optional free-text comment.
    pub comment: Option<String>,
    /// Whether to forward the report to the remote instance as a `Flag`
    /// activity (only applicable when the target is a remote actor).
    #[serde(default)]
    pub forward: bool,
}

/// `POST /api/v1/reports`: any authenticated user may create a report.
///
/// Accepts `application/x-www-form-urlencoded` (HTMX default) or
/// `application/json`.
async fn create_report(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Form(body): Form<CreateReportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let reporter = principal
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?;
    let reporter_id = reporter
        .actor_id()
        .ok_or(ApiError(NoombatError::Forbidden))?;

    if body.target_actor_id.is_none() && body.target_post_id.is_none() {
        return Err(ApiError(NoombatError::BadRequest(
            "either target_actor_id or target_post_id is required".into(),
        )));
    }

    const VALID_REASONS: &[&str] = &["spam", "harassment", "illegal", "impersonation", "other"];
    if !VALID_REASONS.contains(&body.reason.as_str()) {
        return Err(ApiError(NoombatError::BadRequest(format!(
            "invalid reason: expected one of {}",
            VALID_REASONS.join(", ")
        ))));
    }

    let report_id = Uuid::new_v4();

    sqlx::query(
        r#"INSERT INTO reports (id, reporter_id, target_actor_id, target_post_id, reason, comment)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(report_id)
    .bind(reporter_id)
    .bind(body.target_actor_id)
    .bind(body.target_post_id)
    .bind(&body.reason)
    .bind(&body.comment)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    info!(
        report_id = %report_id,
        reporter = ?reporter.username,
        reason = %body.reason,
        "report created"
    );

    // Optionally forward as a Flag activity to the remote instance.
    if body.forward
        && let Some(target_actor_id) = body.target_actor_id
    {
        let _ = forward_flag(
            &state,
            reporter_id,
            target_actor_id,
            &body.reason,
            body.comment.as_deref(),
        )
        .await;
    }

    Ok((
        StatusCode::CREATED,
        axum::response::Html(format!(
            r#"<p class="text-sm text-text-brand">{}</p>"#,
            "Report submitted. A moderator will review it."
        )),
    ))
}

/// Forward a report to the target actor's origin instance as a `Flag`
/// activity, following the Mastodon convention.
async fn forward_flag(
    state: &AppState,
    reporter_id: Uuid,
    target_actor_id: Uuid,
    reason: &str,
    comment: Option<&str>,
) -> Result<(), ApiError> {
    let reporter = noombat_identity::repo::find_by_id(&state.pool, reporter_id).await?;
    let target = noombat_identity::repo::find_by_id(&state.pool, target_actor_id).await?;

    // Only forward to remote actors.
    if target.is_local {
        return Ok(());
    }

    let flag_id = format!(
        "{}#flag-{}",
        reporter.ap_id,
        chrono::Utc::now().timestamp_millis()
    );

    let mut flag_activity = serde_json::json!({
        "@context": noombat_ap::context::default_context(),
        "id": flag_id,
        "type": "Flag",
        "actor": reporter.ap_id,
        "object": [target.ap_id],
    });

    // Include the reason and comment in the content field.
    let content = match comment {
        Some(c) => format!("{reason}: {c}"),
        None => reason.to_string(),
    };
    flag_activity["content"] = serde_json::Value::String(content);

    let target_inbox = target
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{}/inbox", target.ap_id));

    noombat_federation::delivery::enqueue(&state.pool, reporter_id, &flag_activity, &target_inbox)
        .await?;

    // Mark the report as forwarded.
    sqlx::query(
        "UPDATE reports SET forwarded = TRUE WHERE reporter_id = $1 AND target_actor_id = $2 AND status = 'open'",
    )
    .bind(reporter_id)
    .bind(target_actor_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    info!(
        reporter = %reporter.ap_id,
        target = %target.ap_id,
        "Flag activity forwarded to remote instance"
    );

    Ok(())
}

// ..... AP REPORT RESOLUTION .....

/// Action to take when resolving an ActivityPub report.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApReportAction {
    Dismiss,
    Warn,
    RemoveContent,
    Silence,
    Suspend,
}

/// Request body for `POST /api/v1/admin/reports/{id}/resolve`.
#[derive(Debug, Deserialize)]
pub struct ResolveApReportRequest {
    pub action: ApReportAction,
    pub note: Option<String>,
}

/// `POST /api/v1/admin/reports/{id}/resolve`: moderator resolves an AP report.
async fn resolve_report(
    State(state): State<AppState>,
    Path(report_id): Path<Uuid>,
    principal: Option<axum::Extension<Principal>>,
    Form(body): Form<ResolveApReportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator(&principal)?;
    let moderator_id = moderator.actor_id();

    // Fetch the report.
    let (target_actor_id, target_post_id, status): (Option<Uuid>, Option<Uuid>, String) =
        sqlx::query_as("SELECT target_actor_id, target_post_id, status FROM reports WHERE id = $1")
            .bind(report_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(NoombatError::from)?
            .ok_or(NoombatError::NotFound {
                entity: "report",
                id: report_id,
            })?;

    if status != "open" {
        return Err(ApiError(NoombatError::BadRequest(
            "report is already resolved".into(),
        )));
    }

    match body.action {
        ApReportAction::Dismiss => {
            info!(report_id = %report_id, "AP report dismissed");
        }
        ApReportAction::Warn => {
            info!(report_id = %report_id, "warning issued for AP report");
        }
        ApReportAction::RemoveContent => {
            if let Some(post_id) = target_post_id {
                sqlx::query("DELETE FROM posts WHERE id = $1")
                    .bind(post_id)
                    .execute(&state.pool)
                    .await
                    .map_err(NoombatError::from)?;
                info!(report_id = %report_id, post_id = %post_id, "reported post removed");
            }
        }
        ApReportAction::Silence => {
            if let Some(actor_id) = target_actor_id {
                noombat_identity::repo::set_actor_status(
                    &state.pool,
                    actor_id,
                    noombat_core::actor::ActorStatus::Silenced,
                )
                .await?;
                info!(report_id = %report_id, actor_id = %actor_id, "actor silenced");
            }
        }
        ApReportAction::Suspend => {
            if let Some(actor_id) = target_actor_id {
                execute_suspension(&state, actor_id).await?;
                info!(report_id = %report_id, actor_id = %actor_id, "actor suspended via AP report");
            }
        }
    }

    let resolution_status = match body.action {
        ApReportAction::Dismiss => "dismissed",
        _ => "resolved",
    };

    sqlx::query(
        r#"UPDATE reports
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

    // Return an empty body so that hx-swap="outerHTML" on the report
    // article removes the resolved entry from the moderation queue.
    Ok((StatusCode::OK, axum::response::Html(String::new())))
}

// ..... JOB_APPLICATION REVIEW .....

/// Request body for `POST /api/v1/admin/applications/{id}/review`.
#[derive(Debug, Deserialize)]
pub struct ReviewJobApplicationRequest {
    /// Why this application is being read. Shown to the applicant.
    pub reason: String,
}

/// One application, as a moderator investigating a report sees it.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct JobApplicationReview {
    pub id: Uuid,
    pub applicant_id: Uuid,
    pub posting_title: String,
    pub posting_organization: String,
    pub status: String,
    pub cover_letter_md: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `POST /api/v1/admin/applications/{id}/review`
///
/// Read one application as a moderator, stating why. The read is written
/// to `job_application_accesses` in the same transaction, so it appears in
/// the applicant's own record of who saw their application.
///
/// A read is not authority to act: nothing here can move an application
/// through its states. That stays with the organisation.
async fn review_job_application(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReviewJobApplicationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator(&principal)?;

    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(ApiError(NoombatError::BadRequest(
            "reason must not be empty".into(),
        )));
    }

    // The moderator's own actor, so the log names a person rather than a
    // role. A principal carrying no actor id is refused: an
    // unattributable read is what this route exists to prevent.
    let reader_id = moderator
        .actor_uuid
        .ok_or(ApiError(NoombatError::Forbidden))?;

    let mut tx = state.pool.begin().await.map_err(NoombatError::from)?;

    let application = sqlx::query_as::<_, JobApplicationReview>(
        "SELECT id, applicant_id, posting_title, posting_organization, status, \
                cover_letter_md, created_at \
         FROM job_applications WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(NoombatError::from)?
    .ok_or(ApiError(NoombatError::NotFound {
        entity: "application",
        id,
    }))?;

    sqlx::query(
        "INSERT INTO job_application_accesses \
             (job_application_id, reader_id, kind, outcome, reason) \
         VALUES ($1, $2, 'moderator_review', 'disclosed', $3)",
    )
    .bind(id)
    .bind(reader_id)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(NoombatError::from)?;

    tx.commit().await.map_err(NoombatError::from)?;

    info!(
        job_application_id = %id,
        moderator = %reader_id,
        "moderator read an application"
    );

    Ok(Json(application))
}
