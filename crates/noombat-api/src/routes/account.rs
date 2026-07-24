// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Account data portability and deletion endpoints.
//!
//! - `GET  /api/v1/me/export`         ZIP archive of all user data
//! - `POST /api/v1/me/delete`         initiate deletion grace period
//! - `POST /api/v1/me/cancel-delete`  cancel pending deletion

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use noombat_core::error::NoombatError;
use serde::Serialize;
use std::io::Write;
use tracing::info;
use uuid::Uuid;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/me/export", get(export_data))
        .route("/api/v1/me/delete", post(request_deletion))
        .route("/api/v1/me/cancel-delete", post(cancel_deletion))
}

/// Require an authenticated principal with a known actor UUID.
fn require_actor(
    principal: &Option<axum::Extension<Principal>>,
) -> Result<(Uuid, String), ApiError> {
    let principal = principal
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = principal
        .actor_id()
        .ok_or(ApiError(NoombatError::Forbidden))?;
    let username = principal
        .username
        .clone()
        .unwrap_or_else(|| actor_id.to_string());
    Ok((actor_id, username))
}

// ..... DATA EXPORT .....

/// `GET /api/v1/me/export`
///
/// Returns a ZIP archive containing the authenticated user's data in
/// JSON-LD–compatible format. The archive is generated in memory.
async fn export_data(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<Response, ApiError> {
    let (actor_id, _username) = require_actor(&principal)?;

    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        // Actor profile (sensitive columns excluded).
        let actor: serde_json::Value = sqlx::query_scalar(
            r#"SELECT row_to_json(t) FROM (
                SELECT id, actor_type, ap_id, username, display_name,
                       avatar_url, header_url, summary_md, summary_html,
                       domain, is_local, instance_role, actor_status,
                       chatmail_addr, orcid, moved_to, headline,
                       actor_privacy, created_at, updated_at
                FROM actors WHERE id = $1
            ) t"#,
        )
        .bind(actor_id)
        .fetch_one(&state.pool)
        .await
        .map_err(NoombatError::from)?;

        write_json_entry(&mut zip, "actor.json", &actor, opts)?;

        // Experiences.
        let experiences: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(e) FROM experiences e WHERE actor_id = $1 ORDER BY sort_order",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        write_json_entry(&mut zip, "experiences.json", &experiences, opts)?;

        // Educations.
        let educations: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(e) FROM educations e WHERE actor_id = $1 ORDER BY sort_order",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        write_json_entry(&mut zip, "educations.json", &educations, opts)?;

        // Skills.
        let skills: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT row_to_json(s) FROM skills s WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        write_json_entry(&mut zip, "skills.json", &skills, opts)?;

        // Publications.
        let publications: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(p) FROM publications p WHERE actor_id = $1 ORDER BY sort_order",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        write_json_entry(&mut zip, "publications.json", &publications, opts)?;

        // Custom sections.
        let custom_sections: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(c) FROM custom_profile_sections c WHERE actor_id = $1 ORDER BY sort_order",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        write_json_entry(&mut zip, "custom_sections.json", &custom_sections, opts)?;

        // Posts.
        let posts: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(p) FROM posts p WHERE actor_id = $1 ORDER BY created_at",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        write_json_entry(&mut zip, "posts.json", &posts, opts)?;

        // Social graph: followers.
        let followers: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(f) FROM follows f WHERE following_id = $1 AND accepted = TRUE",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

        // Social graph: following.
        let following: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(f) FROM follows f WHERE follower_id = $1 AND accepted = TRUE",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        let social_graph = serde_json::json!({
            "followers": followers,
            "following": following,
        });
        write_json_entry(&mut zip, "social_graph.json", &social_graph, opts)?;

        // Group memberships.
        let memberships: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT row_to_json(g) FROM group_memberships g WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        write_json_entry(&mut zip, "group_memberships.json", &memberships, opts)?;

        // Event RSVPs.
        let rsvps: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT row_to_json(r) FROM event_rsvps r WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        write_json_entry(&mut zip, "event_rsvps.json", &rsvps, opts)?;

        // Verified links.
        let links: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT row_to_json(l) FROM verified_links l WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        write_json_entry(&mut zip, "verified_links.json", &links, opts)?;

        // Blocks.
        let blocks: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT row_to_json(b) FROM blocks b WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        write_json_entry(&mut zip, "blocks.json", &blocks, opts)?;

        // Mutes.
        let mutes: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT row_to_json(m) FROM mutes m WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        write_json_entry(&mut zip, "mutes.json", &mutes, opts)?;

        // Job applications (applicant side).
        let applications: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT row_to_json(a) FROM applications a WHERE applicant_id = $1")
                .bind(actor_id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        write_json_entry(&mut zip, "job_applications.json", &applications, opts)?;

        zip.finish()
            .map_err(|e| ApiError(NoombatError::Internal(e.to_string())))?;
    }

    info!(actor_id = %actor_id, "data export generated");

    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/zip"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"noombat-export.zip\"",
            ),
        ],
        buf,
    )
        .into_response())
}

/// Helper: write a JSON value as a file entry in the ZIP archive.
fn write_json_entry<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    name: &str,
    value: &impl Serialize,
    options: SimpleFileOptions,
) -> Result<(), ApiError> {
    let json_bytes = serde_json::to_vec_pretty(value).map_err(NoombatError::from)?;
    zip.start_file(name, options)
        .map_err(|e| ApiError(NoombatError::Internal(e.to_string())))?;
    zip.write_all(&json_bytes)
        .map_err(|e| ApiError(NoombatError::Internal(e.to_string())))?;
    Ok(())
}

// ..... ACCOUNT DELETION .....

/// `POST /api/v1/me/delete`
///
/// Initiates the deletion grace period (default: 30 days). The actual
/// deletion is executed by a background worker after the grace period
/// elapses.
async fn request_deletion(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let (actor_id, username) = require_actor(&principal)?;

    // Check whether a deletion is already pending.
    let existing: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deletion_requested_at FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await
            .map_err(NoombatError::from)?;

    if existing.is_some() {
        return Err(ApiError(NoombatError::BadRequest(
            "deletion already requested".into(),
        )));
    }

    sqlx::query(
        "UPDATE actors SET deletion_requested_at = now(), updated_at = now() WHERE id = $1",
    )
    .bind(actor_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    info!(actor_id = %actor_id, username = %username, "account deletion requested");

    Ok(Json(serde_json::json!({
        "status": "deletion_pending",
        "grace_period_days": 30,
    })))
}

/// `POST /api/v1/me/cancel-delete`
///
/// Cancels a pending deletion request if the grace period has not
/// elapsed.
async fn cancel_deletion(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let (actor_id, username) = require_actor(&principal)?;

    let result = sqlx::query(
        "UPDATE actors SET deletion_requested_at = NULL, updated_at = now() \
         WHERE id = $1 AND deletion_requested_at IS NOT NULL",
    )
    .bind(actor_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    if result.rows_affected() == 0 {
        return Err(ApiError(NoombatError::BadRequest(
            "no pending deletion to cancel".into(),
        )));
    }

    info!(actor_id = %actor_id, username = %username, "account deletion cancelled");

    Ok(Json(serde_json::json!({ "status": "deletion_cancelled" })))
}
