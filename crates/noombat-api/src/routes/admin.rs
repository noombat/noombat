// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Server-rendered administration and moderation pages.
//!
//! All routes require `moderator` or `admin` instance role. Admin-only
//! routes (instance settings, federation health) additionally check for
//! the `admin` role.
//!
//! Page routes:
//! - `GET  /admin`             redirect to moderation queue
//! - `GET  /admin/moderation`  unified moderation queue
//! - `GET  /admin/users`       user management
//! - `GET  /admin/domains`     domain management
//! - `GET  /admin/settings`    instance settings (admin only)
//! - `GET  /admin/federation`  federation health (admin only)
//!
//! API routes:
//! - `POST   /api/v1/admin/domains`             add domain restriction
//! - `DELETE /api/v1/admin/domains/{id}`        remove domain restriction
//! - `PATCH  /api/v1/admin/settings`            update instance settings
//! - `POST   /api/v1/admin/announcements`       create announcement
//! - `DELETE /api/v1/admin/announcements/{id}`  delete announcement

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Form, Json, Router};
use noombat_core::actor::InstanceRole;
use noombat_core::error::NoombatError;
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use crate::error::ApiError;
use crate::i18n::I18n;
use crate::middleware::Principal;
use crate::state::AppState;
use crate::theme::{Contrast, Theme};

pub fn router() -> Router<AppState> {
    Router::new()
        // Page routes.
        .route("/admin", get(admin_redirect))
        .route("/admin/moderation", get(moderation_page))
        .route("/admin/users", get(users_page))
        .route("/admin/domains", get(domains_page))
        .route("/admin/settings", get(settings_page))
        .route("/admin/federation", get(federation_page))
        // API routes.
        .route("/api/v1/admin/domains", post(add_domain_restriction))
        .route(
            "/api/v1/admin/domains/{id}",
            delete(remove_domain_restriction),
        )
        .route("/api/v1/admin/users/{username}/role", post(set_user_role))
        .route("/api/v1/admin/settings", patch(update_settings))
        .route("/api/v1/admin/announcements", post(create_announcement))
        .route(
            "/api/v1/admin/announcements/{id}",
            delete(delete_announcement),
        )
}

// ..... GUARDS .....

fn require_moderator(
    principal: &Option<axum::Extension<Principal>>,
) -> Result<&Principal, Box<Response>> {
    let principal = principal
        .as_ref()
        .ok_or_else(|| Box::new(Redirect::temporary("/auth/login").into_response()))?;
    match principal.instance_role {
        Some(InstanceRole::Moderator | InstanceRole::Admin) => Ok(principal),
        _ => Err(Box::new(Redirect::temporary("/").into_response())),
    }
}

fn require_admin(
    principal: &Option<axum::Extension<Principal>>,
) -> Result<&Principal, Box<Response>> {
    let principal = principal
        .as_ref()
        .ok_or_else(|| Box::new(Redirect::temporary("/auth/login").into_response()))?;
    match principal.instance_role {
        Some(InstanceRole::Admin) => Ok(principal),
        _ => Err(Box::new(Redirect::temporary("/").into_response())),
    }
}

fn require_moderator_api(
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

fn require_admin_api(
    principal: &Option<axum::Extension<Principal>>,
) -> Result<&Principal, ApiError> {
    let principal = principal
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?;
    match principal.instance_role {
        Some(InstanceRole::Admin) => Ok(principal),
        _ => Err(ApiError(NoombatError::Forbidden)),
    }
}

fn nav_username(principal: &Option<axum::Extension<Principal>>) -> String {
    principal
        .as_ref()
        .and_then(|p| p.username.clone())
        .unwrap_or_default()
}

// ..... REDIRECT .....

async fn admin_redirect() -> Redirect {
    Redirect::temporary("/admin/moderation")
}

// ..... MODERATION QUEUE .....

/// A unified report entry (AP or chat) for the moderation queue template.
struct UnifiedReportEntry {
    id: String,
    source: String, // "ap" or "chat"
    reporter_name: String,
    target_description: String,
    reason: String,
    comment: String,
    created_at: String,
}

/// Row returned by the AP reports JOIN query.
#[derive(sqlx::FromRow)]
struct ApReportRow {
    id: Uuid,
    reporter_name: String,
    target_name: Option<String>,
    target_post_id: Option<Uuid>,
    reason: String,
    comment: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Row returned by the chat reports JOIN query.
#[derive(sqlx::FromRow)]
struct ChatReportRow {
    id: Uuid,
    reporter_name: String,
    target_addr: String,
    reason: String,
    comment: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_moderation.html")]
struct ModerationPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    reports: Vec<UnifiedReportEntry>,
}

async fn moderation_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    if let Err(r) = require_moderator(&principal) {
        return *r;
    }
    let uname = nav_username(&principal);

    // Fetch open AP reports with reporter and target names via JOIN.
    let ap_rows: Vec<ApReportRow> = sqlx::query_as(
        r#"SELECT r.id,
                      COALESCE(reporter.display_name, reporter.username) AS reporter_name,
                      COALESCE(target.display_name, target.username) AS target_name,
                      r.target_post_id,
                      r.reason,
                      r.comment,
                      r.created_at
               FROM reports r
               JOIN actors reporter ON reporter.id = r.reporter_id
               LEFT JOIN actors target ON target.id = r.target_actor_id
               WHERE r.status = 'open'
               ORDER BY r.created_at ASC LIMIT 200"#,
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Fetch open chat reports with reporter name via JOIN.
    let chat_rows: Vec<ChatReportRow> = sqlx::query_as(
        r#"SELECT cr.id,
                      COALESCE(reporter.display_name, reporter.username) AS reporter_name,
                      cr.target_addr,
                      cr.reason,
                      cr.comment,
                      cr.created_at
               FROM chat_reports cr
               JOIN actors reporter ON reporter.id = cr.reporter_id
               WHERE cr.status = 'open'
               ORDER BY cr.created_at ASC LIMIT 200"#,
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Build unified entries with raw timestamps for correct sorting.
    struct RawEntry {
        entry: UnifiedReportEntry,
        ts: chrono::DateTime<chrono::Utc>,
    }

    let mut raw: Vec<RawEntry> = Vec::new();

    for row in ap_rows {
        let target_description = match (row.target_name, row.target_post_id) {
            (Some(name), _) => format!("Actor: {name}"),
            (None, Some(post_id)) => format!("Post: {post_id}"),
            _ => "unknown target".into(),
        };
        raw.push(RawEntry {
            ts: row.created_at,
            entry: UnifiedReportEntry {
                id: row.id.to_string(),
                source: "ap".into(),
                reporter_name: row.reporter_name,
                target_description,
                reason: row.reason,
                comment: row.comment.unwrap_or_default(),
                created_at: row.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            },
        });
    }

    for row in chat_rows {
        raw.push(RawEntry {
            ts: row.created_at,
            entry: UnifiedReportEntry {
                id: row.id.to_string(),
                source: "chat".into(),
                reporter_name: row.reporter_name,
                target_description: format!("Chat: {}", row.target_addr),
                reason: row.reason,
                comment: row.comment.unwrap_or_default(),
                created_at: row.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            },
        });
    }

    // Sort by raw timestamp, not the formatted string.
    raw.sort_by_key(|r| r.ts);
    let reports: Vec<UnifiedReportEntry> = raw.into_iter().map(|r| r.entry).collect();

    ModerationPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        reports,
    }
    .into_response()
}

// ..... USER MANAGEMENT .....

struct UserEntry {
    id: String,
    username: String,
    display_name: String,
    instance_role: String,
    actor_status: String,
    created_at: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_users.html")]
struct UsersPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    users: Vec<UserEntry>,
    filter_role: String,
    filter_status: String,
}

#[derive(Deserialize)]
struct UsersQuery {
    role: Option<String>,
    status: Option<String>,
}

/// Row returned by the local actors query.
#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    display_name: String,
    instance_role: String,
    actor_status: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn users_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    principal: Option<axum::Extension<Principal>>,
    axum::extract::Query(params): axum::extract::Query<UsersQuery>,
) -> Response {
    if let Err(r) = require_moderator(&principal) {
        return *r;
    }
    let uname = nav_username(&principal);

    let filter_role = params.role.unwrap_or_default();
    let filter_status = params.status.unwrap_or_default();

    // Build a dynamic query with optional filters.
    let mut query = String::from(
        "SELECT id, username, COALESCE(display_name, username) AS display_name, \
         instance_role, actor_status, created_at \
         FROM actors WHERE is_local = TRUE",
    );
    let mut binds: Vec<String> = Vec::new();
    if !filter_role.is_empty() {
        binds.push(filter_role.clone());
        query.push_str(&format!(" AND instance_role = ${}", binds.len()));
    }
    if !filter_status.is_empty() {
        binds.push(filter_status.clone());
        query.push_str(&format!(" AND actor_status = ${}", binds.len()));
    }
    query.push_str(" ORDER BY created_at DESC LIMIT 200");

    // SAFETY: the dynamic fragments are hardcoded column names and
    // bind-parameter placeholders, not user input.
    let mut q = sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(query));
    for b in &binds {
        q = q.bind(b);
    }

    let rows = q.fetch_all(&state.pool).await.unwrap_or_default();

    let users = rows
        .into_iter()
        .map(|row| UserEntry {
            id: row.id.to_string(),
            username: row.username,
            display_name: row.display_name,
            instance_role: row.instance_role,
            actor_status: row.actor_status,
            created_at: row.created_at.format("%Y-%m-%d").to_string(),
        })
        .collect();

    UsersPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        users,
        filter_role,
        filter_status,
    }
    .into_response()
}

// ..... DOMAIN MANAGEMENT .....

struct DomainEntry {
    id: String,
    domain: String,
    restriction: String,
    reason: String,
    created_by_name: String,
    created_at: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_domains.html")]
struct DomainsPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    domains: Vec<DomainEntry>,
}

/// Row returned by the domain restrictions JOIN query.
#[derive(sqlx::FromRow)]
struct DomainRestrictionRow {
    id: Uuid,
    domain: String,
    restriction: String,
    reason: Option<String>,
    created_by_name: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn domains_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    if let Err(r) = require_moderator(&principal) {
        return *r;
    }
    let uname = nav_username(&principal);

    let rows: Vec<DomainRestrictionRow> = sqlx::query_as(
        r#"SELECT dr.id, dr.domain, dr.restriction, dr.reason,
                      COALESCE(a.display_name, a.username) AS created_by_name,
                      dr.created_at
               FROM domain_restrictions dr
               LEFT JOIN actors a ON a.id = dr.created_by
               ORDER BY dr.domain ASC"#,
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let domains = rows
        .into_iter()
        .map(|row| DomainEntry {
            id: row.id.to_string(),
            domain: row.domain,
            restriction: row.restriction,
            reason: row.reason.unwrap_or_default(),
            created_by_name: row.created_by_name.unwrap_or_default(),
            created_at: row.created_at.format("%Y-%m-%d").to_string(),
        })
        .collect();

    DomainsPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        domains,
    }
    .into_response()
}

// ..... DOMAIN API .....

#[derive(Deserialize)]
struct AddDomainRequest {
    domain: String,
    restriction: String,
    reason: Option<String>,
}

async fn add_domain_restriction(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Form(body): Form<AddDomainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator_api(&principal)?;
    let moderator_id = moderator.actor_id();

    sqlx::query(
        "INSERT INTO domain_restrictions (domain, restriction, reason, created_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (domain) DO UPDATE SET restriction = $2, reason = $3",
    )
    .bind(&body.domain)
    .bind(&body.restriction)
    .bind(&body.reason)
    .bind(moderator_id)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    info!(
        domain = %body.domain,
        restriction = %body.restriction,
        moderator = ?moderator.username,
        "domain restriction added"
    );

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "ok": true }))))
}

async fn remove_domain_restriction(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator_api(&principal)?;

    sqlx::query("DELETE FROM domain_restrictions WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(NoombatError::from)?;

    info!(
        id = %id,
        moderator = ?moderator.username,
        "domain restriction removed"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ..... INSTANCE SETTINGS .....

#[derive(Template, WebTemplate)]
#[template(path = "admin_settings.html")]
struct SettingsAdminPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    registration_mode: String,
    default_job_approval: bool,
    analytics_retention_days: i32,
    announcements: Vec<AnnouncementEntry>,
}

struct AnnouncementEntry {
    id: String,
    content: String,
    active: bool,
    created_at: String,
}

async fn settings_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    if let Err(r) = require_admin(&principal) {
        return *r;
    }
    let uname = nav_username(&principal);

    let settings: Option<(String, bool, i32)> = sqlx::query_as(
        "SELECT registration_mode, default_job_approval, analytics_retention_days \
         FROM instance_settings LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let (registration_mode, default_job_approval, analytics_retention_days) =
        settings.unwrap_or(("open".into(), true, 90));

    let announcement_rows: Vec<(Uuid, String, bool, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, content, active, created_at FROM announcements ORDER BY created_at DESC LIMIT 50",
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

    let announcements = announcement_rows
        .into_iter()
        .map(|(id, content, active, created_at)| AnnouncementEntry {
            id: id.to_string(),
            content,
            active,
            created_at: created_at.format("%Y-%m-%d").to_string(),
        })
        .collect();

    SettingsAdminPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        registration_mode,
        default_job_approval,
        analytics_retention_days,
        announcements,
    }
    .into_response()
}

#[derive(Deserialize)]
struct UpdateSettingsRequest {
    registration_mode: Option<String>,
    default_job_approval: Option<bool>,
    analytics_retention_days: Option<i32>,
}

async fn update_settings(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Form(body): Form<UpdateSettingsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_api(&principal)?;

    sqlx::query(
        r#"UPDATE instance_settings SET
               registration_mode = COALESCE($1, registration_mode),
               default_job_approval = COALESCE($2, default_job_approval),
               analytics_retention_days = COALESCE($3, analytics_retention_days),
               updated_at = now()"#,
    )
    .bind(&body.registration_mode)
    .bind(body.default_job_approval)
    .bind(body.analytics_retention_days)
    .execute(&state.pool)
    .await
    .map_err(NoombatError::from)?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ..... ANNOUNCEMENTS .....

#[derive(Deserialize)]
struct CreateAnnouncementRequest {
    content: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn create_announcement(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Form(body): Form<CreateAnnouncementRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let admin = require_admin_api(&principal)?;
    let admin_id = admin.actor_id();

    sqlx::query("INSERT INTO announcements (content, created_by, expires_at) VALUES ($1, $2, $3)")
        .bind(&body.content)
        .bind(admin_id)
        .bind(body.expires_at)
        .execute(&state.pool)
        .await
        .map_err(NoombatError::from)?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "ok": true }))))
}

async fn delete_announcement(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_api(&principal)?;

    sqlx::query("DELETE FROM announcements WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(NoombatError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

// ..... FEDERATION HEALTH .....

struct FailedDomainEntry {
    domain: String,
    failed_count: i64,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_federation.html")]
struct FederationPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    queue_depth: i64,
    failed_domains: Vec<FailedDomainEntry>,
    tombstoned_count: i64,
}

async fn federation_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    if let Err(r) = require_admin(&principal) {
        return *r;
    }
    let uname = nav_username(&principal);

    let queue_depth: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM delivery_queue WHERE attempts < 10")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let failed_rows: Vec<(String, i64)> = sqlx::query_as(
        r#"SELECT
               split_part(target_inbox, '/', 3) AS domain,
               COUNT(*) AS cnt
           FROM delivery_queue
           WHERE attempts >= 3
           GROUP BY domain
           ORDER BY cnt DESC
           LIMIT 50"#,
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let failed_domains = failed_rows
        .into_iter()
        .map(|(domain, failed_count)| FailedDomainEntry {
            domain,
            failed_count,
        })
        .collect();

    let tombstoned_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tombstoned_actors")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

    FederationPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        queue_depth,
        failed_domains,
        tombstoned_count,
    }
    .into_response()
}

/// Body of `POST /api/v1/admin/users/{username}/role`.
#[derive(Debug, Deserialize)]
struct RoleChange {
    role: InstanceRole,
}

/// Promote or demote a local actor.
///
/// Two refusals, both about not locking the instance out of itself: an
/// administrator may not change their own role, and the last
/// administrator may not be demoted by anyone.
async fn set_user_role(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Path(username): Path<String>,
    Form(body): Form<RoleChange>,
) -> Result<impl IntoResponse, ApiError> {
    let admin = require_admin_api(&principal)?;

    let target = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    if admin.actor_id() == Some(target.id) {
        return Err(ApiError(NoombatError::BadRequest(
            "an administrator cannot change their own role; ask another administrator".into(),
        )));
    }

    // Counted before the write, and only when the write would remove an
    // administrator. A demotion that leaves none returns the instance to
    // the state this route exists to escape.
    if target.instance_role == InstanceRole::Admin
        && body.role != InstanceRole::Admin
        && noombat_identity::repo::count_admins(&state.pool).await? <= 1
    {
        return Err(ApiError(NoombatError::BadRequest(
            "refusing to demote the last administrator; promote another one first".into(),
        )));
    }

    noombat_identity::repo::set_instance_role(&state.pool, target.id, body.role).await?;

    info!(
        actor = %target.username,
        role = ?body.role,
        by = ?admin.username,
        "instance role changed"
    );

    Ok(StatusCode::NO_CONTENT)
}
