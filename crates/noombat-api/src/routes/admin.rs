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
use crate::middleware::Viewer;
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

fn require_moderator(viewer: &Option<axum::Extension<Viewer>>) -> Result<&Viewer, Box<Response>> {
    let viewer = viewer
        .as_ref()
        .ok_or_else(|| Box::new(Redirect::temporary("/auth/login").into_response()))?;
    if viewer.may_moderate() {
        Ok(viewer)
    } else {
        Err(Box::new(Redirect::temporary("/").into_response()))
    }
}

fn require_admin(viewer: &Option<axum::Extension<Viewer>>) -> Result<&Viewer, Box<Response>> {
    let viewer = viewer
        .as_ref()
        .ok_or_else(|| Box::new(Redirect::temporary("/auth/login").into_response()))?;
    if viewer.may_administer() {
        Ok(viewer)
    } else {
        Err(Box::new(Redirect::temporary("/").into_response()))
    }
}

fn require_moderator_api(viewer: &Option<axum::Extension<Viewer>>) -> Result<&Viewer, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    if viewer.may_moderate() {
        Ok(viewer)
    } else {
        Err(ApiError(NoombatError::Forbidden))
    }
}

fn require_admin_api(viewer: &Option<axum::Extension<Viewer>>) -> Result<&Viewer, ApiError> {
    let viewer = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    if viewer.may_administer() {
        Ok(viewer)
    } else {
        Err(ApiError(NoombatError::Forbidden))
    }
}

fn nav_username(viewer: &Option<axum::Extension<Viewer>>) -> String {
    viewer
        .as_ref()
        .map(|p| p.username.clone())
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

/// Row returned by the moderation queue query.
///
/// One row shape for every kind of report, because there is one table.
/// Which target column is set is what the report is about.
#[derive(sqlx::FromRow)]
struct ReportRow {
    id: Uuid,
    reporter_name: String,
    target_name: Option<String>,
    target_post_id: Option<Uuid>,
    target_chat_addr: Option<String>,
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
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    if let Err(r) = require_moderator(&viewer) {
        return *r;
    }
    let uname = nav_username(&viewer);

    // One query, because there is one table. A second spine would cost a
    // second read and a merge in Rust even where nothing goes wrong, and
    // the ordering would have to be redone over the union.
    let rows: Vec<ReportRow> = match sqlx::query_as(
        r#"SELECT r.id,
                  COALESCE(reporter.display_name, reporter.username) AS reporter_name,
                  COALESCE(target.display_name, target.username) AS target_name,
                  r.target_post_id,
                  r.target_chat_addr,
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
    {
        Ok(rows) => rows,
        Err(e) => {
            // An empty queue and a queue that failed to load look identical
            // on the page, and the difference is whether anybody is coming.
            tracing::error!(error = %e, "moderation queue could not be read");
            Vec::new()
        }
    };

    let reports: Vec<UnifiedReportEntry> = rows
        .into_iter()
        .map(|row| {
            // The chat address wins where it is set, because it is the only
            // one of the three that says which surface the report came from.
            let (source, target_description) =
                match (row.target_chat_addr, row.target_name, row.target_post_id) {
                    (Some(addr), _, _) => ("chat", format!("Chat: {addr}")),
                    (None, Some(name), _) => ("ap", format!("Actor: {name}")),
                    (None, None, Some(post_id)) => ("ap", format!("Post: {post_id}")),
                    _ => ("ap", "unknown target".to_owned()),
                };
            UnifiedReportEntry {
                id: row.id.to_string(),
                source: source.to_owned(),
                reporter_name: row.reporter_name,
                target_description,
                reason: row.reason,
                comment: row.comment.unwrap_or_default(),
                created_at: row.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            }
        })
        .collect();

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
    viewer: Option<axum::Extension<Viewer>>,
    axum::extract::Query(params): axum::extract::Query<UsersQuery>,
) -> Response {
    if let Err(r) = require_moderator(&viewer) {
        return *r;
    }
    let uname = nav_username(&viewer);

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
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    if let Err(r) = require_moderator(&viewer) {
        return *r;
    }
    let uname = nav_username(&viewer);

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
    viewer: Option<axum::Extension<Viewer>>,
    Form(body): Form<AddDomainRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator_api(&viewer)?;
    let moderator_id = moderator.actor_id;

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
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let moderator = require_moderator_api(&viewer)?;

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

/// The settings row the admin page renders.
///
/// A named type rather than an eight-column tuple: the columns are all
/// `bool` or `i32` in runs, so a tuple lets two of them swap places
/// silently. `Default` supplies the schema defaults for an instance whose
/// settings row has not been created yet.
#[derive(sqlx::FromRow)]
struct InstanceSettingsRow {
    registration_mode: String,
    default_job_approval: bool,
    analytics_retention_days: i32,
    index_remote_posts: bool,
    organization_creation_enabled: bool,
    organization_rate_limit_count: i32,
    organization_rate_limit_amount: i32,
    organization_rate_limit_unit: String,
    organization_concurrent_cap: i32,
    organization_period_cap_count: i32,
    organization_period_cap_amount: i32,
    organization_period_cap_unit: String,
}

impl Default for InstanceSettingsRow {
    fn default() -> Self {
        Self {
            registration_mode: "open".to_owned(),
            default_job_approval: true,
            analytics_retention_days: 90,
            index_remote_posts: false,
            organization_creation_enabled: true,
            organization_rate_limit_count: 1,
            organization_rate_limit_amount: 7,
            organization_rate_limit_unit: "days".to_owned(),
            organization_concurrent_cap: 5,
            organization_period_cap_count: 10,
            organization_period_cap_amount: 1,
            organization_period_cap_unit: "years".to_owned(),
        }
    }
}

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
    index_remote_posts: bool,
    organization_creation_enabled: bool,
    organization_rate_limit_count: i32,
    organization_rate_limit_amount: i32,
    organization_rate_limit_unit: String,
    organization_concurrent_cap: i32,
    organization_period_cap_count: i32,
    organization_period_cap_amount: i32,
    organization_period_cap_unit: String,
    /// The unit dropdown's options: the stored value and its message key.
    ///
    /// Rendered from one list so the two selects cannot drift, and so the
    /// set the form offers is the set the CHECK constraint accepts.
    period_units: Vec<(&'static str, &'static str)>,
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
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    if let Err(r) = require_admin(&viewer) {
        return *r;
    }
    let uname = nav_username(&viewer);

    let settings: InstanceSettingsRow = sqlx::query_as(
        "SELECT registration_mode, default_job_approval, analytics_retention_days, \
                index_remote_posts, organization_creation_enabled, \
                organization_rate_limit_count, organization_rate_limit_amount, \
                organization_rate_limit_unit, organization_concurrent_cap, \
                organization_period_cap_count, organization_period_cap_amount, \
                organization_period_cap_unit \
         FROM instance_settings LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();

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
        registration_mode: settings.registration_mode,
        default_job_approval: settings.default_job_approval,
        analytics_retention_days: settings.analytics_retention_days,
        index_remote_posts: settings.index_remote_posts,
        organization_creation_enabled: settings.organization_creation_enabled,
        organization_rate_limit_count: settings.organization_rate_limit_count,
        organization_rate_limit_amount: settings.organization_rate_limit_amount,
        organization_rate_limit_unit: settings.organization_rate_limit_unit,
        organization_concurrent_cap: settings.organization_concurrent_cap,
        organization_period_cap_count: settings.organization_period_cap_count,
        organization_period_cap_amount: settings.organization_period_cap_amount,
        organization_period_cap_unit: settings.organization_period_cap_unit,
        period_units: vec![
            ("hours", "admin_settings_unit_hours"),
            ("days", "admin_settings_unit_days"),
            ("weeks", "admin_settings_unit_weeks"),
            ("months", "admin_settings_unit_months"),
            ("years", "admin_settings_unit_years"),
        ],
        announcements,
    }
    .into_response()
}

#[derive(Deserialize)]
struct UpdateSettingsRequest {
    registration_mode: Option<String>,
    default_job_approval: Option<bool>,
    analytics_retention_days: Option<i32>,
    /// Whether posts from other instances enter search and trending.
    ///
    /// `Option` and `COALESCE`, like its neighbours, so a caller
    /// changing one setting does not clear the rest. An HTML checkbox
    /// submits nothing when unchecked, so the form posts an explicit
    /// value rather than relying on presence.
    index_remote_posts: Option<bool>,
    /// Whether a signed-in account may enrol an Organization actor.
    ///
    /// Independent of `registration_mode`: an instance can be closed to
    /// new members while its members still enrol organisations, and open
    /// to members while organisation creation is paused.
    organization_creation_enabled: Option<bool>,
    /// Per-owner ceilings. A count of `0` disables the one it names, and
    /// each time-based ceiling carries its own window.
    organization_rate_limit_count: Option<i32>,
    organization_rate_limit_amount: Option<i32>,
    organization_rate_limit_unit: Option<String>,
    organization_concurrent_cap: Option<i32>,
    organization_period_cap_count: Option<i32>,
    organization_period_cap_amount: Option<i32>,
    organization_period_cap_unit: Option<String>,
}

async fn update_settings(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Form(body): Form<UpdateSettingsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_api(&viewer)?;

    // Checked here, not left to the CHECK constraints. A constraint
    // violation reaches the caller through the catch-all arm of the error
    // mapping as a 500 with no detail, which tells an administrator
    // nothing about which field they got wrong.
    for (name, value) in [
        (
            "organization_rate_limit_count",
            body.organization_rate_limit_count,
        ),
        (
            "organization_concurrent_cap",
            body.organization_concurrent_cap,
        ),
        (
            "organization_period_cap_count",
            body.organization_period_cap_count,
        ),
    ] {
        if let Some(value) = value
            && value < 0
        {
            return Err(ApiError(NoombatError::BadRequest(format!(
                "{name} cannot be negative; 0 disables that ceiling"
            ))));
        }
    }
    // A window of zero is not "no limit", it is a window nothing fits in:
    // `now() - make_interval(days => 0)` is now, so the count inside it is
    // always zero and the ceiling silently stops applying. Disabling a
    // ceiling is what its count is for.
    for (name, value) in [
        (
            "organization_rate_limit_amount",
            body.organization_rate_limit_amount,
        ),
        (
            "organization_period_cap_amount",
            body.organization_period_cap_amount,
        ),
    ] {
        if let Some(value) = value
            && value < 1
        {
            return Err(ApiError(NoombatError::BadRequest(format!(
                "{name} must be at least 1; set the matching count to 0 to remove the limit"
            ))));
        }
    }
    // Closed here as well as by the CHECK constraint, so a bad unit is a
    // 400 naming the field rather than a 500 from the catch-all arm.
    const UNITS: [&str; 5] = ["hours", "days", "weeks", "months", "years"];
    for (name, value) in [
        (
            "organization_rate_limit_unit",
            &body.organization_rate_limit_unit,
        ),
        (
            "organization_period_cap_unit",
            &body.organization_period_cap_unit,
        ),
    ] {
        if let Some(value) = value
            && !UNITS.contains(&value.as_str())
        {
            return Err(ApiError(NoombatError::BadRequest(format!(
                "{name} must be one of {}",
                UNITS.join(", ")
            ))));
        }
    }

    sqlx::query(
        r#"UPDATE instance_settings SET
               registration_mode = COALESCE($1, registration_mode),
               default_job_approval = COALESCE($2, default_job_approval),
               analytics_retention_days = COALESCE($3, analytics_retention_days),
               index_remote_posts = COALESCE($4, index_remote_posts),
               organization_creation_enabled = COALESCE($5, organization_creation_enabled),
               organization_rate_limit_count = COALESCE($6, organization_rate_limit_count),
               organization_rate_limit_amount = COALESCE($7, organization_rate_limit_amount),
               organization_rate_limit_unit = COALESCE($8, organization_rate_limit_unit),
               organization_concurrent_cap = COALESCE($9, organization_concurrent_cap),
               organization_period_cap_count = COALESCE($10, organization_period_cap_count),
               organization_period_cap_amount = COALESCE($11, organization_period_cap_amount),
               organization_period_cap_unit = COALESCE($12, organization_period_cap_unit),
               updated_at = now()"#,
    )
    .bind(&body.registration_mode)
    .bind(body.default_job_approval)
    .bind(body.analytics_retention_days)
    .bind(body.index_remote_posts)
    .bind(body.organization_creation_enabled)
    .bind(body.organization_rate_limit_count)
    .bind(body.organization_rate_limit_amount)
    .bind(&body.organization_rate_limit_unit)
    .bind(body.organization_concurrent_cap)
    .bind(body.organization_period_cap_count)
    .bind(body.organization_period_cap_amount)
    .bind(&body.organization_period_cap_unit)
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
    viewer: Option<axum::Extension<Viewer>>,
    Form(body): Form<CreateAnnouncementRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let admin = require_admin_api(&viewer)?;
    let admin_id = admin.actor_id;

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
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin_api(&viewer)?;

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
    /// Chatmail deletions still owed, and those given up on. Erasure is
    /// the one operation whose failure nobody would otherwise notice:
    /// the account is gone and the mail is not.
    chatmail_pending: Vec<crate::chatmail_ops::PendingOperation>,
    chatmail_failed: Vec<crate::chatmail_ops::FailedOperation>,
    /// Posts admitted on a relay's word alone, and so held out of
    /// trending. Counted here because an exclusion nobody can see is
    /// indistinguishable from there being nothing to exclude, and an
    /// administrator choosing `trust-relay` is owed the figure it
    /// produces.
    relayed_unverified_posts: i64,
    /// Search documents that should have gone and have not. The figure
    /// that says whether an erasure actually finished.
    stuck_search_removals: i64,
    search_failures: Vec<crate::search_ops::FailedOperation>,
}

async fn federation_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    if let Err(r) = require_admin(&viewer) {
        return *r;
    }
    let uname = nav_username(&viewer);

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

    let chatmail_pending = crate::chatmail_ops::pending(&state.pool)
        .await
        .unwrap_or_default();
    let chatmail_failed = crate::chatmail_ops::failures(&state.pool)
        .await
        .unwrap_or_default();

    let relayed_unverified_posts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM posts WHERE relayed_unverified")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let stuck_search_removals = crate::search_ops::stuck_removals(&state.pool)
        .await
        .unwrap_or(0);
    let search_failures = crate::search_ops::failures(&state.pool)
        .await
        .unwrap_or_default();

    FederationPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        queue_depth,
        failed_domains,
        tombstoned_count,
        chatmail_pending,
        chatmail_failed,
        relayed_unverified_posts,
        stuck_search_removals,
        search_failures,
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
    viewer: Option<axum::Extension<Viewer>>,
    Path(username): Path<String>,
    Form(body): Form<RoleChange>,
) -> Result<impl IntoResponse, ApiError> {
    let admin = require_admin_api(&viewer)?;

    let target = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    if admin.actor_id == target.id {
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
