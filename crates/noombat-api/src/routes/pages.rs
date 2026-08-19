// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Server-rendered HTML pages.
//!
//! Serves Askama templates for authentication, settings, profile
//! editing, and the chat interface. Distinct from the JSON API
//! endpoints (which handle form submissions and return JSON).

use askama::Template;
use askama_web::WebTemplate;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};

use crate::i18n::I18n;
use crate::middleware::Principal;
use crate::state::AppState;
use crate::theme::Theme;

// ..... Helper .....

/// Extract the authenticated username or redirect to login.
#[allow(clippy::result_large_err)]
fn require_auth(principal: &Option<axum::Extension<Principal>>) -> Result<String, Response> {
    principal
        .as_ref()
        .and_then(|p| p.username.clone())
        .ok_or_else(|| Redirect::temporary("/auth/login").into_response())
}

fn nav_username(principal: &Option<axum::Extension<Principal>>) -> String {
    principal
        .as_ref()
        .and_then(|p| p.username.clone())
        .unwrap_or_default()
}

fn actor_uuid(principal: &Option<axum::Extension<Principal>>) -> Option<uuid::Uuid> {
    principal.as_ref().and_then(|p| p.actor_id())
}

// ..... Privacy settings write path .....

/// Body of `POST /settings/privacy`.
///
/// Every boolean carries `serde(default)` because an unchecked HTML
/// checkbox submits nothing at all. Without it, clearing a toggle would
/// be a deserialisation failure rather than a `false`, which is the
/// difference between a working form and one that only ever turns
/// things on.
#[derive(Debug, serde::Deserialize)]
pub struct PrivacySettingsForm {
    #[serde(default)]
    discoverable: bool,
    #[serde(default)]
    indexable: bool,
    #[serde(default)]
    federate_profile: bool,
    #[serde(default)]
    require_follow_approval: bool,
    #[serde(default)]
    show_followers_count: bool,
    #[serde(default)]
    chatmail_visible: bool,
    #[serde(default)]
    cv_download: noombat_core::privacy::CvDownload,
    /// Posted by the form and deliberately unused.
    ///
    /// `default_visibility` is not a field on `ActorPrivacy` and has
    /// nowhere to be stored yet. Accepted so the submission does not
    /// fail wholesale on an unknown field, and dropped rather than
    /// silently half-applied.
    #[serde(default)]
    #[allow(dead_code)]
    default_visibility: Option<String>,
}

/// Persist the profile privacy settings of the signed-in actor.
///
/// There is no username in the path on purpose: the target is whoever
/// the session says it is, so there is no other user's settings to
/// authorise against and no confused-deputy shape to get wrong.
async fn save_privacy_settings(
    State(state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    axum::Form(form): axum::Form<PrivacySettingsForm>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "sign in to change privacy settings",
        )
            .into_response();
    };

    let privacy = noombat_core::privacy::ActorPrivacy {
        discoverable: form.discoverable,
        indexable: form.indexable,
        require_follow_approval: form.require_follow_approval,
        federate_profile: form.federate_profile,
        chatmail_visible: form.chatmail_visible,
        show_followers_count: form.show_followers_count,
        cv_download: form.cv_download,
    };

    if let Err(e) =
        noombat_identity::profile::update_actor_privacy(&state.pool, actor_id, &privacy).await
    {
        tracing::error!(%actor_id, "failed to save privacy settings: {e}");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "could not save privacy settings",
        )
            .into_response();
    }

    // Bring the search index into line with the setting that was just
    // saved. Without this the control is cosmetic in the direction that
    // matters: `index_profile` honours `discoverable` by *not* indexing,
    // which leaves an already-indexed profile in place forever.
    match noombat_identity::repo::find_by_id(&state.pool, actor_id).await {
        Ok(actor) if privacy.discoverable => {
            crate::search_sync::reindex_profile_from_db(&state.pool, &state.search, &actor).await;
        }
        Ok(_) => {
            crate::search_sync::remove_from_index(&state.search, "profiles", &actor_id.to_string());
        }
        Err(e) => {
            // The settings are saved; only the index is now stale.
            tracing::warn!(%actor_id, "saved privacy settings but could not resync search: {e}");
        }
    }

    axum::http::StatusCode::NO_CONTENT.into_response()
}

// ..... Templates .....

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginPage {
    i18n: I18n,
    theme: Theme,
    error: Option<String>,
    orcid_enabled: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "register.html")]
struct RegisterPage {
    i18n: I18n,
    theme: Theme,
    error: Option<String>,
    open_registrations: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "totp.html")]
struct TotpPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    totp_enabled: bool,
    qr_data_uri: Option<String>,
    secret_base32: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "chat.html")]
struct ChatPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    ws_url: String,
    chatmail_addr: String,
    username: String,
    /// True when the actor's chat has been suspended by a moderator
    /// and requires reprovisioning.
    chat_suspended: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "upgrade.html")]
struct UpgradePage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "chat_credentials.html")]
struct ChatCredentialsPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    chatmail_addr: String,
    chatmail_domain: String,
    suspended: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "settings.html")]
struct SettingsPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_profile.html")]
struct EditProfilePage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    display_name: String,
    headline: String,
    location: String,
    summary_md: String,
    avatar_url: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_experience.html")]
struct EditExperiencePage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    title: String,
    company: String,
    start_date: String,
    end_date: String,
    description_md: String,
    visibility: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_education.html")]
struct EditEducationPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    institution: String,
    degree: String,
    field_of_study: String,
    start_date: String,
    end_date: String,
    visibility: String,
}

// Skill entry for the template.
struct SkillEntry {
    id: String,
    name: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_skills.html")]
struct EditSkillsPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    skills: Vec<SkillEntry>,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_publication.html")]
struct EditPublicationPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
}

// Verified link entry for the template.
struct LinkEntry {
    id: String,
    url: String,
    verified_at: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_links.html")]
struct EditLinksPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    domain: String,
    links: Vec<LinkEntry>,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_job.html")]
struct EditJobPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "compose.html")]
struct ComposePage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
}

// Search result entry for the template.
struct SearchResultEntry {
    url: String,
    title: String,
    subtitle: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "search.html")]
struct SearchPage {
    i18n: I18n,
    theme: Theme,
    query: String,
    index: String,
    results: Vec<SearchResultEntry>,
}

// Follow request entry for the template.
struct FollowRequestEntry {
    id: String,
    display_name: String,
    profile_url: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "follow_requests.html")]
struct FollowRequestsPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    requests: Vec<FollowRequestEntry>,
}

// Block/mute entry for the template.
struct BlockEntry {
    id: String,
    target_name: String,
    target_ap_id_encoded: String,
}
struct MuteEntry {
    id: String,
    target_name: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "blocked_muted.html")]
struct BlockedMutedPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    blocked: Vec<BlockEntry>,
    muted: Vec<MuteEntry>,
}

// Section visibility entry for the privacy page.
struct SectionVisibilityRow {
    section_id: String,
    table_name: String,
    label: String,
    visibility: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_privacy.html")]
struct PrivacyPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    discoverable: bool,
    indexable: bool,
    federate_profile: bool,
    require_follow_approval: bool,
    show_followers_count: bool,
    chatmail_visible: bool,
    cv_download: String,
    default_visibility: String,
    section_rows: Vec<SectionVisibilityRow>,
}

// Alias entry for the template.
struct AliasEntry {
    id: String,
    alias: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "migrate.html")]
struct MigratePage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    username: String,
    aliases: Vec<AliasEntry>,
}

// ..... Routes .....

pub fn router() -> Router<AppState> {
    Router::new()
        // Auth pages (unauthenticated).
        .route("/auth/login", get(login_page))
        .route("/auth/register", get(register_page))
        .route("/auth/totp", get(totp_page))
        .route("/auth/upgrade", get(upgrade_page))
        // Chat.
        .route("/chat", get(chat_page))
        // Settings hub.
        .route("/settings", get(settings_page))
        .route("/settings/profile", get(edit_profile_page))
        .route("/settings/experience", get(edit_experience_page))
        .route("/settings/education", get(edit_education_page))
        .route("/settings/skills", get(edit_skills_page))
        .route("/settings/publications", get(edit_publication_page))
        .route("/settings/links", get(edit_links_page))
        .route("/settings/jobs/new", get(edit_job_page))
        .route(
            "/settings/privacy",
            get(privacy_page).post(save_privacy_settings),
        )
        .route("/settings/privacy/preview", get(privacy_preview_partial))
        .route("/settings/account", get(account_settings_page))
        .route("/settings/blocked", get(blocked_muted_page))
        .route("/settings/follow-requests", get(follow_requests_page))
        .route("/settings/chat", get(chat_credentials_page))
        .route("/settings/migrate", get(migrate_page))
        // Deliberately not behind require_auth: the theme is a property
        // of the browser, not of an account.
        .route("/settings/theme", post(set_theme))
        // Compose.
        .route("/compose", get(compose_page))
        // HTML search results.
        .route("/search/html", get(search_html_page))
}

// ..... Handlers .....

async fn login_page(State(state): State<AppState>, i18n: I18n, theme: Theme) -> impl IntoResponse {
    LoginPage {
        i18n,
        theme,
        error: None,
        orcid_enabled: state.orcid_config.is_some(),
    }
}

async fn register_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
) -> impl IntoResponse {
    RegisterPage {
        i18n,
        theme,
        error: None,
        open_registrations: state.open_registrations,
    }
}

async fn totp_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> impl IntoResponse {
    let mut totp_enabled = false;
    let mut qr_data_uri = None;
    let mut secret_base32 = String::new();

    if let Some(actor_id) = actor_uuid(&principal) {
        totp_enabled = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM totp_secrets WHERE actor_id = $1 AND verified = TRUE)",
        )
        .bind(actor_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if !totp_enabled {
            let uname = nav_username(&principal);
            if let Ok(enrolment) =
                noombat_identity::totp::enrol_totp(&state.pool, actor_id, &uname, &state.domain)
                    .await
            {
                qr_data_uri =
                    noombat_identity::totp::otpauth_to_qr_data_uri(&enrolment.otpauth_uri).ok();
                secret_base32 = enrolment.secret_base32;
            }
        }
    }

    TotpPage {
        i18n,
        theme,
        nav_username: nav_username(&principal),
        totp_enabled,
        qr_data_uri,
        secret_base32,
    }
}

async fn chat_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let (chatmail_addr, chat_suspended): (Option<String>, bool) =
        sqlx::query_as::<_, (Option<String>, bool)>(
            "SELECT chatmail_addr, chat_requires_reprovisioning FROM actors WHERE id = $1",
        )
        .bind(actor_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or((None, false));
    let chatmail_addr = chatmail_addr.unwrap_or_default();
    // The scheme must match the one pinned in the Content-Security-
    // Policy `connect-src` directive, and must be plain `ws` for a
    // development instance served over HTTP.
    let ws_url = format!(
        "{}/api/v1/chat/ws",
        crate::middleware::websocket_origin(&state.domain, state.public_port)
    );
    let username = nav_username(&principal);
    ChatPage {
        i18n,
        theme,
        nav_username: username.clone(),
        ws_url,
        chatmail_addr,
        username,
        chat_suspended,
    }
    .into_response()
}

async fn upgrade_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    match require_auth(&principal) {
        Ok(uname) => UpgradePage {
            i18n,
            theme,
            nav_username: uname,
        }
        .into_response(),
        Err(r) => r,
    }
}

async fn chat_credentials_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let chatmail_addr =
        sqlx::query_scalar::<_, Option<String>>("SELECT chatmail_addr FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
    let chatmail_domain = state.chatmail_domain.clone().unwrap_or_default();
    let suspended: bool = sqlx::query_scalar(
        "SELECT COALESCE(actor_status = 'suspended', FALSE) FROM actors WHERE id = $1",
    )
    .bind(actor_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    let uname = nav_username(&principal);
    ChatCredentialsPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        chatmail_addr,
        chatmail_domain,
        suspended,
    }
    .into_response()
}

#[derive(Debug, serde::Deserialize)]
struct ThemeForm {
    theme: String,
}

/// The path of `referer` when it addresses `origin`, and nothing when it
/// addresses anywhere else.
///
/// The whole origin must match and the remainder must begin with a
/// slash. Both halves are load-bearing: `//evil.example/x` satisfies a
/// leading-slash test, and `https://example.org.evil.example/x`
/// satisfies a host comparison.
fn same_origin_path<'a>(referer: &'a str, origin: &str) -> Option<&'a str> {
    referer
        .strip_prefix(origin)
        .filter(|path| path.starts_with('/'))
}

/// Record the chosen theme and return the reader to the page they were on.
///
/// A same-origin form post carries the full URL in `Referer`, which the
/// response referrer policy permits, so it is enough to get back.
/// Anything not addressed to this instance is discarded rather than
/// followed.
async fn set_theme(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<ThemeForm>,
) -> Response {
    let origin = crate::middleware::http_origin(&state.domain, state.public_port);
    let back = headers
        .get(axum::http::header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(|referer| same_origin_path(referer, &origin))
        .unwrap_or("/");

    let mut response = Redirect::to(back).into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        crate::theme::set_theme_cookie(Theme::parse(&form.theme), &state.domain),
    );
    response
}

async fn settings_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    match require_auth(&principal) {
        Ok(uname) => SettingsPage {
            i18n,
            theme,
            nav_username: uname,
        }
        .into_response(),
        Err(r) => r,
    }
}

async fn edit_profile_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);
    let row = sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT display_name, headline, location, summary_md, avatar_url FROM actors WHERE id = $1",
    )
    .bind(actor_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or_default();
    EditProfilePage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        display_name: row.0.unwrap_or_default(),
        headline: row.1.unwrap_or_default(),
        location: row.2.unwrap_or_default(),
        summary_md: row.3.unwrap_or_default(),
        avatar_url: row.4.unwrap_or_default(),
    }
    .into_response()
}

async fn edit_experience_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let uname = match require_auth(&principal) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditExperiencePage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        title: String::new(),
        company: String::new(),
        start_date: String::new(),
        end_date: String::new(),
        description_md: String::new(),
        visibility: "public".into(),
    }
    .into_response()
}

async fn edit_education_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let uname = match require_auth(&principal) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditEducationPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        institution: String::new(),
        degree: String::new(),
        field_of_study: String::new(),
        start_date: String::new(),
        end_date: String::new(),
        visibility: "public".into(),
    }
    .into_response()
}

async fn edit_skills_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);
    let rows = sqlx::query_as::<_, (uuid::Uuid, String)>(
        "SELECT id, name FROM skills WHERE actor_id = $1 ORDER BY name",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let skills = rows
        .into_iter()
        .map(|(id, name)| SkillEntry {
            id: id.to_string(),
            name,
        })
        .collect();
    EditSkillsPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        skills,
    }
    .into_response()
}

async fn edit_publication_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let uname = match require_auth(&principal) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditPublicationPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
    }
    .into_response()
}

async fn edit_links_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);
    let rows = sqlx::query_as::<_, (uuid::Uuid, String, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, url, verified_at FROM verified_links WHERE actor_id = $1 ORDER BY url",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let links = rows
        .into_iter()
        .map(|(id, url, verified_at)| LinkEntry {
            id: id.to_string(),
            url,
            verified_at: verified_at.map(|t| t.to_string()),
        })
        .collect();
    EditLinksPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        domain: state.domain.clone(),
        links,
    }
    .into_response()
}

async fn edit_job_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let uname = match require_auth(&principal) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditJobPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
    }
    .into_response()
}

async fn compose_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let uname = match require_auth(&principal) {
        Ok(u) => u,
        Err(r) => return r,
    };
    ComposePage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
    }
    .into_response()
}

async fn privacy_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);
    let privacy: serde_json::Value =
        sqlx::query_scalar("SELECT actor_privacy FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or_default();

    // Gather section visibility rows from each profile section table.
    let mut section_rows = Vec::new();

    let exp_rows: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT id, title, visibility FROM experiences WHERE actor_id = $1 ORDER BY sort_order",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    for (id, label, vis) in exp_rows {
        section_rows.push(SectionVisibilityRow {
            section_id: id.to_string(),
            table_name: "experience".into(),
            label,
            visibility: vis,
        });
    }

    let edu_rows: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT id, institution, visibility FROM educations WHERE actor_id = $1 ORDER BY sort_order",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    for (id, label, vis) in edu_rows {
        section_rows.push(SectionVisibilityRow {
            section_id: id.to_string(),
            table_name: "education".into(),
            label,
            visibility: vis,
        });
    }

    let pub_rows: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT id, title, visibility FROM publications WHERE actor_id = $1 ORDER BY sort_order",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    for (id, label, vis) in pub_rows {
        section_rows.push(SectionVisibilityRow {
            section_id: id.to_string(),
            table_name: "publication".into(),
            label,
            visibility: vis,
        });
    }

    let link_rows: Vec<(uuid::Uuid, String, String)> =
        sqlx::query_as("SELECT id, url, visibility FROM verified_links WHERE actor_id = $1")
            .bind(actor_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    for (id, label, vis) in link_rows {
        section_rows.push(SectionVisibilityRow {
            section_id: id.to_string(),
            table_name: "link".into(),
            label,
            visibility: vis,
        });
    }

    let skill_rows: Vec<(uuid::Uuid, String, String)> =
        sqlx::query_as("SELECT id, name, visibility FROM skills WHERE actor_id = $1 ORDER BY name")
            .bind(actor_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    for (id, label, vis) in skill_rows {
        section_rows.push(SectionVisibilityRow {
            section_id: id.to_string(),
            table_name: "skill".into(),
            label,
            visibility: vis,
        });
    }

    PrivacyPage {
        i18n,
        theme,
        nav_username: uname,
        discoverable: privacy["discoverable"].as_bool().unwrap_or(true),
        indexable: privacy["indexable"].as_bool().unwrap_or(true),
        federate_profile: privacy["federate_profile"].as_bool().unwrap_or(true),
        require_follow_approval: privacy["require_follow_approval"]
            .as_bool()
            .unwrap_or(false),
        show_followers_count: privacy["show_followers_count"].as_bool().unwrap_or(true),
        chatmail_visible: privacy["chatmail_visible"].as_bool().unwrap_or(true),
        cv_download: privacy["cv_download"]
            .as_str()
            .unwrap_or("public")
            .to_owned(),
        default_visibility: "public".into(),
        section_rows,
    }
    .into_response()
}

/// HTMX partial: profile preview as seen by public / follower / owner.
#[derive(serde::Deserialize)]
struct PreviewQuery {
    #[serde(rename = "as")]
    perspective: Option<String>,
}

async fn privacy_preview_partial(
    State(state): State<AppState>,
    _i18n: I18n,
    principal: Option<axum::Extension<Principal>>,
    axum::extract::Query(params): axum::extract::Query<PreviewQuery>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let perspective = params.perspective.unwrap_or_else(|| "public".into());

    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT COALESCE(display_name, username), COALESCE(headline, ''), COALESCE(summary_html, '') FROM actors WHERE id = $1",
    )
    .bind(actor_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let (display_name, headline, summary) = row.unwrap_or_default();

    // For the public view, suppress sections marked as followers-only or private.
    // For the follower view, suppress sections marked as private.
    // For the owner view, show everything.
    let vis_filter: &[&str] = match perspective.as_str() {
        "public" => &["public"],
        "follower" => &["public", "followers"],
        _ => &["public", "followers", "private"],
    };

    let exp_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM experiences WHERE actor_id = $1 AND visibility = ANY($2)",
    )
    .bind(actor_id)
    .bind(vis_filter)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let edu_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM educations WHERE actor_id = $1 AND visibility = ANY($2)",
    )
    .bind(actor_id)
    .bind(vis_filter)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let pub_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM publications WHERE actor_id = $1 AND visibility = ANY($2)",
    )
    .bind(actor_id)
    .bind(vis_filter)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    // Render a simple preview fragment (this is an HTMX partial, not a full page).
    // Note: `summary` is `summary_html` from the database, which is
    // pre-sanitised by the noombat-markup pipeline on write (ammonia
    // allowlist). It is safe to interpolate without re-sanitising,
    // consistent with the profile template's `{{ summary_html|safe }}`.
    let html = format!(
        r#"<p class="font-semibold text-lg">{display_name}</p>
{headline_html}
<div class="text-sm leading-relaxed mt-2">{summary}</div>
<p class="text-xs text-text-secondary mt-3">{exp_count} experience · {edu_count} education · {pub_count} publications visible</p>"#,
        display_name = ammonia::clean(&display_name),
        headline_html = if headline.is_empty() {
            String::new()
        } else {
            format!(
                r#"<p class="text-sm text-text-secondary">{}</p>"#,
                ammonia::clean(&headline)
            )
        },
        summary = summary,
        exp_count = exp_count,
        edu_count = edu_count,
        pub_count = pub_count,
    );

    axum::response::Html(html).into_response()
}

// Account settings page (data export and deletion).

#[derive(Template, WebTemplate)]
#[template(path = "account_settings.html")]
struct AccountSettingsPage {
    i18n: I18n,
    theme: Theme,
    nav_username: String,
    deletion_pending: bool,
}

async fn account_settings_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);

    let deletion_requested: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deletion_requested_at FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(None);

    AccountSettingsPage {
        i18n,
        theme,
        nav_username: uname,
        deletion_pending: deletion_requested.is_some(),
    }
    .into_response()
}

async fn blocked_muted_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);

    let block_rows = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
        "SELECT id, target_id FROM blocks WHERE actor_id = $1",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut blocked = Vec::new();
    for (id, target_id) in block_rows {
        let target = sqlx::query_as::<_, (String, String)>(
            "SELECT COALESCE(display_name, username), ap_id FROM actors WHERE id = $1",
        )
        .bind(target_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        blocked.push(BlockEntry {
            id: id.to_string(),
            target_name: target.0,
            target_ap_id_encoded: urlencoding::encode(&target.1).into_owned(),
        });
    }

    let mute_rows = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
        "SELECT id, target_id FROM mutes WHERE actor_id = $1",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut muted = Vec::new();
    for (id, target_id) in mute_rows {
        let name: String =
            sqlx::query_scalar("SELECT COALESCE(display_name, username) FROM actors WHERE id = $1")
                .bind(target_id)
                .fetch_one(&state.pool)
                .await
                .unwrap_or_default();
        muted.push(MuteEntry {
            id: id.to_string(),
            target_name: name,
        });
    }

    BlockedMutedPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        blocked,
        muted,
    }
    .into_response()
}

async fn follow_requests_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);

    let rows = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
        "SELECT id, follower_id FROM follows WHERE following_id = $1 AND accepted = FALSE ORDER BY created_at DESC"
    ).bind(actor_id).fetch_all(&state.pool).await.unwrap_or_default();

    let mut requests = Vec::new();
    for (id, follower_id) in rows {
        let info = sqlx::query_as::<_, (String, String, String)>(
            "SELECT COALESCE(display_name, username), username, domain FROM actors WHERE id = $1",
        )
        .bind(follower_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(("unknown".into(), "unknown".into(), "unknown".into()));
        requests.push(FollowRequestEntry {
            id: id.to_string(),
            display_name: info.0,
            profile_url: format!("/@{}", info.1),
        });
    }

    FollowRequestsPage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        requests,
    }
    .into_response()
}

async fn migrate_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&principal) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&principal);

    let rows = sqlx::query_as::<_, (uuid::Uuid, String)>(
        "SELECT id, alias FROM actor_aliases WHERE actor_id = $1 ORDER BY alias",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let aliases = rows
        .into_iter()
        .map(|(id, alias)| AliasEntry {
            id: id.to_string(),
            alias,
        })
        .collect();

    MigratePage {
        i18n,
        theme,
        nav_username: uname.clone(),
        username: uname,
        aliases,
    }
    .into_response()
}

async fn search_html_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    axum::extract::Query(params): axum::extract::Query<SearchQueryParams>,
) -> impl IntoResponse {
    let query = params.q.clone().unwrap_or_default();
    let index = params.index.clone().unwrap_or_else(|| "profiles".into());
    let mut results = Vec::new();

    if !query.is_empty()
        && let Some(ref backend) = state.search
        && let Ok(hits) = backend.search(&index, &query, None, 20, 0).await
    {
        for hit in hits {
            let title = hit
                .get("title")
                .or(hit.get("name"))
                .or(hit.get("display_name"))
                .and_then(|v| v.as_str())
                // Posts lack a title field; fall back to a
                // truncated snippet of the HTML content.
                .or_else(|| hit.get("content_html").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_owned();
            // Truncate to 120 characters for display.
            let title = if title.len() > 120 {
                format!("{}…", &title[..title.floor_char_boundary(120)])
            } else {
                title
            };
            let url = hit
                .get("url")
                .or(hit.get("ap_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("#")
                .to_owned();
            let subtitle = hit
                .get("headline")
                .or(hit.get("company"))
                .or(hit.get("location"))
                .or(hit.get("journal"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            results.push(SearchResultEntry {
                url,
                title,
                subtitle,
            });
        }
    }

    SearchPage {
        i18n,
        theme,
        query,
        index,
        results,
    }
}

#[derive(serde::Deserialize)]
struct SearchQueryParams {
    q: Option<String>,
    index: Option<String>,
}

// ..... Tests .....

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::DEFAULT_LOCALE;

    // ..... Theme return path .....

    const ORIGIN: &str = "https://noombat.social";

    #[test]
    fn a_same_origin_referer_yields_its_path() {
        assert_eq!(
            same_origin_path("https://noombat.social/feed", ORIGIN),
            Some("/feed")
        );
    }

    #[test]
    fn the_query_string_survives_so_the_reader_returns_to_the_same_page() {
        assert_eq!(
            same_origin_path("https://noombat.social/feed?page=3&user=ada", ORIGIN),
            Some("/feed?page=3&user=ada")
        );
    }

    #[test]
    fn a_foreign_origin_is_refused() {
        assert_eq!(same_origin_path("https://evil.example/feed", ORIGIN), None);
    }

    /// The reason the check is a whole-origin prefix rather than a host
    /// comparison or a leading-slash test. Each of these passes a weaker
    /// check and is an open redirect.
    #[test]
    fn near_misses_are_refused() {
        for referer in [
            "https://noombat.social.evil.example/feed",
            "https://noombat.socialevil.example/",
            "http://noombat.social/feed",
            "//evil.example/feed",
            "/feed",
            "https://noombat.social",
        ] {
            assert_eq!(same_origin_path(referer, ORIGIN), None, "{referer}");
        }
    }

    #[test]
    fn the_origin_itself_with_a_trailing_slash_is_the_root() {
        assert_eq!(
            same_origin_path("https://noombat.social/", ORIGIN),
            Some("/")
        );
    }

    // ..... Theme rendering .....

    fn render_with_theme(theme: Theme) -> String {
        LoginPage {
            i18n: I18n {
                locale: DEFAULT_LOCALE.to_owned(),
            },
            theme,
            error: None,
            orcid_enabled: false,
        }
        .render()
        .expect("login.html renders")
    }

    /// The theme reaches the root element, which is the whole mechanism:
    /// the stylesheet resolves `data-theme` and nothing else consults the
    /// preference. A `Theme` that is read from the cookie, threaded
    /// through every handler and never rendered would satisfy every other
    /// test here.
    #[test]
    fn the_chosen_theme_reaches_the_root_element() {
        for theme in [Theme::System, Theme::Light, Theme::Dark] {
            let html = render_with_theme(theme);
            let expected = format!(r#"data-theme="{}""#, theme.as_str());
            assert!(html.contains(&expected), "{expected} absent from:\n{html}");
        }
    }

    /// Exactly one control is marked, and it is the current theme.
    #[test]
    fn the_control_marks_the_current_theme_and_only_that_one() {
        for theme in [Theme::System, Theme::Light, Theme::Dark] {
            let html = render_with_theme(theme);
            assert_eq!(
                html.matches(r#"aria-pressed="true""#).count(),
                1,
                "expected exactly one marked control for {}",
                theme.as_str()
            );
            assert_eq!(html.matches(r#"aria-pressed="false""#).count(), 2);

            // The marked button is the one whose `value` is the last to
            // appear before the mark.
            let marked = html
                .split_once(r#"aria-pressed="true""#)
                .expect("a marked control")
                .0
                .rsplit_once(r#"value=""#)
                .expect("a value attribute on the marked control")
                .1
                .split('"')
                .next()
                .expect("a closing quote");
            assert_eq!(marked, theme.as_str());
        }
    }

    /// Every character HTML escaping exists for, in one string.
    const HOSTILE: &str = r#"<script>alert('xss') & "quoted"</script>"#;

    /// What Askama's `Html` escaper must produce for [`HOSTILE`].
    ///
    /// Askama emits numeric entities rather than the named ones, so
    /// `&#60;` and not `&lt;`. Asserting the exact string rather than
    /// "contains no `<script>`" is deliberate: a half-broken escaper
    /// that dropped only the quote handling would still satisfy the
    /// weaker check.
    const ESCAPED: &str =
        "&#60;script&#62;alert(&#39;xss&#39;) &#38; &#34;quoted&#34;&#60;/script&#62;";

    /// Interpolation escapes user-controlled content.
    ///
    /// Nothing else in the suite asserts a single byte of rendered
    /// HTML: the header tests drive real template routes but check
    /// only the status and a header set, so an escaper regression
    /// would ship green. That gap is not hypothetical. The escaper is
    /// selected by file extension, `.html` mapping to `Html` through a
    /// table in `askama_derive`, and an upgrade that changed either
    /// the table or the escaper would silently turn every `{{ }}` on
    /// every page into an injection point.
    #[test]
    fn interpolation_escapes_user_controlled_content() {
        let page = LoginPage {
            i18n: I18n {
                locale: DEFAULT_LOCALE.to_owned(),
            },
            theme: Theme::System,
            error: Some(HOSTILE.to_owned()),
            orcid_enabled: false,
        };

        let html = page.render().expect("login.html renders");

        assert!(
            html.contains(ESCAPED),
            "escaped form absent from the rendered page; got:\n{html}"
        );
        assert!(
            !html.contains(HOSTILE),
            "raw user content reached the rendered page verbatim"
        );
        assert!(
            !html.contains("<script>alert"),
            "an executable script tag reached the rendered page"
        );
    }
}
