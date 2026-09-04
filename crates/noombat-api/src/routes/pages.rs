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
use axum::extract::{Path, State};

use crate::error::ApiError;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};

use crate::i18n::I18n;
use crate::middleware::Viewer;
use crate::state::AppState;
use crate::theme::{Contrast, Theme};

// ..... Helper .....

/// Extract the authenticated username or redirect to login.
#[allow(clippy::result_large_err)]
fn require_auth(viewer: &Option<axum::Extension<Viewer>>) -> Result<String, Response> {
    viewer
        .as_ref()
        .map(|p| p.username.clone())
        .ok_or_else(|| Redirect::temporary("/auth/login").into_response())
}

fn nav_username(viewer: &Option<axum::Extension<Viewer>>) -> String {
    viewer
        .as_ref()
        .map(|p| p.username.clone())
        .unwrap_or_default()
}

fn actor_uuid(viewer: &Option<axum::Extension<Viewer>>) -> Option<uuid::Uuid> {
    viewer.as_ref().map(|p| p.actor_id)
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
    /// Stored on `actors.default_post_visibility`, not inside
    /// `actor_privacy`: that blob holds access-control predicates, each
    /// with a read-enforcement site, and a default for new objects has
    /// none. The only thing that reads it is the compose path.
    #[serde(default)]
    default_visibility: Option<String>,
    /// Who may read each relationship list. Absent means unchanged
    /// rather than private, because a form that omits a select must not
    /// silently narrow a setting the owner never touched.
    #[serde(default)]
    connections_visibility: Option<String>,
    #[serde(default)]
    following_visibility: Option<String>,
    #[serde(default)]
    followers_visibility: Option<String>,
}

/// Persist the four settings that live in columns rather than in the
/// `actor_privacy` blob: the default post visibility and the three list
/// tiers.
///
/// A value the form did not send leaves its column alone. A value it did
/// send but that no tier names is refused, rather than being folded to
/// the narrowest one: reporting success on a setting that was not stored
/// is how a privacy control comes to be cosmetic.
async fn save_visibility_columns(
    state: &AppState,
    actor_id: uuid::Uuid,
    form: &PrivacySettingsForm,
) -> Result<(), (axum::http::StatusCode, String)> {
    let bad_request = |message: String| (axum::http::StatusCode::BAD_REQUEST, message);

    if let Some(ref value) = form.default_visibility {
        if !matches!(
            value.as_str(),
            "public" | "unlisted" | "followers" | "connections"
        ) {
            return Err(bad_request(format!(
                "default post visibility must be 'public', 'unlisted', \
                 'followers' or 'connections', not {value:?}"
            )));
        }
        if let Err(e) = sqlx::query("UPDATE actors SET default_post_visibility = $2 WHERE id = $1")
            .bind(actor_id)
            .bind(value)
            .execute(&state.pool)
            .await
        {
            tracing::error!(%actor_id, "failed to save the default post visibility: {e}");
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "could not save privacy settings".to_owned(),
            ));
        }
    }

    let current = noombat_identity::connections::list_settings(&state.pool, actor_id)
        .await
        .unwrap_or(noombat_identity::connections::ListSettings {
            connections: noombat_core::privacy::ListVisibility::Private,
            following: noombat_core::privacy::ListVisibility::Private,
            followers: noombat_core::privacy::ListVisibility::Private,
        });

    let mut settings = current;
    for (posted, target) in [
        (&form.connections_visibility, &mut settings.connections),
        (&form.following_visibility, &mut settings.following),
        (&form.followers_visibility, &mut settings.followers),
    ] {
        if let Some(value) = posted {
            match crate::routes::connections::parse_list_setting(value) {
                Ok(parsed) => *target = parsed,
                Err(e) => return Err(bad_request(e.to_string())),
            }
        }
    }

    if settings != current
        && let Err(e) =
            noombat_identity::connections::set_list_settings(&state.pool, actor_id, settings).await
    {
        tracing::error!(%actor_id, "failed to save the list visibility settings: {e}");
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "could not save privacy settings".to_owned(),
        ));
    }

    Ok(())
}

/// Persist the profile privacy settings of the signed-in actor.
///
/// There is no username in the path on purpose: the target is whoever
/// the session says it is, so there is no other user's settings to
/// authorise against and no confused-deputy shape to get wrong.
async fn save_privacy_settings(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    axum::Form(form): axum::Form<PrivacySettingsForm>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
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

    if let Err(refusal) = save_visibility_columns(&state, actor_id, &form).await {
        return refusal.into_response();
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
    contrast: Contrast,
    error: Option<String>,
    orcid_enabled: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "register.html")]
struct RegisterPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    error: Option<String>,
    open_registrations: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "totp.html")]
struct TotpPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
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
    contrast: Contrast,
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
    contrast: Contrast,
    nav_username: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "chat_credentials.html")]
struct ChatCredentialsPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
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
    contrast: Contrast,
    nav_username: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_profile.html")]
struct EditProfilePage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    username: String,
    display_name: String,
    headline: String,
    location: String,
    summary_md: String,
    avatar_url: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_work_experience.html")]
struct EditWorkExperiencePage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    username: String,
    title: String,
    organization: String,
    start_date: String,
    end_date: String,
    description_md: String,
    visibility: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_education_entry.html")]
struct EditEducationEntryPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
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
    contrast: Contrast,
    nav_username: String,
    username: String,
    skills: Vec<SkillEntry>,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_scholarly_article.html")]
struct EditScholarlyArticlePage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
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
    contrast: Contrast,
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
    contrast: Contrast,
    nav_username: String,
    /// Where the form posts. A new posting goes to `/settings/jobs`, an
    /// existing one to `/settings/jobs/{id}`, and the template does not
    /// have to know which case it is in.
    form_action: String,
    title: String,
    description_md: String,
    location: String,
    remote: bool,
    salary_min: String,
    salary_max: String,
    currency: String,
}

impl EditJobPage {
    /// An empty form for a posting that does not exist yet.
    fn blank(i18n: I18n, theme: Theme, contrast: Contrast, username: String) -> Self {
        Self {
            i18n,
            theme,
            contrast,
            nav_username: username,
            form_action: "/settings/jobs".to_owned(),
            title: String::new(),
            description_md: String::new(),
            location: String::new(),
            remote: false,
            salary_min: String::new(),
            salary_max: String::new(),
            currency: String::new(),
        }
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "compose.html")]
struct ComposePage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    username: String,
}

// Search result entry for the template.
struct SearchResultEntry {
    url: String,
    title: String,
    subtitle: String,
    /// The i18n key for the poster's declaration, on a job result.
    /// Empty on every other index, and on a posting an individual wrote.
    org_kind_key: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "search.html")]
struct SearchPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    query: String,
    index: String,
    /// The declaration the seeker filtered on, so the control comes back
    /// showing what it is doing rather than reset to "any".
    org_kind: String,
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
    contrast: Contrast,
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

/// A blocked Chatmail sender, which is an address rather than an actor:
/// the sender may have no account here at all.
struct ChatmailBlockEntry {
    address: String,
    address_encoded: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "blocked_muted.html")]
struct BlockedMutedPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    nav_username: String,
    username: String,
    blocked: Vec<BlockEntry>,
    chatmail_blocked: Vec<ChatmailBlockEntry>,
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
    contrast: Contrast,
    nav_username: String,
    discoverable: bool,
    indexable: bool,
    federate_profile: bool,
    require_follow_approval: bool,
    show_followers_count: bool,
    chatmail_visible: bool,
    cv_download: String,
    default_visibility: String,
    connections_visibility: String,
    following_visibility: String,
    followers_visibility: String,
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
    contrast: Contrast,
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
        .route("/settings/experience", get(edit_work_experience_page))
        .route("/settings/education", get(edit_education_entry_page))
        .route("/settings/skills", get(edit_skills_page))
        .route("/settings/publications", get(edit_scholarly_article_page))
        .route("/settings/links", get(edit_links_page))
        .route("/settings/jobs/new", get(edit_job_page))
        .route("/settings/jobs", post(create_job_from_form))
        .route(
            "/settings/jobs/{id}",
            get(edit_existing_job_page).post(update_job_from_form),
        )
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
        // Deliberately not behind require_auth: appearance is a property
        // of the browser, not of an account.
        .route("/settings/theme", post(set_theme))
        .route("/settings/contrast", post(set_contrast))
        // Compose.
        .route("/compose", get(compose_page))
        // HTML search results.
        .route("/search/html", get(search_html_page))
}

// ..... Handlers .....

async fn login_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
) -> impl IntoResponse {
    LoginPage {
        i18n,
        theme,
        contrast,
        error: None,
        orcid_enabled: state.orcid_config.is_some(),
    }
}

async fn register_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
) -> impl IntoResponse {
    RegisterPage {
        i18n,
        theme,
        contrast,
        error: None,
        open_registrations: state.open_registrations,
    }
}

async fn totp_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> impl IntoResponse {
    let mut totp_enabled = false;
    let mut qr_data_uri = None;
    let mut secret_base32 = String::new();

    if let Some(actor_id) = actor_uuid(&viewer) {
        totp_enabled = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM totp_secrets WHERE actor_id = $1 AND verified = TRUE)",
        )
        .bind(actor_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if !totp_enabled {
            let uname = nav_username(&viewer);
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
        contrast,
        nav_username: nav_username(&viewer),
        totp_enabled,
        qr_data_uri,
        secret_base32,
    }
}

async fn chat_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
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
    let username = nav_username(&viewer);
    ChatPage {
        i18n,
        theme,
        contrast,
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
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    match require_auth(&viewer) {
        Ok(uname) => UpgradePage {
            i18n,
            theme,
            contrast,
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
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
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
    // Anything that is not a signed-in state reads as suspended to this page.
    // Kept in step with the login allowlist rather than naming 'suspended'
    // alone, so the two cannot diverge.
    let suspended: bool = sqlx::query_scalar(
        "SELECT COALESCE(actor_status NOT IN ('active', 'silenced'), FALSE) \
         FROM actors WHERE id = $1",
    )
    .bind(actor_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    let uname = nav_username(&viewer);
    ChatCredentialsPage {
        i18n,
        theme,
        contrast,
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

#[derive(Debug, serde::Deserialize)]
struct ContrastForm {
    contrast: String,
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
    let cookie = crate::theme::set_theme_cookie(Theme::parse(&form.theme), &state.domain);
    redirect_back_with(&state, &headers, cookie)
}

/// Record the contrast setting and return the reader to the page they
/// were on.
async fn set_contrast(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<ContrastForm>,
) -> Response {
    let cookie = crate::theme::set_contrast_cookie(Contrast::parse(&form.contrast), &state.domain);
    redirect_back_with(&state, &headers, cookie)
}

/// Send the reader back where they came from, carrying one `Set-Cookie`.
fn redirect_back_with(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    cookie: axum::http::HeaderValue,
) -> Response {
    let origin = crate::middleware::http_origin(&state.domain, state.public_port);
    let back = headers
        .get(axum::http::header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(|referer| same_origin_path(referer, &origin))
        .unwrap_or("/");

    let mut response = Redirect::to(back).into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    response
}

async fn settings_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    match require_auth(&viewer) {
        Ok(uname) => SettingsPage {
            i18n,
            theme,
            contrast,
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
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);
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
        contrast,
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

async fn edit_work_experience_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let uname = match require_auth(&viewer) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditWorkExperiencePage {
        i18n,
        theme,
        contrast,
        nav_username: uname.clone(),
        username: uname,
        title: String::new(),
        organization: String::new(),
        start_date: String::new(),
        end_date: String::new(),
        description_md: String::new(),
        visibility: "public".into(),
    }
    .into_response()
}

async fn edit_education_entry_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let uname = match require_auth(&viewer) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditEducationEntryPage {
        i18n,
        theme,
        contrast,
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
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);
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
        contrast,
        nav_username: uname.clone(),
        username: uname,
        skills,
    }
    .into_response()
}

async fn edit_scholarly_article_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let uname = match require_auth(&viewer) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditScholarlyArticlePage {
        i18n,
        theme,
        contrast,
        nav_username: uname.clone(),
        username: uname,
    }
    .into_response()
}

async fn edit_links_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);
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
        contrast,
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
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let uname = match require_auth(&viewer) {
        Ok(u) => u,
        Err(r) => return r,
    };
    EditJobPage::blank(i18n, theme, contrast, uname).into_response()
}

// ..... The job write path .....

/// Body of `POST /settings/jobs` and `POST /settings/jobs/{id}`.
///
/// Form-encoded, because that is what the page posts. The JSON route on
/// `/users/{username}/jobs` takes the same fields as JSON, and the form
/// used to post at it: an HTML form cannot send `application/json`, so
/// every submission was rejected on content type before authorisation
/// was even reached.
#[derive(Debug, serde::Deserialize)]
pub struct JobPostingForm {
    title: String,
    description_md: String,
    #[serde(default)]
    location: String,
    /// An unchecked checkbox submits nothing at all, so this must
    /// default rather than fail to deserialise.
    #[serde(default)]
    remote: bool,
    #[serde(default)]
    salary_min: String,
    #[serde(default)]
    salary_max: String,
    #[serde(default)]
    currency: String,
    /// One requirement per line, which is what a textarea gives.
    #[serde(default)]
    requirements: String,
}

impl JobPostingForm {
    /// An empty text field is absent, not an empty value.
    fn optional(value: &str) -> Option<String> {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    /// A blank or unparsable salary is absent rather than zero. Zero is
    /// a salary somebody could mean.
    fn salary(value: &str) -> Option<i64> {
        value.trim().parse().ok()
    }

    fn requirement_list(&self) -> Option<Vec<String>> {
        let items: Vec<String> = self
            .requirements
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        (!items.is_empty()).then_some(items)
    }
}

/// `POST /settings/jobs`
async fn create_job_from_form(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    axum::Form(form): axum::Form<JobPostingForm>,
) -> Response {
    let Some(actor_id) = viewer.as_ref().map(|v| v.actor_id) else {
        return Redirect::temporary("/auth/login").into_response();
    };

    let actor = match noombat_identity::repo::find_by_id(&state.pool, actor_id).await {
        Ok(a) => a,
        Err(e) => return ApiError(e).into_response(),
    };

    // The same gate the JSON route applies, and it has to be applied
    // here too rather than trusted from there: two write paths that
    // disagree about the gate are one write path that has none.
    if actor.actor_type == noombat_core::actor::ActorType::Organization
        && !noombat_identity::verification::controls_claimed_domain(&state.pool, actor.id)
            .await
            .unwrap_or(false)
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "this organisation has not yet proved it controls the domain it claims",
        )
            .into_response();
    }

    // Likewise on both paths: a seeker filtering for direct employers
    // reads a declaration, and a posting written through the form with
    // none would be missing from both filtered lists.
    if actor.actor_type == noombat_core::actor::ActorType::Organization && actor.org_kind.is_none()
    {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "declare whether this organisation is an employer or an agency before posting",
        )
            .into_response();
    }

    let params = noombat_jobs::NewJobPosting {
        title: form.title.clone(),
        description_md: form.description_md.clone(),
        location: JobPostingForm::optional(&form.location),
        remote: Some(form.remote),
        salary_min: JobPostingForm::salary(&form.salary_min),
        salary_max: JobPostingForm::salary(&form.salary_max),
        currency: JobPostingForm::optional(&form.currency),
        requirements: form.requirement_list(),
        expires_at: None,
        publish: true,
    };

    match noombat_jobs::create_job(
        &state.pool,
        actor.id,
        Some(actor_id),
        &state.domain,
        &params,
    )
    .await
    {
        Ok(job) => {
            crate::search_sync::index_job(&state.search, &job);
            crate::jobs_federation::announce_published(&state.pool, &state.domain, &actor, &job)
                .await;
            Redirect::to(&format!("/jobs/{}", job.id)).into_response()
        }
        Err(e) => ApiError(e).into_response(),
    }
}

/// `GET /settings/jobs/{id}`: the same form, filled in.
async fn edit_existing_job_page(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let uname = match require_auth(&viewer) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let job = match noombat_jobs::get_job(&state.pool, id).await {
        Ok(j) => j,
        Err(e) => return ApiError(e).into_response(),
    };
    if let Err(e) = crate::auth::require_acts_for(&state.pool, job.actor_id, &viewer).await {
        return e.into_response();
    }

    EditJobPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        form_action: format!("/settings/jobs/{id}"),
        title: job.title,
        description_md: job.description_md,
        location: job.location.unwrap_or_default(),
        remote: job.remote,
        salary_min: job.salary_min.map(|v| v.to_string()).unwrap_or_default(),
        salary_max: job.salary_max.map(|v| v.to_string()).unwrap_or_default(),
        currency: job.currency.unwrap_or_default(),
    }
    .into_response()
}

/// `POST /settings/jobs/{id}`
async fn update_job_from_form(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    viewer: Option<axum::Extension<Viewer>>,
    axum::Form(form): axum::Form<JobPostingForm>,
) -> Response {
    let job = match noombat_jobs::get_job(&state.pool, id).await {
        Ok(j) => j,
        Err(e) => return ApiError(e).into_response(),
    };
    if let Err(e) = crate::auth::require_acts_for(&state.pool, job.actor_id, &viewer).await {
        return e.into_response();
    }

    let params = noombat_jobs::UpdateJobPosting {
        title: Some(form.title.clone()),
        description_md: Some(form.description_md.clone()),
        location: JobPostingForm::optional(&form.location),
        remote: Some(form.remote),
        salary_min: JobPostingForm::salary(&form.salary_min),
        salary_max: JobPostingForm::salary(&form.salary_max),
        currency: JobPostingForm::optional(&form.currency),
        requirements: form.requirement_list(),
        expires_at: None,
    };

    match noombat_jobs::update_job(&state.pool, job.actor_id, id, &params).await {
        Ok(updated) => {
            crate::search_sync::index_job(&state.search, &updated);
            Redirect::to(&format!("/jobs/{id}")).into_response()
        }
        Err(e) => ApiError(e).into_response(),
    }
}

async fn compose_page(
    _state: State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let uname = match require_auth(&viewer) {
        Ok(u) => u,
        Err(r) => return r,
    };
    ComposePage {
        i18n,
        theme,
        contrast,
        nav_username: uname.clone(),
        username: uname,
    }
    .into_response()
}

async fn privacy_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);
    let privacy: serde_json::Value =
        sqlx::query_scalar("SELECT actor_privacy FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or_default();

    // The four columns the form's selects reflect. Read rather than
    // assumed: a select that always renders its first option reports
    // "public" to an owner who chose otherwise.
    let (default_visibility, list_settings_str) =
        sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT default_post_visibility, connections_visibility, \
                following_visibility, followers_visibility \
         FROM actors WHERE id = $1",
        )
        .bind(actor_id)
        .fetch_one(&state.pool)
        .await
        .map(|row| (row.0, (row.1, row.2, row.3)))
        .unwrap_or_else(|_| {
            (
                "public".to_owned(),
                (
                    "private".to_owned(),
                    "private".to_owned(),
                    "private".to_owned(),
                ),
            )
        });

    // Gather section visibility rows from each profile section table.
    let mut section_rows = Vec::new();

    let exp_rows: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT id, title, visibility FROM work_experiences WHERE actor_id = $1 ORDER BY sort_order",
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
        "SELECT id, institution, visibility FROM education_entries WHERE actor_id = $1 ORDER BY sort_order",
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
        "SELECT id, title, visibility FROM scholarly_articles WHERE actor_id = $1 ORDER BY sort_order",
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
        contrast,
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
        default_visibility,
        connections_visibility: list_settings_str.0,
        following_visibility: list_settings_str.1,
        followers_visibility: list_settings_str.2,
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
    viewer: Option<axum::Extension<Viewer>>,
    axum::extract::Query(params): axum::extract::Query<PreviewQuery>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
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
        "SELECT COUNT(*) FROM work_experiences WHERE actor_id = $1 AND visibility = ANY($2)",
    )
    .bind(actor_id)
    .bind(vis_filter)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let edu_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM education_entries WHERE actor_id = $1 AND visibility = ANY($2)",
    )
    .bind(actor_id)
    .bind(vis_filter)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let pub_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scholarly_articles WHERE actor_id = $1 AND visibility = ANY($2)",
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
    contrast: Contrast,
    nav_username: String,
    deletion_pending: bool,
}

async fn account_settings_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);

    let deletion_requested: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deletion_requested_at FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(None);

    AccountSettingsPage {
        i18n,
        theme,
        contrast,
        nav_username: uname,
        deletion_pending: deletion_requested.is_some(),
    }
    .into_response()
}

async fn blocked_muted_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);

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

    // Chatmail senders. A user could block one and had no way to undo
    // it: `unblock_sender` existed with no caller and no surface, and
    // nothing listed `chatmail_blocks` at all, so the block was
    // invisible as well as permanent.
    let chatmail_blocked = sqlx::query_scalar::<_, String>(
        "SELECT blocked_addr FROM chatmail_blocks WHERE actor_id = $1 ORDER BY blocked_addr",
    )
    .bind(actor_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|address| ChatmailBlockEntry {
        address_encoded: urlencoding::encode(&address).into_owned(),
        address,
    })
    .collect();

    BlockedMutedPage {
        i18n,
        theme,
        contrast,
        nav_username: uname.clone(),
        username: uname,
        blocked,
        muted,
        chatmail_blocked,
    }
    .into_response()
}

async fn follow_requests_page(
    State(state): State<AppState>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);

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
        contrast,
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
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let uname = nav_username(&viewer);

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
        contrast,
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
    contrast: Contrast,
    axum::extract::Query(params): axum::extract::Query<SearchQueryParams>,
) -> impl IntoResponse {
    let query = params.q.clone().unwrap_or_default();
    let index = params.index.clone().unwrap_or_else(|| "profiles".into());
    let mut results = Vec::new();

    // Parsed rather than interpolated. The value reaches a Meilisearch
    // filter expression, so anything but the two declarations it can
    // name is dropped, and the control comes back showing "any".
    let org_kind = params
        .org_kind
        .as_deref()
        .and_then(noombat_core::actor::OrgKind::parse);

    // Only the jobs index carries the attribute. Meilisearch rejects a
    // filter naming an attribute an index was not told about, so sending
    // it while searching profiles would fail the whole search.
    let filter = match (index.as_str(), org_kind) {
        ("jobs", Some(kind)) => Some(format!("org_kind = \"{}\"", kind.as_str())),
        _ => None,
    };

    if !query.is_empty()
        && let Some(ref backend) = state.search
        && let Ok(hits) = backend
            .search(&index, &query, filter.as_deref(), 20, 0)
            .await
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
                .or(hit.get("organization"))
                .or(hit.get("location"))
                .or(hit.get("journal"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            // Read back from the hit, not from the filter: an unfiltered
            // list mixes employers and agencies, and the badge is what
            // tells them apart.
            let org_kind_key = hit
                .get("org_kind")
                .and_then(|v| v.as_str())
                .and_then(noombat_core::actor::OrgKind::parse)
                .map(|kind| match kind {
                    noombat_core::actor::OrgKind::Employer => "job_kind_employer",
                    noombat_core::actor::OrgKind::Agency => "job_kind_agency",
                })
                .unwrap_or_default()
                .to_owned();
            results.push(SearchResultEntry {
                url,
                title,
                subtitle,
                org_kind_key,
            });
        }
    }

    SearchPage {
        i18n,
        theme,
        contrast,
        query,
        index,
        org_kind: org_kind.map(|k| k.as_str()).unwrap_or_default().to_owned(),
        results,
    }
}

#[derive(serde::Deserialize)]
struct SearchQueryParams {
    q: Option<String>,
    index: Option<String>,
    /// Free-form here and parsed at use, so a value the enum does not
    /// name is an unfiltered search rather than a rejected request.
    org_kind: Option<String>,
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

    fn render_with(theme: Theme, contrast: Contrast) -> String {
        LoginPage {
            i18n: I18n {
                locale: DEFAULT_LOCALE.to_owned(),
            },
            theme,
            contrast,
            error: None,
            orcid_enabled: false,
        }
        .render()
        .expect("login.html renders")
    }

    fn render_with_theme(theme: Theme) -> String {
        render_with(theme, Contrast::Standard)
    }

    fn render_in_locale(locale: &str) -> String {
        LoginPage {
            i18n: I18n {
                locale: locale.to_owned(),
            },
            theme: Theme::System,
            contrast: Contrast::Standard,
            error: None,
            orcid_enabled: false,
        }
        .render()
        .expect("login.html renders")
    }

    /// `dir` is served from the locale, not from a literal. The second
    /// case is the whole assertion: the first passes against a hardcoded
    /// `dir="ltr"` just as well.
    #[test]
    fn the_direction_attribute_follows_the_locale() {
        assert!(render_in_locale(DEFAULT_LOCALE).contains(r#"dir="ltr""#));
        assert!(render_in_locale("ar-EG").contains(r#"dir="rtl""#));
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

    /// The contrast setting reaches the root element, and does so
    /// independently of the theme: the stylesheet keys the high-contrast
    /// palette off `data-contrast` alone, so a page that renders one
    /// attribute correctly says nothing about the other.
    #[test]
    fn the_contrast_setting_reaches_the_root_element_under_every_theme() {
        for theme in [Theme::System, Theme::Light, Theme::Dark] {
            for contrast in [Contrast::Standard, Contrast::High] {
                let html = render_with(theme, contrast);
                let expected = format!(r#"data-contrast="{}""#, contrast.as_str());
                assert!(
                    html.contains(&expected),
                    "{expected} absent with theme {}",
                    theme.as_str()
                );
                assert!(html.contains(&format!(r#"data-theme="{}""#, theme.as_str())));
            }
        }
    }

    /// The value of the one marked control in `group`, where a group is
    /// the markup of a single form.
    fn marked_value(group: &str) -> &str {
        assert_eq!(
            group.matches(r#"aria-pressed="true""#).count(),
            1,
            "expected exactly one marked control in:\n{group}"
        );
        group
            .split_once(r#"aria-pressed="true""#)
            .expect("a marked control")
            .0
            .rsplit_once(r#"value=""#)
            .expect("a value attribute on the marked control")
            .1
            .split('"')
            .next()
            .expect("a closing quote")
    }

    /// Split the rendered page at the boundary between the two forms, so
    /// each group is counted on its own. Counting across the page would
    /// pass while both controls marked the same thing.
    fn appearance_groups(html: &str) -> (&str, &str) {
        html.split_once(r#"action="/settings/contrast""#)
            .expect("the contrast form")
    }

    /// Exactly one control is marked, and it is the current theme.
    #[test]
    fn the_control_marks_the_current_theme_and_only_that_one() {
        for theme in [Theme::System, Theme::Light, Theme::Dark] {
            let html = render_with_theme(theme);
            let (theme_group, _) = appearance_groups(&html);
            assert_eq!(marked_value(theme_group), theme.as_str());
        }
    }

    #[test]
    fn the_control_marks_the_current_contrast_and_only_that_one() {
        for contrast in [Contrast::Standard, Contrast::High] {
            let html = render_with(Theme::System, contrast);
            let (_, contrast_group) = appearance_groups(&html);
            assert_eq!(marked_value(contrast_group), contrast.as_str());
        }
    }

    /// The two groups are marked independently. A single shared variable
    /// behind both would satisfy each group's own assertion.
    #[test]
    fn the_two_controls_do_not_track_each_other() {
        let html = render_with(Theme::Dark, Contrast::Standard);
        let (theme_group, contrast_group) = appearance_groups(&html);
        assert_eq!(marked_value(theme_group), "dark");
        assert_eq!(marked_value(contrast_group), "standard");
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
            contrast: Contrast::Standard,
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
