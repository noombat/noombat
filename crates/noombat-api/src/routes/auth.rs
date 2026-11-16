// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Authentication API routes.
//!
//! Provides endpoints for local registration, login, session
//! management, TOTP 2FA, OAuth (Mastodon, ORCID), and password
//! set/change (OAuth account upgrade).

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use noombat_core::error::NoombatError;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/totp/enrol", post(totp_enrol))
        .route("/api/v1/auth/totp/verify", post(totp_verify))
        .route("/api/v1/auth/totp", delete(totp_disable))
        .route("/api/v1/auth/mastodon", get(mastodon_init))
        .route("/api/v1/auth/mastodon/link", get(mastodon_link_init))
        .route("/api/v1/auth/mastodon/callback", get(mastodon_callback))
        .route("/api/v1/auth/orcid", get(orcid_init))
        .route("/api/v1/auth/orcid/link", get(orcid_link_init))
        .route("/api/v1/auth/orcid/callback", get(orcid_callback))
        .route("/api/v1/auth/password", post(set_password))
        .route("/api/v1/me/email", post(request_email_verification))
        .route("/auth/verify-email", get(verify_email))
        .route("/api/v1/me/provision_chat", post(provision_chat))
        .route(
            "/api/v1/me/chatmail_cred",
            get(get_chatmail_cred).put(put_chatmail_cred),
        )
}

// ..... Email verification .....

/// The signed-in actor, or a refusal.
fn require_actor(viewer: &Option<axum::Extension<Viewer>>) -> Result<uuid::Uuid, ApiError> {
    viewer
        .as_ref()
        .map(|p| p.actor_id)
        .ok_or(ApiError(NoombatError::Forbidden))
}

#[derive(Deserialize)]
struct EmailRequest {
    email: String,
}

/// Send a challenge, and say nothing about the address in the reply.
///
/// The mail goes out before the caller is answered, so a success here means
/// the message left rather than that a row was written. Where no relay is
/// configured this refuses: reporting success and dropping the message
/// leaves somebody waiting for mail that was never sent, which they cannot
/// tell from a slow inbox.
async fn send_challenge(
    state: &AppState,
    actor_id: uuid::Uuid,
    email: &str,
) -> Result<(), ApiError> {
    let mailer = state.mailer.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "this instance cannot send mail, so an address cannot be verified".into(),
        ))
    })?;

    let challenge =
        noombat_identity::email::request_verification(&state.pool, actor_id, email).await?;

    let link = format!(
        "https://{}/auth/verify-email?token={}",
        state.domain, challenge.token
    );
    let body = format!(
        "Confirm this address so your account can be recovered if you forget your password.\n\n\
         {link}\n\n\
         The link stops working in 24 hours. If you did not ask for this, ignore it: \
         nothing changes until the link is opened.\n"
    );

    mailer
        .send(&challenge.email, "Confirm your email address", &body)
        .await?;

    Ok(())
}

/// `POST /api/v1/me/email`
///
/// Start proving control of an address, for the signed-in account.
async fn request_email_verification(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(req): Json<EmailRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let actor_id = require_actor(&viewer)?;
    send_challenge(&state, actor_id, &req.email).await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct VerifyEmailQuery {
    token: String,
}

/// `GET /auth/verify-email?token=...`
///
/// The target of the link in the message, so it is a GET and carries its
/// credential in the query. Unauthenticated by design: somebody confirming
/// an address is often doing it in whichever browser opened their mail,
/// which is not the one holding their session.
async fn verify_email(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Result<Response, ApiError> {
    noombat_identity::email::verify(&state.pool, &query.token).await?;
    Ok(Redirect::temporary("/settings/account").into_response())
}

// ..... Local registration .....

async fn register(
    State(state): State<AppState>,
    Json(req): Json<noombat_identity::registration::RegisterRequest>,
) -> Result<Response, ApiError> {
    if !state.open_registrations {
        return Err(ApiError(NoombatError::Forbidden));
    }

    // Refused before the account is made, not after. This path mints a
    // password and the server can reset nothing, so an instance that cannot
    // send the challenge cannot offer password sign-up at all: creating the
    // account anyway would produce exactly the unrecoverable account the
    // address exists to prevent. The OAuth paths are unaffected, because
    // they mint no password and are recoverable through the provider.
    if state.mailer.is_none() {
        return Err(ApiError(NoombatError::ServiceUnavailable(
            "this instance cannot send mail, so it cannot offer password sign-up; \
             sign in with ORCID or Mastodon instead"
                .into(),
        )));
    }

    let result = noombat_identity::registration::register(&state.pool, &state.domain, &req).await?;

    // The address was validated during registration, so this fails only if
    // the relay is unreachable. It is awaited rather than spawned: the
    // person is about to be told their account exists, and they need to
    // know in the same breath whether to go and look for the message.
    if let Some(email) = req.email.as_deref() {
        send_challenge(&state, result.actor_id, email).await?;
    }

    // An account awaiting admission gets no session. `login` already
    // refuses a pending account, so minting a token here would be the
    // one way past the approval an administrator has not given yet.
    if result.awaiting_approval {
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "username": result.username,
                "status": "pending",
                "detail": "this instance admits new accounts by approval; \
                           you will be able to sign in once an administrator admits yours",
            })),
        )
            .into_response());
    }

    let session_config = state.session_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "sessions not configured".into(),
        ))
    })?;

    let tokens = noombat_identity::session::create_session(
        &state.pool,
        session_config,
        result.actor_id,
        &result.username,
        noombat_core::actor::InstanceRole::User,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await?;

    let cookie = crate::cookie::set_session_cookie(&tokens, &state.domain);
    let mut response = (StatusCode::CREATED, Json(&tokens)).into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    Ok(response)
}

// ..... Local login .....

async fn login(
    State(state): State<AppState>,
    Json(req): Json<noombat_identity::login::LoginRequest>,
) -> Result<Response, ApiError> {
    let (actor_id, username, role, _has_totp) =
        noombat_identity::login::verify_credentials(&state.pool, &req).await?;

    let session_config = state.session_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "sessions not configured".into(),
        ))
    })?;

    let tokens = noombat_identity::session::create_session(
        &state.pool,
        session_config,
        actor_id,
        &username,
        role,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await?;

    // Fetch the encrypted credential blob, and the setup it belongs to,
    // which a write of it must name.
    let (blob, chat_setup): (Option<Vec<u8>>, i64) =
        sqlx::query_as("SELECT chatmail_cred, chat_setup_generation FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await?;

    // Build a response that includes both the session tokens and the
    // base64-encoded blob (null if chat has not been provisioned).
    use base64::Engine as _;
    let blob_b64 = blob.map(|b| base64::engine::general_purpose::STANDARD.encode(b));

    let body = serde_json::json!({
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_in": tokens.expires_in,
        "chatmail_cred": blob_b64,
        "chat_setup": chat_setup,
    });

    let cookie = crate::cookie::set_session_cookie(&tokens, &state.domain);
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    Ok(response)
}

// ..... Session refresh .....

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Response, ApiError> {
    let session_config = state.session_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "sessions not configured".into(),
        ))
    })?;

    let tokens =
        noombat_identity::session::refresh_session(&state.pool, session_config, &req.refresh_token)
            .await?;

    let cookie = crate::cookie::set_session_cookie(&tokens, &state.domain);
    let mut response = Json(&tokens).into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    Ok(response)
}

// ..... Logout .....

#[derive(Deserialize)]
struct LogoutRequest {
    refresh_token: String,
}

async fn logout(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<Response, ApiError> {
    noombat_identity::session::revoke_session(&state.pool, &req.refresh_token).await?;
    let cookie = crate::cookie::clear_session_cookie(&state.domain);
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    Ok(response)
}

// ..... TOTP 2FA .....

async fn totp_enrol(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;
    let username = viewer.username.as_str();

    let enrolment =
        noombat_identity::totp::enrol_totp(&state.pool, actor_id, username, &state.domain).await?;

    Ok(Json(enrolment))
}

#[derive(Deserialize)]
struct TotpVerifyRequest {
    code: String,
}

async fn totp_verify(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<Response, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;

    noombat_identity::totp::verify_totp(&state.pool, actor_id, &req.code).await?;

    // Return an HTML fragment that HTMX swaps into the #totp-enrolment
    // container, replacing the verification form with a success message.
    let html = "<div class=\"bg-bg-success-subtle border border-border-success \
                text-text-success rounded px-4 py-3 text-sm\" role=\"status\">\
                Two-factor authentication is now enabled.</div>";
    Ok((StatusCode::OK, axum::response::Html(html)).into_response())
}

async fn totp_disable(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;

    noombat_identity::totp::disable_totp(&state.pool, actor_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ..... Mastodon OAuth .....

#[derive(Deserialize)]
struct MastodonInitQuery {
    handle: String,
}

async fn mastodon_init(
    State(state): State<AppState>,
    Query(query): Query<MastodonInitQuery>,
) -> Result<Response, ApiError> {
    let (url, _state_token) = noombat_identity::oauth_mastodon::build_authorise_url(
        &state.pool,
        &state.http_client,
        &query.handle,
        &state.domain,
        None,
    )
    .await?;

    Ok(Redirect::temporary(&url).into_response())
}

/// `GET /api/v1/auth/mastodon/link`
///
/// Start the same flow as signing in, but bound to the account already
/// signed in, so the callback links rather than creating. The account is
/// taken from the session here and recorded with the state: nothing in the
/// redirect that comes back is trusted to say whose account this is.
async fn mastodon_link_init(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Query(query): Query<MastodonInitQuery>,
) -> Result<Response, ApiError> {
    let actor_id = require_actor(&viewer)?;

    let (url, _state_token) = noombat_identity::oauth_mastodon::build_authorise_url(
        &state.pool,
        &state.http_client,
        &query.handle,
        &state.domain,
        Some(actor_id),
    )
    .await?;

    Ok(Redirect::temporary(&url).into_response())
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
}

async fn mastodon_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    let result = noombat_identity::oauth_mastodon::handle_callback(
        &state.pool,
        &state.http_client,
        &state.domain,
        &query.code,
        &query.state,
        state.open_registrations,
    )
    .await?;

    // Issue a session for the (new or existing) actor.
    let session_config = state.session_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "sessions not configured".into(),
        ))
    })?;

    let actor = noombat_identity::repo::find_by_id(&state.pool, result.actor_id).await?;

    let tokens = noombat_identity::session::create_session(
        &state.pool,
        session_config,
        result.actor_id,
        &result.username,
        actor.instance_role,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await?;

    // Set the session cookie and redirect to the home page.
    let cookie = crate::cookie::set_session_cookie(&tokens, &state.domain);
    let mut response = Redirect::temporary("/").into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    Ok(response)
}

// ..... ORCID OAuth .....

async fn orcid_init(State(state): State<AppState>) -> Result<Response, ApiError> {
    let orcid_config = state.orcid_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "ORCID not configured".into(),
        ))
    })?;

    let (url, _state_token) = noombat_identity::oauth_orcid::build_authorise_url(
        &state.pool,
        orcid_config,
        &state.domain,
        None,
    )
    .await?;

    Ok(Redirect::temporary(&url).into_response())
}

/// `GET /api/v1/auth/orcid/link`
///
/// As `orcid_init`, but bound to the signed-in account so the callback
/// links rather than creating.
async fn orcid_link_init(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<Response, ApiError> {
    let actor_id = require_actor(&viewer)?;
    let orcid_config = state.orcid_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "ORCID not configured".into(),
        ))
    })?;

    let (url, _state_token) = noombat_identity::oauth_orcid::build_authorise_url(
        &state.pool,
        orcid_config,
        &state.domain,
        Some(actor_id),
    )
    .await?;

    Ok(Redirect::temporary(&url).into_response())
}

async fn orcid_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    let orcid_config = state.orcid_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "ORCID not configured".into(),
        ))
    })?;

    let result = noombat_identity::oauth_orcid::handle_callback(
        &state.pool,
        &state.http_client,
        orcid_config,
        &state.domain,
        &query.code,
        &query.state,
        state.open_registrations,
    )
    .await?;
    // Linking an iD to an account adds it to the document; a sign-in
    // changes nothing, and its push sends nothing.
    noombat_federation::update::push_actor_document(&state.pool, result.actor_id, &state.domain)
        .await;

    // Optionally import publications in the background, which the
    // document lists once they are public.
    if result.is_new {
        let pool = state.pool.clone();
        let client = state.http_client.clone();
        let orcid = result.orcid.clone();
        let actor_id = result.actor_id;
        let pub_api = orcid_config.pub_api_uri.clone();
        let mailto = state.contact_email.clone();
        let domain = state.domain.clone();
        tokio::spawn(async move {
            if let Err(e) = noombat_identity::orcid_import::import_orcid_scholarly_articles(
                &pool, &client, actor_id, &orcid, &pub_api, &mailto,
            )
            .await
            {
                tracing::warn!(orcid = %orcid, error = %e, "background ORCID import failed");
            }
            noombat_federation::update::push_actor_document(&pool, actor_id, &domain).await;
        });
    }

    let session_config = state.session_config.as_ref().ok_or_else(|| {
        ApiError(NoombatError::ServiceUnavailable(
            "sessions not configured".into(),
        ))
    })?;

    let actor = noombat_identity::repo::find_by_id(&state.pool, result.actor_id).await?;

    let tokens = noombat_identity::session::create_session(
        &state.pool,
        session_config,
        result.actor_id,
        &result.username,
        actor.instance_role,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await?;

    let cookie = crate::cookie::set_session_cookie(&tokens, &state.domain);
    let mut response = Redirect::temporary("/").into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    Ok(response)
}

// ..... Password set/change (OAuth account upgrade) .....

#[derive(Deserialize)]
struct SetPasswordRequest {
    /// The new authentication key (hex-encoded, 32 bytes).
    auth_key: String,
    /// The old authentication key (required when changing, not when
    /// setting for the first time).
    old_auth_key: Option<String>,
    /// The re-encrypted credential blob (required when changing
    /// password if chat has been provisioned). The browser decrypts
    /// the blob with the old key and re-encrypts with the new key
    /// before sending this field.
    chatmail_cred: Option<String>,
    /// The chat setup those credentials belong to, required with them: a
    /// newer setup's would otherwise be replaced by an older one's.
    chat_setup: Option<i64>,
}

async fn set_password(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;

    // Verify the actor exists.
    let has_password = sqlx::query_scalar::<_, Option<bool>>(
        "SELECT auth_key_hash IS NOT NULL FROM actors WHERE id = $1 AND is_local = TRUE",
    )
    .bind(actor_id)
    .fetch_optional(&state.pool)
    .await?
    .flatten()
    .ok_or(ApiError(NoombatError::Forbidden))?;

    if !has_password {
        // Setting a first password, which is an OAuth account adding the
        // second way in. It needs a proved address first: the server keeps
        // only a hash of the auth key and can reset nothing, so enabling
        // password login without one manufactures an account that a
        // forgotten password destroys. Changing an existing password is
        // exempt, because that account was already made recoverable when
        // the password was first set.
        if !noombat_identity::email::has_verified_email(&state.pool, actor_id).await? {
            return Err(ApiError(NoombatError::BadRequest(
                "verify an email address before setting a password".into(),
            )));
        }
    }

    if has_password {
        // Changing: require the old auth key.
        let old_key = req.old_auth_key.as_deref().ok_or_else(|| {
            ApiError(NoombatError::BadRequest(
                "old_auth_key required when changing password".into(),
            ))
        })?;

        noombat_identity::login::verify_auth_key(&state.pool, actor_id, old_key).await?;
    }

    // Hash and store the new key.
    let auth_key = req.auth_key.clone();
    let hash = tokio::task::spawn_blocking(move || {
        noombat_identity::registration::hash_auth_key(&auth_key)
    })
    .await
    .map_err(|e| ApiError(NoombatError::Internal(format!("hash task failed: {e}"))))?
    .map_err(ApiError)?;

    // Decode the re-encrypted blob if provided.
    let blob_bytes: Option<Vec<u8>> = req
        .chatmail_cred
        .as_deref()
        .map(|b64| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(b64)
        })
        .transpose()
        .map_err(|e| {
            ApiError(NoombatError::BadRequest(format!(
                "invalid chatmail_cred base64: {e}"
            )))
        })?;

    let chat_setup = match (&blob_bytes, req.chat_setup) {
        (Some(_), None) => {
            return Err(ApiError(NoombatError::BadRequest(
                "chat_setup must name the setup the credentials belong to".into(),
            )));
        }
        (_, setup) => setup,
    };

    // One statement, the key and the re-encrypted credentials together,
    // and neither when the credentials belong to a setup a newer one
    // replaced, while a setup is under way (it would store credentials
    // under the old password), or when credentials are held and none are
    // sent (they would stay under it). Credentials re-encrypted take a new
    // setup number, returned in the header, so a tab still holding them
    // under the old password has its writes refused rather than undoing
    // this.
    let written: Option<i64> = sqlx::query_scalar(
        "UPDATE actors SET auth_key_hash = $1, \
             chatmail_cred = COALESCE($2, chatmail_cred), \
             chat_setup_generation = chat_setup_generation \
                 + CASE WHEN $2::bytea IS NULL THEN 0 ELSE 1 END \
         WHERE id = $3 \
           AND ($2::bytea IS NULL OR chat_setup_generation = $4) \
           AND ($2::bytea IS NOT NULL OR chatmail_cred IS NULL) \
           AND (chat_setup_until IS NULL OR chat_setup_until < now()) \
         RETURNING chat_setup_generation",
    )
    .bind(&hash)
    .bind(&blob_bytes)
    .bind(actor_id)
    .bind(chat_setup)
    .fetch_optional(&state.pool)
    .await?;
    let Some(generation) = written else {
        let held: bool =
            sqlx::query_scalar("SELECT chatmail_cred IS NOT NULL FROM actors WHERE id = $1")
                .bind(actor_id)
                .fetch_one(&state.pool)
                .await?;
        return Err(ApiError(if blob_bytes.is_none() && held {
            NoombatError::BadRequest(
                "chatmail_cred required: the chat credentials must be re-encrypted".into(),
            )
        } else {
            NoombatError::Conflict(
                "chat is being set up, or was set up again, in another tab or on another device"
                    .into(),
            )
        }));
    };

    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        crate::routes::chat::CHAT_SETUP,
        axum::http::HeaderValue::from(generation),
    );
    Ok(response)
}

// ..... Chatmail provisioning .....

#[derive(Deserialize, Default)]
struct ProvisionChatRequest {
    auth_key: Option<String>,
}

#[derive(Serialize)]
struct ProvisionChatResponse {
    chatmail_addr: String,
    chatmail_password: String,
    /// The setup's number, which storing the credentials and publishing
    /// the key must name.
    chat_setup: i64,
}

/// `POST /api/v1/me/provision_chat`
///
/// Provision a Chatmail account for the authenticated user: the sidecar
/// creates the account, one IMAP login proves it, and the address is
/// stored on the actor record. The member sends their password's auth key,
/// `{"auth_key": ...}`, so neither a stolen session nor a mistyped
/// password can set chat up; an account without a password sets one
/// first, since chat's credentials are kept under it.
///
/// The response includes the Chatmail address and password, and the
/// setup's number, `chat_setup`. The browser is responsible for
/// generating an OpenPGP key pair, building the credential blob,
/// encrypting it with the blob key (derived from the user's password),
/// and storing it via `PUT /api/v1/me/chatmail_cred`, naming that setup.
/// A second setup while one is under way is refused, and only the newest
/// setup's credentials and key can be stored.
///
/// Returns 409 if chat is already set up and usable, as when another tab
/// has just set it up, or while another setup is under way; 429 within a
/// minute of a setup that reached the relay; 403 for a password that does
/// not prove the member, or an account that may not chat.
/// Returns 503 if Chatmail is not configured on this instance.
async fn provision_chat(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    body: axum::body::Bytes,
) -> Result<Json<ProvisionChatResponse>, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let req: ProvisionChatRequest = if body.is_empty() {
        ProvisionChatRequest::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError(NoombatError::BadRequest(format!("invalid request: {e}"))))?
    };
    // Only a member who may chat, proving it with their password: the
    // check refuses any account that may not sign in, and one with no
    // password.
    let may_chat: bool = sqlx::query_scalar(
        "SELECT actor_status IN ('active', 'silenced') FROM actors WHERE id = $1",
    )
    .bind(viewer.actor_id)
    .fetch_one(&state.pool)
    .await?;
    if !may_chat {
        return Err(ApiError(NoombatError::Forbidden));
    }
    let auth_key = req
        .auth_key
        .ok_or_else(|| ApiError(NoombatError::BadRequest("auth_key required".into())))?;
    noombat_identity::login::verify_auth_key(&state.pool, viewer.actor_id, &auth_key).await?;
    let actor_id = viewer.actor_id;
    let username = viewer.username.as_str();

    // A member with an address sets chat up again only when it is unusable:
    // their credential blob never arrived, or a suspension rotated the
    // Chatmail password it holds. The mailbox is kept and given a new
    // password; the old key, whose private half went with the old setup,
    // is no longer published.
    //
    // Without the sidecar there is no way to create an account: the relay
    // only verifies logins. Refusing keeps an unconfigured deployment from
    // quietly falling back to a login-only path.
    let admin = state.chatmail_admin_client.clone();
    let chatmail_domain = state.chatmail_domain.clone();
    let username = username.to_owned();
    let setup = noombat_chat::keys::set_up(
        &state.pool,
        actor_id,
        noombat_chat::keys::RELAY_TIMEOUT,
        |address| async move {
            let admin = admin.ok_or_else(|| {
                NoombatError::ServiceUnavailable(
                    "chatmail admin sidecar not configured on this instance".into(),
                )
            })?;
            if let Some(address) = address {
                let rotated = admin.rotate_password(&address).await?;
                return Ok((address, rotated.password));
            }
            let chatmail_domain = chatmail_domain.ok_or_else(|| {
                NoombatError::ServiceUnavailable("chatmail not configured on this instance".into())
            })?;
            let provisioned = noombat_chat::provision::provision_chatmail_account(
                &admin,
                &chatmail_domain,
                &username,
            )
            .await?;
            Ok((provisioned.address, provisioned.password))
        },
    )
    .await;
    // Pushed whatever the outcome: a setup that failed after its claim had
    // already forgotten the key the member published.
    noombat_federation::update::push_actor_document(&state.pool, actor_id, &state.domain).await;
    let setup = setup?;

    Ok(Json(ProvisionChatResponse {
        chatmail_addr: setup.address,
        chatmail_password: setup.password,
        chat_setup: setup.generation,
    }))
}

// ..... Chatmail credential blob .....

/// `GET /api/v1/me/chatmail_cred`
///
/// Returns the encrypted credential blob as raw bytes
/// (`application/octet-stream`), with the number of the setup it belongs
/// to in the `Noombat-Chat-Setup` header. Returns 404 if no blob exists.
async fn get_chatmail_cred(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<Response, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;

    let (blob, generation) = noombat_chat::keys::credentials(&state.pool, actor_id).await?;

    match blob {
        Some(bytes) => {
            let mut response = bytes.into_response();
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/octet-stream"),
            );
            // Named back by every later write of the credentials or key.
            response.headers_mut().insert(
                crate::routes::chat::CHAT_SETUP,
                axum::http::HeaderValue::from(generation),
            );
            Ok(response)
        }
        None => Err(ApiError(NoombatError::ActorNotFound(
            "chatmail_cred not set".into(),
        ))),
    }
}

/// `PUT /api/v1/me/chatmail_cred`
///
/// Stores the encrypted credential blob (raw bytes from the request
/// body). Maximum size: 64 KiB. The `Noombat-Chat-Setup` header names the
/// setup it belongs to; 409 once a newer setup has replaced that one.
///
/// **Note on envelope encryption:** This column is *not* envelope-
/// encrypted at the server layer because the blob is already
/// encrypted client-side with the user's password-derived blob key
/// before transmission. The server stores opaque ciphertext.
async fn put_chatmail_cred(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;

    const MAX_BLOB_SIZE: usize = 65_536;
    if body.len() > MAX_BLOB_SIZE {
        return Err(ApiError(NoombatError::BadRequest(format!(
            "blob exceeds maximum size of {MAX_BLOB_SIZE} bytes"
        ))));
    }

    // A tab holding an older setup's credentials must not replace the
    // newest's, whose relay password they do not hold.
    let generation = crate::routes::chat::chat_setup(&headers)?;
    noombat_chat::keys::store_credentials(&state.pool, actor_id, generation, &body).await?;

    Ok(StatusCode::NO_CONTENT)
}
