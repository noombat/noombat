// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Refusing forged writes: a request the session cookie authenticates
//! changes nothing unless it comes from this instance's own pages.
//!
//! `SameSite=Lax` keeps the cookie off other sites' posts, but a page on a
//! sibling subdomain is same-site, and its posts carry the cookie. So such
//! a write must pass two independent checks: the browser's account of
//! where it came from, and a token kept with the session that only this
//! instance's pages hold. Bearer-token clients carry no ambient credential
//! and pass through.

use askama::Template;
use askama_web::WebTemplate;
use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, Multipart, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ORIGIN, UPGRADE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use noombat_ap::error_body::ApError;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::ApiError;
use crate::i18n::{I18n, negotiate_locale};
use crate::state::AppState;
use crate::theme::{Contrast, Theme};

/// The header htmx and the front end send the token in.
pub const HEADER: &str = "x-csrf-token";

/// The field a plain form sends the token in.
pub const FIELD: &str = "csrf_token";

/// The header marking a refusal of an htmx write, whose text the page
/// shows.
pub const REFUSED_HEADER: &str = "x-csrf-refused";

/// The chat WebSocket, whose handshake carries the session cookie and
/// cannot carry a header.
const CHAT_SOCKET: &str = "/api/v1/chat/ws";

/// The largest url-encoded body read for its token: axum's own limit for
/// a form, which the route's extractor applies anyway.
const FORM_LIMIT: usize = 2 * 1024 * 1024;

/// Set by the authentication middleware on a request whose viewer the
/// session cookie names: the session's id, if its access token names one.
#[derive(Clone, Copy, Debug)]
pub struct CookieSession {
    pub session_id: Option<Uuid>,
}

/// The session's token, masked afresh for this answer, for a page to
/// carry; none for a visitor whose request carries no session cookie.
pub struct CsrfToken(Option<String>);

impl CsrfToken {
    /// A page rendered with no session, which carries no token.
    pub fn absent() -> Self {
        Self(None)
    }

    pub fn value(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl FromRequestParts<AppState> for CsrfToken {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(CookieSession {
            session_id: Some(id),
        }) = parts.extensions.get::<CookieSession>().copied()
        else {
            return Ok(Self(None));
        };
        let token = noombat_identity::session::csrf_token(&state.pool, id)
            .await
            .ok()
            .flatten()
            .and_then(|token| noombat_identity::session::mask_csrf_token(&token));
        Ok(Self(token))
    }
}

/// Axum middleware, inside [`crate::middleware::authentication`].
pub async fn protect(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(session) = request.extensions().get::<CookieSession>().copied() else {
        return next.run(request).await;
    };
    let headers = request.headers().clone();
    let websocket = request.method() == Method::GET
        && request.uri().path() == CHAT_SOCKET
        && headers
            .get(UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if !websocket && !crate::middleware::acts_as_viewer(&request) {
        return private(next.run(request).await);
    }

    if !from_own_pages(&state, &headers) {
        return refuse(&headers, Refusal::Elsewhere);
    }
    // A browser cannot add a header to the handshake, and the check
    // above holds there: browsers always send `Origin` with it.
    if websocket {
        return next.run(request).await;
    }

    let (request, sent) = match token_of(request).await {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let Some(session_id) = session.session_id else {
        return refuse(&headers, Refusal::SignInAgain);
    };
    let expected = match noombat_identity::session::csrf_token(&state.pool, session_id).await {
        Ok(expected) => expected,
        Err(error) => return ApiError(error).into_response(),
    };
    let sent = sent
        .as_deref()
        .and_then(noombat_identity::session::unmask_csrf_token);
    match (sent, expected) {
        (Some(sent), Some(expected)) if bool::from(sent.as_bytes().ct_eq(expected.as_bytes())) => {
            private(next.run(request).await)
        }
        _ => refuse(&headers, Refusal::Token),
    }
}

/// An answer to a session can carry its token or the member's own data,
/// so no cache may keep it, unless its route says otherwise, as the hashed
/// assets and public media do.
fn private(mut response: Response) -> Response {
    if !response.headers().contains_key(CACHE_CONTROL) {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    }
    response
}

/// Where the browser says the request came from: with `Sec-Fetch-Site`,
/// this instance's own origin only; without it, an `Origin` that is this
/// instance's. A request with neither is not a browser's, or is an old
/// one's, and is left to the token.
pub(crate) fn from_own_pages(state: &AppState, headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return site == "same-origin";
    }
    headers.get(ORIGIN).is_none_or(|origin| {
        origin.as_bytes()
            == crate::middleware::http_origin(
                &state.domain,
                state.public_port,
                state.public_origin.as_deref(),
            )
            .as_bytes()
    })
}

/// As [`from_own_pages`], but a request saying neither where it came from
/// is refused too: for a request no session's token backs, as a sign-in's
/// start, only the browser's own account counts.
pub(crate) fn shown_from_own_pages(state: &AppState, headers: &HeaderMap) -> bool {
    (headers.contains_key("sec-fetch-site") || headers.contains_key(ORIGIN))
        && from_own_pages(state, headers)
}

#[derive(Deserialize)]
struct TokenField {
    csrf_token: Option<String>,
}

/// The token a request carries, in the header or, from a plain form, in
/// its field. A form's body is read whole and handed on unchanged.
async fn token_of(request: Request<Body>) -> Result<(Request<Body>, Option<String>), StatusCode> {
    if let Some(sent) = request.headers().get(HEADER) {
        let sent = sent.to_str().ok().map(str::to_owned);
        return Ok((request, sent));
    }
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let form = content_type.starts_with("application/x-www-form-urlencoded");
    let multipart = content_type.starts_with("multipart/form-data");
    if !form && !multipart {
        return Ok((request, None));
    }

    // A multipart form's token is read before any part past axum's own 2 MiB
    // limit: the pages put the field first.
    let limit = if form {
        FORM_LIMIT
    } else {
        crate::media::MAX_UPLOAD_BYTES
    };
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    // POST, whatever the original's method: `Form` reads a GET's query
    // string rather than its body.
    let copy = || {
        Request::builder()
            .method(Method::POST)
            .header(CONTENT_TYPE, content_type.as_str())
            .body(Body::from(bytes.clone()))
            .unwrap_or_default()
    };
    let sent = if form {
        Form::<TokenField>::from_request(copy(), &())
            .await
            .ok()
            .and_then(|Form(field)| field.csrf_token)
    } else {
        multipart_token(copy()).await
    };
    Ok((Request::from_parts(parts, Body::from(bytes)), sent))
}

/// The token field of a multipart form.
async fn multipart_token(request: Request<Body>) -> Option<String> {
    let mut form = Multipart::from_request(request, &()).await.ok()?;
    while let Some(field) = form.next_field().await.ok()? {
        if field.name() == Some(FIELD) {
            return field.text().await.ok();
        }
    }
    None
}

/// Why a write was refused.
#[derive(Clone, Copy)]
enum Refusal {
    /// The browser says it came from another site.
    Elsewhere,
    /// It carried no token, or not this session's.
    Token,
    /// Its access token names no session.
    SignInAgain,
}

impl Refusal {
    fn message_key(self) -> &'static str {
        match self {
            Self::Elsewhere | Self::Token => "csrf_refused",
            Self::SignInAgain => "csrf_sign_in_again",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::Elsewhere => "this request did not come from this instance's own pages",
            Self::Token => "this request carried no valid CSRF token",
            Self::SignInAgain => "this session predates a security update: sign in again",
        }
    }
}

/// The page a browser's own form post is refused with.
#[derive(Template, WebTemplate)]
#[template(path = "refused.html")]
struct RefusedPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    csrf: CsrfToken,
    title: String,
    message: String,
    back_href: &'static str,
    back_label: String,
}

/// A refusal as a page, in the asker's language and theme: its title and
/// message, and a link on, by their translation keys.
pub(crate) fn refused_page(
    headers: &HeaderMap,
    title_key: &str,
    message_key: &str,
    back: (&'static str, &str),
) -> Response {
    let i18n = I18n {
        locale: negotiate_locale(headers),
    };
    let page = RefusedPage {
        theme: crate::theme::from_headers(headers),
        contrast: crate::theme::contrast_from_headers(headers),
        csrf: CsrfToken::absent(),
        title: i18n.t(title_key),
        message: i18n.t(message_key),
        back_href: back.0,
        back_label: i18n.t(back.1),
        i18n,
    };
    (StatusCode::FORBIDDEN, page).into_response()
}

/// Refused as coming from elsewhere, in the form its asker reads.
pub(crate) fn refused_elsewhere(headers: &HeaderMap) -> Response {
    refuse(headers, Refusal::Elsewhere)
}

/// Refused, in the form the asker reads: htmx gets the message as text,
/// which the page shows; a browser's own form post gets a page saying it;
/// an API client gets the error document.
fn refuse(headers: &HeaderMap, refusal: Refusal) -> Response {
    let i18n = I18n {
        locale: negotiate_locale(headers),
    };
    let message = i18n.t(refusal.message_key());
    if headers.contains_key("hx-request") {
        let marked = [
            (REFUSED_HEADER, "1"),
            (CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
        ];
        return (StatusCode::FORBIDDEN, marked, message).into_response();
    }
    let wants_page = headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"));
    if wants_page {
        return refused_page(
            headers,
            "csrf_refused_title",
            refusal.message_key(),
            ("/", "csrf_refused_home"),
        );
    }
    (
        StatusCode::FORBIDDEN,
        Json(ApError::bad_request(refusal.detail())),
    )
        .into_response()
}
