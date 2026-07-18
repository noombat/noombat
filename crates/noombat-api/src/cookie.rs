// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Session cookie helpers.
//!
//! Provides functions to build `Set-Cookie` headers for setting and
//! clearing the `noombat_session` cookie. The cookie carries the JWT
//! access token so that server-rendered page loads and HTMX partial
//! requests are automatically authenticated (browsers send cookies
//! with every same-origin request).

use axum::http::HeaderValue;
use noombat_identity::session::SessionTokens;

/// Cookie name used for the session JWT.
pub const COOKIE_NAME: &str = "noombat_session";

/// Build a `Set-Cookie` header value that sets the session cookie.
///
/// Attributes:
/// - `HttpOnly`: prevents JavaScript access (the token is also
///   stored in `sessionStorage` for API `fetch` calls, but the
///   cookie path is the authoritative source for page loads).
/// - `SameSite=Lax`: sent on top-level navigations and same-origin
///   requests, protecting against CSRF while allowing OAuth
///   redirects.
/// - `Secure`: sent only over HTTPS (omitted when `domain` is
///   `localhost` for development).
/// - `Path=/`: available to all routes.
/// - `Max-Age`: matches the access-token TTL.
pub fn set_session_cookie(tokens: &SessionTokens, domain: &str) -> HeaderValue {
    let secure = if domain == "localhost" {
        ""
    } else {
        "; Secure"
    };
    let value = format!(
        "{COOKIE_NAME}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{}",
        tokens.access_token, tokens.expires_in, secure,
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn clear_session_cookie(domain: &str) -> HeaderValue {
    let secure = if domain == "localhost" {
        ""
    } else {
        "; Secure"
    };
    let value = format!(
        "{COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{}",
        secure,
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}
