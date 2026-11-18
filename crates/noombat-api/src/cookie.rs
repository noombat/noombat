// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Session cookie helpers.
//!
//! Provides functions to build `Set-Cookie` headers for setting and
//! clearing the session cookie. The cookie carries the JWT access token
//! so that server-rendered page loads and HTMX partial requests are
//! automatically authenticated (browsers send cookies with every
//! same-origin request).

use axum::http::HeaderValue;
use noombat_identity::session::SessionTokens;

/// Cookie name used for the session JWT.
///
/// The `__Host-` prefix makes the browser refuse the cookie unless it is
/// `Secure`, has `Path=/` and names no `Domain`, so a sibling subdomain
/// cannot set one for this host: no page elsewhere on the site can plant
/// its own session under a longer path for this one to send.
pub const COOKIE_NAME: &str = "__Host-noombat_session";

/// Build a `Set-Cookie` header value that sets the session cookie.
///
/// Attributes:
/// - `HttpOnly`: prevents JavaScript access (the token is also
///   stored in `sessionStorage` for API `fetch` calls, but the
///   cookie path is the authoritative source for page loads).
/// - `SameSite=Lax`: sent on top-level navigations and same-origin
///   requests, allowing OAuth redirects; forged writes are refused by
///   [`crate::csrf`].
/// - `Secure` and `Path=/`, with no `Domain`: what the `__Host-` prefix
///   requires. Browsers treat `localhost` as secure, so development over
///   plain HTTP keeps the cookie.
/// - `Max-Age`: matches the access-token TTL.
pub fn set_session_cookie(tokens: &SessionTokens) -> HeaderValue {
    let value = format!(
        "{COOKIE_NAME}={}; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age={}",
        tokens.access_token, tokens.expires_in,
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn clear_session_cookie() -> HeaderValue {
    let value = format!("{COOKIE_NAME}=; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=0");
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both headers meet what the `__Host-` prefix requires, or a browser
    /// drops the cookie: `Secure`, `Path=/`, no `Domain`.
    #[test]
    fn the_cookie_meets_its_prefixs_rules() {
        let tokens = SessionTokens {
            access_token: "jwt".to_owned(),
            refresh_token: "refresh".to_owned(),
            expires_in: 900,
            actor_id: uuid::Uuid::nil(),
            username: "alice".to_owned(),
            csrf_token: "token".to_owned(),
        };
        for header in [set_session_cookie(&tokens), clear_session_cookie()] {
            let header = header.to_str().expect("an ASCII header");
            let attributes: Vec<&str> = header.split("; ").collect();
            assert!(
                header.starts_with("__Host-noombat_session=")
                    && attributes.contains(&"Secure")
                    && attributes.contains(&"Path=/")
                    && attributes.contains(&"HttpOnly")
                    && !header.contains("Domain"),
                "{header}"
            );
        }
    }
}
