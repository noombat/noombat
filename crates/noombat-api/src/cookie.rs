// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Session cookie helpers.
//!
//! Provides functions to build `Set-Cookie` headers for setting and
//! clearing the session cookie. The cookie carries the JWT access token
//! so that server-rendered page loads and HTMX partial requests are
//! automatically authenticated (browsers send cookies with every
//! same-origin request).

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use noombat_identity::oauth_util::STATE_LIFETIME_SECS;
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

/// Cookie name tying an OAuth flow to the browser that started it: it
/// holds the flow's state, which the callback must find there. A browser
/// starting a second flow keeps only the newer one.
pub const OAUTH_COOKIE_NAME: &str = "__Host-noombat_oauth";

/// Build a `Set-Cookie` header value holding `state`, for as long as the
/// state lasts. `SameSite=Lax`, since the provider's redirect back is a
/// top-level navigation from another site; the rest as for the session.
pub fn set_oauth_cookie(state: &str) -> HeaderValue {
    let max_age = STATE_LIFETIME_SECS;
    let value = format!(
        "{OAUTH_COOKIE_NAME}={state}; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age={max_age}"
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Build a `Set-Cookie` header value that clears the OAuth flow's cookie.
pub fn clear_oauth_cookie() -> HeaderValue {
    let value = format!("{OAUTH_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=0");
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The value of the one cookie named `name`, read from every `Cookie`
/// header, as HTTP/2 may send each cookie in one of its own. None if there
/// is none or more than one: taking the first would let the order the
/// browser sends them in, which a cookie set elsewhere can arrange, decide.
/// A cookie that is not valid text, as one a sibling site sets on the
/// parent domain may be, is skipped alone, not with its whole header.
/// Only the header's own spaces and tabs are trimmed: a name beginning with
/// another kind of space escaped the browser's `__Host-` check and is not
/// this cookie.
pub fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    let mut held = headers
        .get_all(COOKIE)
        .iter()
        .flat_map(|v| v.as_bytes().split(|b| *b == b';'))
        .filter_map(|c| std::str::from_utf8(c).ok())
        .filter_map(|c| c.trim_matches([' ', '\t']).strip_prefix(prefix.as_str()));
    match (held.next(), held.next()) {
        (Some(value), None) => Some(value),
        _ => None,
    }
}

/// The OAuth state the browser's cookie holds.
pub fn oauth_state(headers: &HeaderMap) -> Option<&str> {
    single(headers, OAUTH_COOKIE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every header meets what the `__Host-` prefix requires, or a browser
    /// drops the cookie (`Secure`, `Path=/`, no `Domain`), and carries its
    /// `SameSite=Lax` and its lifetime.
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
        for (header, name, max_age) in [
            (set_session_cookie(&tokens), COOKIE_NAME, "Max-Age=900"),
            (clear_session_cookie(), COOKIE_NAME, "Max-Age=0"),
            (set_oauth_cookie("state"), OAUTH_COOKIE_NAME, "Max-Age=600"),
            (clear_oauth_cookie(), OAUTH_COOKIE_NAME, "Max-Age=0"),
        ] {
            let header = header.to_str().expect("an ASCII header");
            let attributes: Vec<&str> = header.split("; ").collect();
            assert!(
                header.starts_with(&format!("{name}="))
                    && attributes.contains(&"Secure")
                    && attributes.contains(&"Path=/")
                    && attributes.contains(&"HttpOnly")
                    && attributes.contains(&"SameSite=Lax")
                    && attributes.contains(&max_age)
                    && !header.contains("Domain"),
                "{header}"
            );
        }
    }

    /// The flow's cookie is read when the browser holds exactly one, in one
    /// `Cookie` header or among several; two count as none.
    #[test]
    fn the_flows_cookie_is_read_only_when_single() {
        let headers = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(COOKIE, HeaderValue::from_str(value).expect("a header"));
            }
            headers
        };
        let one = headers(&["a=1; __Host-noombat_oauth=s1; b=2"]);
        let two_in_one = headers(&["__Host-noombat_oauth=s1; __Host-noombat_oauth=s2"]);
        let two_in_two = headers(&["__Host-noombat_oauth=s1", "__Host-noombat_oauth=s2"]);
        let none = headers(&["__Host-noombat_session=jwt"]);
        assert_eq!(oauth_state(&one), Some("s1"));
        assert_eq!(oauth_state(&two_in_one), None);
        assert_eq!(oauth_state(&two_in_two), None);
        assert_eq!(oauth_state(&none), None);
    }

    /// A cookie that is not text, as a sibling site may set on the parent
    /// domain, hides nothing else its header carries.
    #[test]
    fn a_cookie_that_is_not_text_hides_no_other() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_bytes(b"sibling=\xff; __Host-noombat_oauth=s1").expect("a header"),
        );
        assert_eq!(oauth_state(&headers), Some("s1"));
    }

    /// A cookie whose name begins with a space other than the header's own
    /// is not the `__Host-` cookie: the browser saw no prefix on it.
    #[test]
    fn a_name_behind_another_kind_of_space_is_not_the_cookie() {
        for space in ["\u{2000}", "\u{00a0}"] {
            let mut headers = HeaderMap::new();
            let value = format!("{space}__Host-noombat_oauth=planted");
            headers.append(
                COOKIE,
                HeaderValue::from_bytes(value.as_bytes()).expect("a header"),
            );
            assert_eq!(oauth_state(&headers), None, "{space:?}");
        }
    }
}
