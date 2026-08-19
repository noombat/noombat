// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Appearance preferences: colour theme, and contrast.
//!
//! Each is carried in a cookie and rendered onto the root element as a
//! `data-` attribute, which the stylesheet resolves with no script, so
//! the first paint is already the chosen palette.
//!
//! They belong to a browser rather than to an account, so they are
//! readable without a session and are never stored against an actor.
//!
//! The two are separate axes: high contrast applies to light and dark
//! alike, so folding them into one setting would make four of the six
//! combinations unreachable.

use axum::http::{HeaderMap, HeaderValue};

/// Cookie carrying the chosen theme.
pub const COOKIE_NAME: &str = "noombat_theme";

/// Cookie carrying the chosen contrast.
pub const CONTRAST_COOKIE_NAME: &str = "noombat_contrast";

/// One year, so the choice outlives a browsing session.
const MAX_AGE_SECONDS: u32 = 31_536_000;

/// A reader's colour theme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    /// Follow the operating system, through `prefers-color-scheme`.
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    /// The value rendered into the `data-theme` attribute, and the value
    /// stored in the cookie. One spelling for both, so a round trip
    /// cannot drift.
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    /// Anything unrecognised is [`Theme::System`]: a stale, truncated or
    /// hand-written cookie degrades to the default rather than failing a
    /// page load over a colour.
    pub fn parse(value: &str) -> Self {
        match value {
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => Theme::System,
        }
    }
}

/// A reader's contrast setting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Contrast {
    #[default]
    Standard,
    /// The palette tuned for WCAG AAA, which
    /// `scripts/check-contrast.py` measures on every run.
    High,
}

impl Contrast {
    /// The value rendered into the `data-contrast` attribute, and the
    /// value stored in the cookie.
    pub fn as_str(self) -> &'static str {
        match self {
            Contrast::Standard => "standard",
            Contrast::High => "high",
        }
    }

    /// Anything unrecognised is [`Contrast::Standard`].
    pub fn parse(value: &str) -> Self {
        match value {
            "high" => Contrast::High,
            _ => Contrast::Standard,
        }
    }
}

/// The value of `name` among a request's cookies.
fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, value)| value)
}

/// Read the theme from a request's `Cookie` header.
pub fn from_headers(headers: &HeaderMap) -> Theme {
    cookie_value(headers, COOKIE_NAME)
        .map(Theme::parse)
        .unwrap_or_default()
}

/// Read the contrast setting from a request's `Cookie` header.
pub fn contrast_from_headers(headers: &HeaderMap) -> Contrast {
    cookie_value(headers, CONTRAST_COOKIE_NAME)
        .map(Contrast::parse)
        .unwrap_or_default()
}

/// Build a `Set-Cookie` header value recording the choice.
///
/// `HttpOnly` because only the server reads it, `SameSite=Lax` so a
/// cross-site form cannot change it, and `Secure` off for `localhost`
/// alone, matching the session cookie.
pub fn set_theme_cookie(theme: Theme, domain: &str) -> HeaderValue {
    preference_cookie(COOKIE_NAME, theme.as_str(), domain)
}

/// Build a `Set-Cookie` header value recording the contrast setting.
pub fn set_contrast_cookie(contrast: Contrast, domain: &str) -> HeaderValue {
    preference_cookie(CONTRAST_COOKIE_NAME, contrast.as_str(), domain)
}

fn preference_cookie(name: &str, value: &str, domain: &str) -> HeaderValue {
    let secure = if domain == "localhost" {
        ""
    } else {
        "; Secure"
    };
    let cookie = format!(
        "{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={MAX_AGE_SECONDS}{secure}"
    );
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Theme {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(from_headers(&parts.headers))
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Contrast {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(contrast_from_headers(&parts.headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn parse_round_trips_every_variant() {
        for theme in [Theme::System, Theme::Light, Theme::Dark] {
            assert_eq!(Theme::parse(theme.as_str()), theme);
        }
    }

    #[test]
    fn unrecognised_values_fall_back_to_system() {
        for value in ["", "Dark", "solarized", "dark; Path=/", "light "] {
            assert_eq!(Theme::parse(value), Theme::System, "{value:?}");
        }
    }

    #[test]
    fn reads_the_theme_from_among_other_cookies() {
        let headers = headers_with_cookie("noombat_session=abc; noombat_theme=dark; other=1");
        assert_eq!(from_headers(&headers), Theme::Dark);
    }

    #[test]
    fn reads_the_theme_when_it_is_the_only_cookie() {
        assert_eq!(
            from_headers(&headers_with_cookie("noombat_theme=light")),
            Theme::Light
        );
    }

    #[test]
    fn a_cookie_whose_name_merely_ends_in_the_theme_name_is_not_the_theme() {
        let headers = headers_with_cookie("not_noombat_theme=dark");
        assert_eq!(from_headers(&headers), Theme::System);
    }

    #[test]
    fn absent_header_is_system() {
        assert_eq!(from_headers(&HeaderMap::new()), Theme::System);
    }

    #[test]
    fn cookie_carries_the_value_and_the_hardening_attributes() {
        let cookie = set_theme_cookie(Theme::Dark, "example.org");
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("noombat_theme=dark;"), "{cookie}");
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        assert!(cookie.contains("Path=/"), "{cookie}");
        assert!(cookie.contains("; Secure"), "{cookie}");
    }

    #[test]
    fn localhost_drops_secure_so_development_over_http_works() {
        let cookie = set_theme_cookie(Theme::Light, "localhost");
        assert!(!cookie.to_str().unwrap().contains("Secure"));
    }

    #[test]
    fn contrast_parse_round_trips_every_variant() {
        for contrast in [Contrast::Standard, Contrast::High] {
            assert_eq!(Contrast::parse(contrast.as_str()), contrast);
        }
    }

    #[test]
    fn unrecognised_contrast_values_fall_back_to_standard() {
        for value in ["", "High", "higher", "aaa"] {
            assert_eq!(Contrast::parse(value), Contrast::Standard, "{value:?}");
        }
    }

    /// The two preferences are independent, and a reader who has set
    /// both must get both.
    #[test]
    fn theme_and_contrast_are_read_from_the_same_header_without_colliding() {
        let headers =
            headers_with_cookie("noombat_theme=dark; noombat_session=x; noombat_contrast=high");
        assert_eq!(from_headers(&headers), Theme::Dark);
        assert_eq!(contrast_from_headers(&headers), Contrast::High);
    }

    #[test]
    fn one_preference_set_does_not_imply_the_other() {
        let headers = headers_with_cookie("noombat_contrast=high");
        assert_eq!(from_headers(&headers), Theme::System);
        assert_eq!(contrast_from_headers(&headers), Contrast::High);
    }

    #[test]
    fn the_contrast_cookie_carries_the_same_hardening_as_the_theme_cookie() {
        let cookie = set_contrast_cookie(Contrast::High, "example.org");
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("noombat_contrast=high;"), "{cookie}");
        for attribute in ["HttpOnly", "SameSite=Lax", "Path=/", "; Secure"] {
            assert!(
                cookie.contains(attribute),
                "{attribute} missing from {cookie}"
            );
        }
    }

    #[test]
    fn a_cookie_written_by_this_module_is_read_back_by_it() {
        let cookie = set_theme_cookie(Theme::Dark, "localhost");
        let pair = cookie
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(from_headers(&headers_with_cookie(&pair)), Theme::Dark);
    }
}
