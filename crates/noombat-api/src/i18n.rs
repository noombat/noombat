// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Internationalisation: locale negotiation and translation helpers.
//!
//! The [`I18n`] struct is passed to every Askama template. Templates call
//! `{{ i18n.t("key") }}` to render translated strings.

use axum::http::HeaderMap;

/// Available locales, ordered by preference for fallback.
pub const AVAILABLE_LOCALES: &[&str] = &["en-US", "en-AU", "pt-BR"];

/// Default locale when no `Accept-Language` header is present or no
/// supported locale matches.
pub const DEFAULT_LOCALE: &str = "en-US";

/// Translation helper passed to Askama templates.
///
/// Templates use `{{ i18n.t("key") }}` for simple strings and
/// `{{ i18n.tf("key", &[("name", value)]) }}` for interpolated strings.
#[derive(Clone)]
pub struct I18n {
    /// The BCP 47 locale tag (e.g. `"pt-BR"`).
    pub locale: String,
}

impl I18n {
    /// Look up a translated string by key.
    pub fn t(&self, key: &str) -> String {
        rust_i18n::t!(key, locale = self.locale.as_str()).to_string()
    }

    /// Look up a translated string with named interpolation arguments.
    ///
    /// ```ignore
    /// i18n.tf("post_title_pattern", &[("name", "Alice")])
    /// // → "Post by Alice" (en-US)
    /// // → "Publicação de Alice" (pt-BR)
    /// ```
    pub fn tf(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut result = rust_i18n::t!(key, locale = self.locale.as_str()).to_string();
        for (name, value) in args {
            result = result.replace(&format!("%{{{name}}}"), value);
        }
        result
    }

    /// The BCP 47 language tag for the HTML `lang` attribute.
    ///
    /// Returns the lowercase primary subtag (e.g. `"en"` for `"en-US"`,
    /// `"pt"` for `"pt-BR"`).
    pub fn lang_attr(&self) -> &str {
        self.locale.split('-').next().unwrap_or("en")
    }
}

/// Negotiate the best locale from the `Accept-Language` header.
///
/// Parses quality-value pairs (as per: RFC 7231 § 5.3.5; RFC 9110 § 12.5.4),
/// matches against [`AVAILABLE_LOCALES`], and returns the best match.
/// Falls back to [`DEFAULT_LOCALE`] if no match is found.
pub fn negotiate_locale(headers: &HeaderMap) -> String {
    let accept = match headers.get("accept-language") {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return DEFAULT_LOCALE.to_owned(),
        },
        None => return DEFAULT_LOCALE.to_owned(),
    };

    let mut candidates: Vec<(&str, f32)> = accept
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let mut parts = entry.split(';');
            let tag = parts.next()?.trim();
            let quality = parts
                .find_map(|p| {
                    let p = p.trim();
                    p.strip_prefix("q=")
                        .and_then(|q| q.parse::<f32>().ok())
                })
                .unwrap_or(1.0);
            Some((tag, quality))
        })
        .collect();

    // Sort by descending quality.
    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    for (tag, _) in &candidates {
        // Exact match (e.g. "pt-BR" matches "pt-BR").
        for locale in AVAILABLE_LOCALES {
            if tag.eq_ignore_ascii_case(locale) {
                return locale.to_string();
            }
        }
        // Prefix match (e.g. "pt" matches "pt-BR", "en" matches "en-US").
        let primary = tag.split('-').next().unwrap_or(tag);
        for locale in AVAILABLE_LOCALES {
            let locale_primary = locale.split('-').next().unwrap_or(locale);
            if primary.eq_ignore_ascii_case(locale_primary) {
                return locale.to_string();
            }
        }
    }

    DEFAULT_LOCALE.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers_with(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert("accept-language", HeaderValue::from_str(value).unwrap());
        map
    }

    #[test]
    fn exact_match() {
        assert_eq!(negotiate_locale(&headers_with("pt-BR")), "pt-BR");
        assert_eq!(negotiate_locale(&headers_with("en-AU")), "en-AU");
    }

    #[test]
    fn prefix_match() {
        // "pt" should match "pt-BR" (first available pt-* locale).
        assert_eq!(negotiate_locale(&headers_with("pt")), "pt-BR");
        // "en" should match "en-US" (first available en-* locale).
        assert_eq!(negotiate_locale(&headers_with("en")), "en-US");
    }

    #[test]
    fn quality_ordering() {
        // pt-BR at q=0.9 beats en-US at q=0.8.
        let h = headers_with("en-US;q=0.8, pt-BR;q=0.9");
        assert_eq!(negotiate_locale(&h), "pt-BR");
    }

    #[test]
    fn fallback_on_unsupported() {
        assert_eq!(negotiate_locale(&headers_with("ja")), "en-US");
    }

    #[test]
    fn fallback_on_empty() {
        assert_eq!(negotiate_locale(&HeaderMap::new()), "en-US");
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(negotiate_locale(&headers_with("PT-br")), "pt-BR");
        assert_eq!(negotiate_locale(&headers_with("EN-au")), "en-AU");
    }
}
