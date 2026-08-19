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
///
/// `I18n` implements [`axum::extract::FromRequestParts`], so handlers
/// may receive it as an extractor parameter:
///
/// ```ignore
/// async fn my_handler(i18n: I18n) -> impl IntoResponse { ... }
/// ```
///
/// The locale is negotiated from the `Accept-Language` header on every
/// request, falling back to [`DEFAULT_LOCALE`].
#[derive(Clone)]
pub struct I18n {
    /// The BCP 47 locale tag (e.g. `"pt-BR"`).
    pub locale: String,
}

// Axum extractor: negotiate locale from the request headers.
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for I18n {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(I18n {
            locale: negotiate_locale(&parts.headers),
        })
    }
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
    /// Returns the full negotiated locale (e.g. `"en-US"`, `"pt-BR"`).
    pub fn lang_attr(&self) -> &str {
        &self.locale
    }

    /// The value for the HTML `dir` attribute.
    ///
    /// Templates pair this with logical-property utilities (`ms-`, `pe-`,
    /// `text-start`), which follow it; a physical `ml-` would not.
    ///
    /// Every locale in [`AVAILABLE_LOCALES`] is left-to-right, so this
    /// returns `ltr` for anything the instance currently serves.
    pub fn dir_attr(&self) -> &'static str {
        if is_rtl(&self.locale) { "rtl" } else { "ltr" }
    }
}

/// Whether a BCP 47 tag names a right-to-left script.
///
/// Decided on the primary language subtag, which is what a tag like
/// `ar-EG` or `he` carries. An explicit script subtag wins where one is
/// present, because `uz-Arab` is right-to-left while `uz` is not.
fn is_rtl(tag: &str) -> bool {
    const RTL_LANGUAGES: &[&str] = &[
        "ar", "arc", "ckb", "dv", "fa", "he", "khw", "ks", "ps", "sd", "ur", "yi",
    ];
    const RTL_SCRIPTS: &[&str] = &["arab", "hebr", "thaa", "syrc", "nkoo", "adlm"];

    let mut parts = tag.split('-');
    let Some(language) = parts.next() else {
        return false;
    };

    if parts.any(|part| RTL_SCRIPTS.contains(&part.to_ascii_lowercase().as_str())) {
        return true;
    }

    RTL_LANGUAGES.contains(&language.to_ascii_lowercase().as_str())
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
                    p.strip_prefix("q=").and_then(|q| q.parse::<f32>().ok())
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

    fn dir_of(locale: &str) -> &'static str {
        I18n {
            locale: locale.to_owned(),
        }
        .dir_attr()
    }

    // ..... Direction .....

    /// Every locale the instance actually offers, so the attribute the
    /// product serves today is asserted rather than inferred.
    #[test]
    fn every_available_locale_is_left_to_right() {
        for locale in AVAILABLE_LOCALES {
            assert_eq!(dir_of(locale), "ltr", "{locale}");
        }
    }

    /// The point of deriving the attribute. Without these, `dir_attr`
    /// could return a constant and pass the test above.
    #[test]
    fn a_right_to_left_language_is_detected_from_its_tag() {
        for locale in [
            "ar", "ar-EG", "he", "he-IL", "fa-IR", "ur", "ps", "ckb", "dv", "yi",
        ] {
            assert_eq!(dir_of(locale), "rtl", "{locale}");
        }
    }

    /// A script subtag decides where the language alone does not: the
    /// same language is written both ways.
    #[test]
    fn a_script_subtag_decides_where_the_language_does_not() {
        assert_eq!(dir_of("uz-Arab"), "rtl");
        assert_eq!(dir_of("uz-Latn"), "ltr");
        assert_eq!(dir_of("sr-Cyrl"), "ltr");
    }

    /// A tag that merely begins with the letters of one is not one.
    #[test]
    fn a_tag_is_not_matched_on_a_prefix() {
        for locale in ["arn", "hel", "urd-x", "fake", ""] {
            assert_eq!(dir_of(locale), "ltr", "{locale}");
        }
    }

    #[test]
    fn the_tag_is_matched_without_regard_to_case() {
        assert_eq!(dir_of("AR-eg"), "rtl");
        assert_eq!(dir_of("uz-ARAB"), "rtl");
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

    #[test]
    fn lang_attr_returns_full_bcp47_tag() {
        let i18n = I18n {
            locale: "pt-BR".to_owned(),
        };
        assert_eq!(i18n.lang_attr(), "pt-BR");

        let i18n_en = I18n {
            locale: "en-US".to_owned(),
        };
        assert_eq!(i18n_en.lang_attr(), "en-US");
    }
}
