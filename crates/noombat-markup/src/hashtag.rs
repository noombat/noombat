// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Hashtag extraction from text content.

use regex::Regex;
use std::sync::LazyLock;

/// Regex for matching hashtags in text (Unicode-aware).
///
/// The hashtag must be preceded by whitespace or the start of the string.
/// The first character must be a Unicode letter (`\p{L}`) so that pure
/// numeric tags like `#123` are excluded. Subsequent characters may be
/// Unicode letters, combining marks, digits, or underscores.
static HASHTAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)#(\p{L}[\p{L}\p{M}\p{N}_]*)").unwrap());

/// Extract hashtags from a text fragment and append them (normalised,
/// lowercase, without the leading `#`) to the output vector.
pub fn extract_from_text(text: &str, out: &mut Vec<String>) {
    for cap in HASHTAG_RE.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let tag = m.as_str().to_lowercase();
            out.push(tag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(input: &str) -> Vec<String> {
        let mut tags = Vec::new();
        extract_from_text(input, &mut tags);
        tags
    }

    #[test]
    fn single_hashtag() {
        assert_eq!(extract("#Rust"), vec!["rust"]);
    }

    #[test]
    fn multiple_hashtags() {
        let tags = extract("#Rust and #ActivityPub are great");
        assert_eq!(tags, vec!["rust", "activitypub"]);
    }

    #[test]
    fn hashtag_mid_sentence() {
        let tags = extract("I love #Rust!");
        assert_eq!(tags, vec!["rust"]);
    }

    #[test]
    fn no_hashtag_in_url() {
        // A `#` inside a URL-like string without preceding whitespace
        // should not match.
        let tags = extract("https://example.com/page#section");
        assert!(tags.is_empty());
    }

    #[test]
    fn numeric_only_not_matched() {
        // `#123` starts with a digit, so the regex requires `\p{L}`
        // (a Unicode letter) as the first character.
        let tags = extract("#123");
        assert!(tags.is_empty());
    }

    #[test]
    fn long_hashtag_accepted() {
        let long_tag = format!("#{}", "a".repeat(256));
        let tags = extract(&long_tag);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].len(), 256);
    }

    // ..... Unicode support .....

    #[test]
    fn cyrillic_hashtag() {
        let tags = extract("#Программирование is programming");
        assert_eq!(tags, vec!["программирование"]);
    }

    #[test]
    fn accented_latin_hashtag() {
        let tags = extract("#Résumé and #naïveté");
        assert_eq!(tags, vec!["résumé", "naïveté"]);
    }

    #[test]
    fn cjk_hashtag() {
        let tags = extract("#日本語 text");
        assert_eq!(tags, vec!["日本語"]);
    }

    #[test]
    fn mixed_script_hashtag() {
        let tags = extract("#Café2Go");
        assert_eq!(tags, vec!["café2go"]);
    }

    #[test]
    fn devanagari_hashtag() {
        let tags = extract("#हिन्दी");
        assert_eq!(tags, vec!["हिन्दी"]);
    }

    #[test]
    fn arabic_hashtag() {
        let tags = extract("#عربي");
        assert_eq!(tags, vec!["عربي"]);
    }

    #[test]
    fn emoji_not_matched() {
        // Emoji are not Unicode letters; a hashtag must start with \p{L}.
        let tags = extract("#🦀rust");
        assert!(tags.is_empty());
    }
}
