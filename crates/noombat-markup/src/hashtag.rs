// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Hashtag extraction from text content.

use regex::Regex;
use std::sync::LazyLock;

/// Regex for matching hashtags in text (Unicode-aware).
///
/// The hashtag must be preceded by whitespace or the start of the string.
static HASHTAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)#([A-Za-z]\w{0,99})").unwrap());

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
        // `#123` starts with a digit, so the regex requires `[A-Za-z]`
        // as the first character.
        let tags = extract("#123");
        assert!(tags.is_empty());
    }

    #[test]
    fn long_hashtag_truncated() {
        // Tags longer than 100 characters are not matched.
        let long_tag = format!("#{}", "a".repeat(101));
        let tags = extract(&long_tag);
        assert!(tags.is_empty());
    }
}
