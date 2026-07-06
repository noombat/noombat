// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! DOI detection in text content.
//!
//! Recognises two forms:
//! - `https://doi.org/10.xxxx/...`
//! - `doi:10.xxxx/...`

use regex::Regex;
use std::sync::LazyLock;

/// A DOI reference detected in user-authored text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoiReference {
    /// The bare DOI string, e.g. `10.1000/xyz123`.
    pub doi: String,
    /// The full URI as it appeared in the source text.
    pub source_uri: String,
}

/// Regex matching DOI URIs in text.
///
/// Covers:
/// - `https://doi.org/10.xxxx/...`
/// - `http://doi.org/10.xxxx/...`
/// - `doi:10.xxxx/...`
///
/// The DOI itself (the `10.xxxx/...` part) is captured in group 1.
/// DOI syntax: `10.` followed by a registrant code (digits), then `/`,
/// then a suffix of non-whitespace characters.
static DOI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:https?://doi\.org/|doi:)(10\.\d{4,}/[^\s),]+)").unwrap());

/// Detect DOI references in a text fragment.
pub fn detect_in_text(text: &str) -> Vec<DoiReference> {
    DOI_RE
        .captures_iter(text)
        .map(|cap| {
            let full_match = cap.get(0).unwrap().as_str();
            let doi = cap.get(1).unwrap().as_str();
            // Strip trailing punctuation that is unlikely to be part of
            // the DOI (period, comma, semicolon, closing parenthesis).
            let doi = doi.trim_end_matches(['.', ',', ';', ')']);
            let source_uri = full_match.trim_end_matches(['.', ',', ';', ')']);
            DoiReference {
                doi: doi.to_owned(),
                source_uri: source_uri.to_owned(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_doi_org() {
        let refs = detect_in_text("See https://doi.org/10.1000/xyz123 for details.");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].doi, "10.1000/xyz123");
    }

    #[test]
    fn doi_scheme() {
        let refs = detect_in_text("Published as doi:10.1038/nature12373.");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].doi, "10.1038/nature12373");
    }

    #[test]
    fn multiple_dois() {
        let text = "Refs: https://doi.org/10.1000/a and doi:10.2000/b.";
        let refs = detect_in_text(text);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].doi, "10.1000/a");
        assert_eq!(refs[1].doi, "10.2000/b");
    }

    #[test]
    fn no_doi() {
        let refs = detect_in_text("No DOI here.");
        assert!(refs.is_empty());
    }

    #[test]
    fn trailing_punctuation_stripped() {
        let refs = detect_in_text("(doi:10.1000/xyz).");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].doi, "10.1000/xyz");
        assert_eq!(refs[0].source_uri, "doi:10.1000/xyz");
    }

    #[test]
    fn source_uri_consistent_with_doi() {
        let refs = detect_in_text("See https://doi.org/10.1000/abc123.");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].doi, "10.1000/abc123");
        assert_eq!(
            refs[0].source_uri, "https://doi.org/10.1000/abc123",
            "source_uri must not retain trailing punctuation stripped from doi"
        );
    }
}
