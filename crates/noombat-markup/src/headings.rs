// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Heading extraction for table-of-contents generation.
//!
//! Parses a Markdown source string and returns a flat list of headings
//! with their depth, plain-text content, and a URL-safe slug derived
//! from the text. The caller (the article template or route handler)
//! is responsible for assembling the list into a nested structure if
//! desired.

use std::collections::HashMap;

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

/// A single heading extracted from a Markdown document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heading {
    /// Heading depth: 1 for `#`, 2 for `##`, etc.
    pub depth: u8,
    /// Plain-text content of the heading (no markup).
    pub text: String,
    /// URL-safe slug derived from `text`, suitable for use as an HTML
    /// `id` attribute and as an anchor target.
    ///
    /// # Safety (HTML attribute injection)
    ///
    /// The slug alphabet is restricted to ASCII alphanumeric characters
    /// and hyphens by [`slugify`]. It cannot contain `"`, `'`, `<`,
    /// `>`, or `&`, so it is safe to interpolate into an HTML `id`
    /// attribute without additional escaping.
    pub slug: String,
}

/// Extract all headings from a Markdown source string.
///
/// The extraction uses pulldown-cmark's parser in the same mode as
/// the main render pipeline (CommonMark + math + tables +
/// strikethrough + task lists) to ensure heading detection is
/// consistent with the rendered output.
///
/// Duplicate heading texts receive disambiguated slugs: the first
/// occurrence uses the base slug (e.g. `introduction`), and
/// subsequent occurrences receive a numeric suffix (`introduction-1`,
/// `introduction-2`, etc.), matching the convention used by GitHub,
/// GitLab, and most static-site generators.
pub fn extract_headings(input: &str) -> Vec<Heading> {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_MATH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(input, options);

    let mut headings = Vec::new();
    let mut current_depth: Option<u8> = None;
    let mut current_text = String::new();
    let mut slug_counts: HashMap<String, u32> = HashMap::new();

    for event in parser {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                current_depth = Some(level as u8);
                current_text.clear();
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some(depth) = current_depth.take() {
                    let text = current_text.trim().to_owned();
                    if !text.is_empty() {
                        let base_slug = slugify(&text);
                        let count = slug_counts.entry(base_slug.clone()).or_insert(0);
                        let slug = if *count == 0 {
                            base_slug
                        } else {
                            format!("{base_slug}-{count}")
                        };
                        *count += 1;
                        headings.push(Heading { depth, text, slug });
                    }
                }
                current_text.clear();
            }
            Event::Text(ref t) if current_depth.is_some() => {
                current_text.push_str(t);
            }
            Event::Code(ref c) if current_depth.is_some() => {
                current_text.push_str(c);
            }
            // Math, inline HTML, and other events inside headings
            // are ignored for the plain-text extraction; the slug
            // and text contain only readable content.
            _ => {}
        }
    }

    headings
}

/// Convert a heading's plain text into a URL-safe slug.
///
/// The algorithm lowercases, replaces whitespace runs with a single
/// hyphen, strips non-alphanumeric non-hyphen characters, and trims
/// leading and trailing hyphens. This matches the slug convention
/// used by GitHub, GitLab, and most static-site generators.
///
/// The output alphabet is restricted to `[a-z0-9-]`, which is safe
/// for use in HTML `id` attributes without additional escaping.
///
/// This function is public so that the render pipeline
/// ([`crate::render_with_options`]) can reuse it when extracting
/// headings from the event stream. External callers should prefer
/// [`extract_headings`], which handles deduplication.
pub fn slugify_heading(text: &str) -> String {
    slugify(text)
}

fn slugify(text: &str) -> String {
    let lower = text.to_lowercase();
    let mut slug = String::with_capacity(lower.len());
    let mut prev_hyphen = true; // suppress leading hyphens

    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            prev_hyphen = false;
        } else if (ch.is_whitespace() || ch == '-' || ch == '_') && !prev_hyphen {
            slug.push('-');
            prev_hyphen = true;
        }
        // All other characters are dropped.
    }

    // Trim trailing hyphen.
    if slug.ends_with('-') {
        slug.pop();
    }

    slug
}

/// Inject `id` attributes into rendered HTML heading tags so that
/// table-of-contents anchor links resolve correctly.
///
/// The function processes headings in document order: for each entry
/// in `headings`, it finds the next matching heading opening tag in
/// the HTML (starting from where the previous match ended) and
/// inserts `id="{slug}"`. This order-preserving approach handles
/// duplicate heading text correctly.
///
/// A match requires the tag prefix (`<h{depth}`) to be followed
/// immediately by `>` (no attributes) or ` ` (attributes follow).
/// This prevents false matches against tags like `<h2x>` in
/// user-authored raw HTML.
///
/// If a heading tag already carries an `id` attribute, it is left
/// unchanged and the heading is consumed (the search cursor advances
/// past the tag).
pub fn inject_ids(html: &str, headings: &[Heading]) -> String {
    let mut result = String::with_capacity(html.len() + headings.len() * 24);
    let mut search_from = 0;

    for heading in headings {
        let tag_prefix = format!("<h{}", heading.depth);

        // Scan forward for the next opening tag that matches both the
        // prefix and a valid delimiter (` ` or `>`). This avoids
        // matching `<h2x` or `<h21` in user-authored raw HTML.
        let mut scan = search_from;
        let found = loop {
            let Some(rel_pos) = html[scan..].find(&tag_prefix) else {
                break None;
            };
            let abs_pos = scan + rel_pos;
            let after_prefix = abs_pos + tag_prefix.len();
            if after_prefix < html.len() {
                let next_ch = html.as_bytes()[after_prefix];
                if next_ch == b'>' || next_ch == b' ' {
                    break Some((abs_pos, after_prefix));
                }
            }
            // Not a valid heading tag; skip past this occurrence.
            scan = abs_pos + tag_prefix.len();
        };

        let Some((abs_pos, after_tag)) = found else {
            continue;
        };

        // Find the closing `>` of the opening tag.
        let Some(close_rel) = html[after_tag..].find('>') else {
            continue;
        };
        let close_abs = after_tag + close_rel;
        let tag_attrs = &html[after_tag..close_abs];

        // Append everything before this tag.
        result.push_str(&html[search_from..abs_pos]);

        if tag_attrs.contains("id=") {
            // Already has an id; emit unchanged, advance past it.
            result.push_str(&html[abs_pos..=close_abs]);
        } else {
            // Inject the id attribute.
            result.push_str(&tag_prefix);
            result.push_str(&format!(" id=\"{}\"", heading.slug));
            result.push_str(tag_attrs);
            result.push('>');
        }

        search_from = close_abs + 1;
    }

    // Append the remainder of the HTML.
    result.push_str(&html[search_from..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_headings_at_all_depths() {
        let input = "# One\n## Two\n### Three\n#### Four";
        let headings = extract_headings(input);
        assert_eq!(headings.len(), 4);
        assert_eq!(
            headings[0],
            Heading {
                depth: 1,
                text: "One".into(),
                slug: "one".into()
            }
        );
        assert_eq!(
            headings[1],
            Heading {
                depth: 2,
                text: "Two".into(),
                slug: "two".into()
            }
        );
        assert_eq!(
            headings[2],
            Heading {
                depth: 3,
                text: "Three".into(),
                slug: "three".into()
            }
        );
        assert_eq!(
            headings[3],
            Heading {
                depth: 4,
                text: "Four".into(),
                slug: "four".into()
            }
        );
    }

    #[test]
    fn slugifies_with_special_characters() {
        let input = "## Hello, World! (2026)";
        let headings = extract_headings(input);
        assert_eq!(headings.len(), 1);
        assert_eq!(headings[0].slug, "hello-world-2026");
    }

    #[test]
    fn inline_code_included_in_text() {
        let input = "## Using `tokio::spawn`";
        let headings = extract_headings(input);
        assert_eq!(headings.len(), 1);
        assert_eq!(headings[0].text, "Using tokio::spawn");
    }

    #[test]
    fn empty_heading_is_excluded() {
        let input = "## \n### Real heading";
        let headings = extract_headings(input);
        assert_eq!(headings.len(), 1);
        assert_eq!(headings[0].text, "Real heading");
    }

    #[test]
    fn no_headings_returns_empty() {
        let input = "Just a paragraph.\n\nAnother paragraph.";
        let headings = extract_headings(input);
        assert!(headings.is_empty());
    }

    #[test]
    fn duplicate_headings_receive_suffixed_slugs() {
        let input = "## Setup\n\nFirst.\n\n## Setup\n\nSecond.\n\n## Setup\n\nThird.";
        let headings = extract_headings(input);
        assert_eq!(headings.len(), 3);
        assert_eq!(headings[0].slug, "setup");
        assert_eq!(headings[1].slug, "setup-1");
        assert_eq!(headings[2].slug, "setup-2");
    }

    #[test]
    fn slugify_collapses_whitespace() {
        assert_eq!(slugify("  Multiple   Spaces  "), "multiple-spaces");
    }

    #[test]
    fn slugify_strips_non_ascii_alphanumeric() {
        assert_eq!(slugify("Café & Résumé"), "caf-rsum");
    }
}

#[cfg(test)]
mod inject_tests {
    use super::*;

    #[test]
    fn injects_ids_into_plain_headings() {
        let html = "<h2>Introduction</h2><p>Text</p><h2>Conclusion</h2>";
        let headings = vec![
            Heading {
                depth: 2,
                text: "Introduction".into(),
                slug: "introduction".into(),
            },
            Heading {
                depth: 2,
                text: "Conclusion".into(),
                slug: "conclusion".into(),
            },
        ];
        let result = inject_ids(html, &headings);
        assert!(result.contains(r#"<h2 id="introduction">"#));
        assert!(result.contains(r#"<h2 id="conclusion">"#));
    }

    #[test]
    fn preserves_existing_id() {
        let html = r#"<h2 id="custom">Title</h2>"#;
        let headings = vec![Heading {
            depth: 2,
            text: "Title".into(),
            slug: "title".into(),
        }];
        let result = inject_ids(html, &headings);
        assert!(result.contains(r#"id="custom""#));
        assert!(!result.contains(r#"id="title""#));
    }

    #[test]
    fn handles_empty_headings_list() {
        let html = "<h1>Title</h1><p>body</p>";
        let result = inject_ids(html, &[]);
        assert_eq!(result, html);
    }

    #[test]
    fn preserves_other_attributes() {
        let html = r#"<h3 class="fancy">Styled</h3>"#;
        let headings = vec![Heading {
            depth: 3,
            text: "Styled".into(),
            slug: "styled".into(),
        }];
        let result = inject_ids(html, &headings);
        assert!(result.contains(r#"<h3 id="styled" class="fancy">"#));
    }

    #[test]
    fn does_not_match_non_heading_tags() {
        // `<h2x>` should not be matched as `<h2>`.
        let html = "<h2x>not a heading</h2x><h2>real</h2>";
        let headings = vec![Heading {
            depth: 2,
            text: "real".into(),
            slug: "real".into(),
        }];
        let result = inject_ids(html, &headings);
        assert!(result.contains("<h2x>not a heading</h2x>"));
        assert!(result.contains(r#"<h2 id="real">"#));
    }

    #[test]
    fn duplicate_slugs_produce_unique_ids() {
        let html = "<h2>Setup</h2><h2>Setup</h2>";
        let headings = vec![
            Heading {
                depth: 2,
                text: "Setup".into(),
                slug: "setup".into(),
            },
            Heading {
                depth: 2,
                text: "Setup".into(),
                slug: "setup-1".into(),
            },
        ];
        let result = inject_ids(html, &headings);
        assert!(result.contains(r#"<h2 id="setup">"#));
        assert!(result.contains(r#"<h2 id="setup-1">"#));
    }
}
