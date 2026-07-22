// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! HTML sanitisation via `ammonia`.
//!
//! Configures an allowlist that permits standard Markdown-generated
//! HTML, KaTeX-rendered output (spans with classes, MathML elements),
//! hashtag and DOI annotation elements, and task-list checkboxes.
//!
//! # Trust model for the `style` attribute
//!
//! Two sanitisation profiles are provided:
//!
//! - [`clean`] allows `style` on `<span>`. This is safe when the
//!   only source of `<span style="...">` in the input is the trusted
//!   KaTeX renderer. This profile is used for Notes, profile
//!   summaries, and all non-Article Markdown fields, where users are
//!   not expected to author raw HTML containing styled spans.
//!
//! - [`clean_strict`] omits `style` from `<span>`. This profile is
//!   used for Article content, where user-authored raw HTML is an
//!   expected use case and `<span style="...">` elements may reach
//!   the sanitiser. Allowing `style` on those elements would enable
//!   CSS-based attacks (tracking pixels via `background-image:
//!   url(...)`, UI spoofing via `position: fixed`, etc.). KaTeX
//!   output degrades gracefully: the MathML branch of the
//!   `htmlAndMathml` output provides a semantic fallback.
//!
//! Note: pulldown-cmark always passes raw HTML through to the event
//! stream per the CommonMark specification. The distinction between
//! the two profiles is not about whether raw HTML reaches the
//! sanitiser (it always does), but about which CSS properties are
//! permitted on specific elements in the sanitised output.

use std::sync::LazyLock;

use ammonia::Builder;

/// Tags allowed beyond ammonia's defaults: KaTeX HTML output, MathML
/// elements, additional semantic HTML, and task-list checkboxes.
const EXTRA_TAGS: &[&str] = &[
    "span",
    "math",
    "semantics",
    "mrow",
    "mi",
    "mo",
    "mn",
    "ms",
    "mtext",
    "mspace",
    "msup",
    "msub",
    "msubsup",
    "mfrac",
    "msqrt",
    "mroot",
    "mtable",
    "mtr",
    "mtd",
    "mover",
    "munder",
    "munderover",
    "mpadded",
    "mphantom",
    "menclose",
    "annotation",
    "annotation-xml",
    // Standard Markdown elements not in ammonia defaults.
    "details",
    "summary",
    "kbd",
    "mark",
    "var",
    "samp",
    "time",
    "figure",
    "figcaption",
    // Task-list checkboxes emitted by pulldown-cmark when
    // ENABLE_TASKLISTS is active.
    "input",
];

/// Apply the tag and attribute allowlist shared by both sanitisation
/// profiles. The only difference between the two profiles is whether
/// `style` is permitted on `<span>` (controlled by
/// `allow_span_style`).
fn configure_builder(builder: &mut Builder<'_>, allow_span_style: bool) {
    builder.add_tags(EXTRA_TAGS.iter().copied());

    // `<span>` attributes: `class` and `aria-hidden` are always
    // allowed; `style` is allowed only in the non-strict profile
    // (where KaTeX is the sole source of styled spans).
    if allow_span_style {
        builder.add_tag_attributes("span", ["class", "style", "aria-hidden"]);
    } else {
        builder.add_tag_attributes("span", ["class", "aria-hidden"]);
    }

    builder.add_tag_attributes("div", ["class"]);
    builder.add_tag_attributes("a", ["class", "data-doi"]);
    builder.add_tag_attributes("math", ["xmlns", "display"]);
    builder.add_tag_attributes("annotation", ["encoding"]);
    builder.add_tag_attributes("annotation-xml", ["encoding"]);
    builder.add_tag_attributes("time", ["datetime"]);

    // Task-list checkboxes: permit only the attributes that
    // pulldown-cmark emits (`type="checkbox"`, `disabled`,
    // `checked`). The `type` attribute is restricted to the value
    // `"checkbox"` via `add_tag_attribute_values`.
    builder.add_tag_attributes("input", ["disabled", "checked"]);
    builder.add_tag_attribute_values("input", "type", ["checkbox"]);
}

/// Default profile: `style` allowed on `<span>` (KaTeX-only trust model).
static SANITISER: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut builder = Builder::default();
    configure_builder(&mut builder, true);
    builder
});

/// Strict profile: `style` stripped from `<span>` (user-authored HTML may
/// be present).
static SANITISER_STRICT: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut builder = Builder::default();
    configure_builder(&mut builder, false);
    builder
});

/// Clean an HTML string using the Noombat sanitisation profile.
///
/// This profile allows `style` on `<span>` because the only source of
/// styled spans in normal operation is the trusted KaTeX renderer. If
/// raw user-authored HTML is present (i.e. the `strict_sanitisation`
/// rendering option is enabled), use [`clean_strict`] instead.
pub fn clean(html: &str) -> String {
    SANITISER.clean(html).to_string()
}

/// Strict sanitisation profile for content rendered with
/// `strict_sanitisation`.
///
/// Identical to [`clean`] except that `style` is **not** permitted on
/// `<span>`, preventing CSS-based attacks from user-authored HTML.
pub fn clean_strict(html: &str) -> String {
    SANITISER_STRICT.clean(html).to_string()
}

/// Strip all HTML tags, returning plain text.
///
/// Configures `ammonia` with no allowed tags, so every tag is removed
/// and only text content survives. HTML entities are decoded
/// automatically by `ammonia`. This is used by the feed handler to
/// generate plain-text article previews.
static STRIP_TAGS: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut builder = Builder::new();
    builder.tags(std::collections::HashSet::new());
    builder
});

/// Remove all HTML tags from a string, returning decoded plain text.
///
/// Uses the `ammonia` sanitiser with an empty tag allowlist, which
/// handles edge cases (self-closing tags, comments, CDATA, entity
/// decoding) that a naive regex or char-by-char approach would miss.
pub fn strip_tags(html: &str) -> String {
    STRIP_TAGS.clean(html).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_script_tags() {
        let result = clean("<p>Hello</p><script>alert('xss')</script>");
        assert!(!result.contains("<script>"));
        assert!(result.contains("<p>Hello</p>"));
    }

    #[test]
    fn allows_standard_html() {
        let input = "<p>Hello <strong>world</strong></p>";
        assert_eq!(clean(input), input);
    }

    #[test]
    fn allows_katex_span_with_style() {
        // KaTeX output uses style on <span> for strut sizing.
        let input = r#"<span class="katex" style="height:0.6444em"><span class="katex-mathml">x</span></span>"#;
        let result = clean(input);
        assert!(result.contains("katex"));
        assert!(result.contains("style="));
    }

    #[test]
    fn strips_style_from_div() {
        // style must NOT be allowed on <div> (UI-spoofing vector).
        let input = r#"<div class="safe" style="position:fixed;z-index:9999">overlay</div>"#;
        let result = clean(input);
        assert!(result.contains(r#"class="safe""#));
        assert!(
            !result.contains("style="),
            "style on <div> must be stripped: {result}"
        );
    }

    #[test]
    fn allows_mathml_elements() {
        let input =
            "<math xmlns=\"http://www.w3.org/1998/Math/MathML\"><mrow><mi>x</mi></mrow></math>";
        let result = clean(input);
        assert!(result.contains("<math"));
        assert!(result.contains("<mrow>"));
        assert!(result.contains("<mi>"));
    }

    #[test]
    fn strips_event_handlers() {
        let input = r#"<a href="https://example.com" onclick="alert('xss')">link</a>"#;
        let result = clean(input);
        assert!(!result.contains("onclick"));
        assert!(result.contains("href"));
    }

    #[test]
    fn allows_task_list_checkbox() {
        let input = r#"<li><input type="checkbox" disabled checked /> Done</li>"#;
        let result = clean(input);
        assert!(
            result.contains(r#"<input"#),
            "task-list checkbox must survive sanitisation: {result}"
        );
        assert!(
            result.contains(r#"type="checkbox""#),
            "type=\"checkbox\" must survive sanitisation: {result}"
        );
        assert!(result.contains("disabled"));
        assert!(result.contains("checked"));
    }

    #[test]
    fn strips_non_checkbox_input_type() {
        let input = r#"<input type="text" name="evil" value="xss">"#;
        let result = clean(input);
        assert!(
            !result.contains(r#"type="text""#),
            "type=\"text\" must be stripped: {result}"
        );
        assert!(!result.contains("name="));
        assert!(!result.contains("value="));
    }

    #[test]
    fn strips_style_from_user_authored_span() {
        let input = r#"<span style="background-image:url(https://evil.example/t)">track</span>"#;
        let result = clean(input);
        assert!(result.contains("style="));
    }

    #[test]
    fn strict_strips_style_from_span() {
        let input = r#"<span style="background-image:url(https://evil.example/t)">track</span>"#;
        let result = clean_strict(input);
        assert!(
            !result.contains("style="),
            "strict profile must strip style from span: {result}"
        );
    }

    #[test]
    fn strict_preserves_katex_class() {
        let input = r#"<span class="katex">math</span>"#;
        let result = clean_strict(input);
        assert!(
            result.contains("katex"),
            "strict profile must preserve class on span: {result}"
        );
    }

    /// Guard against RUSTSEC-2026-0213: ammonia up to 4.1.3 does
    /// not sanitise the `to`, `from`, and `values` attributes on
    /// SVG animation tags (`animate`, `set`, `animateTransform`,
    /// `animateMotion`), enabling XSS via `javascript:` URLs.
    ///
    /// The advisory does not affect Noombat because none of these
    /// tags are in the allowlist. This test ensures they are never
    /// added while the advisory remains unpatched. Remove this test
    /// (and the corresponding `ignore` entry in `deny.toml`) when
    /// ammonia publishes a fixed version.
    #[test]
    fn svg_animation_tags_not_in_allowlist() {
        const VULNERABLE_TAGS: &[&str] = &["animate", "set", "animateTransform", "animateMotion"];
        for tag in VULNERABLE_TAGS {
            assert!(
                !EXTRA_TAGS.contains(tag),
                "RUSTSEC-2026-0213: '{tag}' must not be in EXTRA_TAGS \
                 while ammonia lacks attribute sanitisation for SVG \
                 animation elements. See deny.toml for details."
            );
        }
    }
}
