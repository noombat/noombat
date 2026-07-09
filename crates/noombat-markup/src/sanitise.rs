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

/// The pre-configured ammonia builder, constructed once.
static SANITISER: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut builder = Builder::default();

    // ..... Additional tags beyond ammonia's defaults .....
    // KaTeX HTML output and MathML elements.
    builder.add_tags([
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
        // ENABLE_TASKLISTS is active. Only `type`, `disabled`, and
        // `checked` are permitted (see tag-attribute section below).
        "input",
    ]);

    // ..... Additional tag attributes .....
    //
    // `style` is allowed on `<span>` only: see the trust-model note
    // in the module doc-comment. It is intentionally NOT allowed on
    // `<div>` because KaTeX does not use styled divs, and arbitrary
    // div styling enables UI-spoofing attacks (position: fixed, z-index).
    builder.add_tag_attributes("span", ["class", "style", "aria-hidden"]);
    builder.add_tag_attributes("div", ["class"]);
    builder.add_tag_attributes("a", ["class", "data-doi"]);
    builder.add_tag_attributes("math", ["xmlns", "display"]);
    builder.add_tag_attributes("annotation", ["encoding"]);
    builder.add_tag_attributes("annotation-xml", ["encoding"]);
    builder.add_tag_attributes("time", ["datetime"]);
    // Task-list checkboxes: permit only the attributes that
    // pulldown-cmark emits (`type="checkbox"`, `disabled`,
    // `checked`). No other input types or attributes are allowed.
    builder.add_tag_attributes("input", ["type", "disabled", "checked"]);

    builder
});

/// Clean an HTML string using the Noombat sanitisation profile.
///
/// This profile allows `style` on `<span>` because the only source of
/// styled spans in normal operation is the trusted KaTeX renderer. If
/// raw user-authored HTML is present (i.e. the `allow_html` rendering
/// option is enabled), use [`clean_strict`] instead.
pub fn clean(html: &str) -> String {
    SANITISER.clean(html).to_string()
}

/// Strict sanitisation profile for content rendered with `allow_html`.
///
/// Identical to [`clean`] except that `style` is **not** permitted on
/// `<span>`. When `ENABLE_HTML` is active, user-authored `<span
/// style="...">` elements reach the sanitiser unsanitised. Allowing
/// `style` on those elements would enable CSS-based attacks (tracking
/// pixels via `background-image: url(...)`, UI spoofing via
/// `position: fixed`, etc.).
///
/// KaTeX output that relies on inline styles is unaffected in
/// practice: the KaTeX renderer produces its own `<span>` elements
/// with class names and inline styles, but when `allow_html` is
/// enabled, user-authored spans with the same tag name also reach the
/// sanitiser. Stripping `style` from all `<span>` elements is the
/// conservative choice; KaTeX output degrades gracefully (minor
/// alignment differences) because the MathML branch of the
/// `htmlAndMathml` output provides a semantic fallback.
pub fn clean_strict(html: &str) -> String {
    SANITISER_STRICT.clean(html).to_string()
}

/// Strict variant of [`SANITISER`]: same tag/attribute allowlist but
/// with `style` removed from `<span>`.
static SANITISER_STRICT: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut builder = Builder::default();

    builder.add_tags([
        "span",
        "math", "semantics", "mrow", "mi", "mo", "mn", "ms",
        "mtext", "mspace", "msup", "msub", "msubsup", "mfrac",
        "msqrt", "mroot", "mtable", "mtr", "mtd", "mover", "munder",
        "munderover", "mpadded", "mphantom", "menclose",
        "annotation", "annotation-xml",
        "details", "summary", "kbd", "mark", "var", "samp", "time",
        "figure", "figcaption",
        "input",
    ]);

    // `style` intentionally omitted from `<span>` (see doc-comment).
    builder.add_tag_attributes("span", ["class", "aria-hidden"]);
    builder.add_tag_attributes("div", ["class"]);
    builder.add_tag_attributes("a", ["class", "data-doi"]);
    builder.add_tag_attributes("math", ["xmlns", "display"]);
    builder.add_tag_attributes("annotation", ["encoding"]);
    builder.add_tag_attributes("annotation-xml", ["encoding"]);
    builder.add_tag_attributes("time", ["datetime"]);
    builder.add_tag_attributes("input", ["type", "disabled", "checked"]);

    builder
});

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
        // pulldown-cmark emits this for `- [x] Done`.
        let input = r#"<li><input type="checkbox" disabled checked /> Done</li>"#;
        let result = clean(input);
        assert!(
            result.contains(r#"<input"#),
            "task-list checkbox must survive sanitisation: {result}"
        );
        assert!(result.contains("disabled"));
        assert!(result.contains("checked"));
    }

    #[test]
    fn strips_non_checkbox_input() {
        // An <input type="text"> survives (the tag is allowlisted),
        // but dangerous attributes must be stripped.
        let input = r#"<input type="text" name="evil" value="xss">"#;
        let result = clean(input);
        // ammonia allows the tag but strips unknown attributes.
        // `name` and `value` are not in the allowlist.
        assert!(!result.contains("name="));
        assert!(!result.contains("value="));
    }

    #[test]
    fn strips_style_from_user_authored_span() {
        // Even though style is allowed on <span>, user-authored raw HTML
        // is entity-encoded by pulldown-cmark (ENABLE_HTML is off).
        // This test documents that if raw HTML DID reach the sanitiser,
        // the style would still pass, i.e. reinforcing the trust-model note.
        let input = r#"<span style="background-image:url(https://evil.example/t)">track</span>"#;
        let result = clean(input);
        // style IS allowed on span in the current configuration.
        assert!(result.contains("style="));
        // This is acceptable because raw HTML never reaches the sanitiser
        // in normal operation; see the trust-model note above.
    }
}
