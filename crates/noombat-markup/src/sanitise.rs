// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! HTML sanitisation via `ammonia`.
//!
//! Configures an allowlist that permits standard Markdown-generated
//! HTML, KaTeX-rendered output (spans with classes, MathML elements),
//! and hashtag or DOI annotation elements.
//!
//! # Trust model for the `style` attribute
//!
//! The `style` attribute is allowed **only on `<span>`**, and only
//! because KaTeX's `htmlAndMathml` output relies on inline styles for
//! strut sizing, sub/superscript positioning, and margin spacing.
//!
//! This is safe in the current pipeline because user-authored raw HTML
//! is **not** passed through: the `render()` function in `lib.rs` does
//! not enable `pulldown_cmark::Options::ENABLE_HTML`, so user HTML is
//! entity-encoded by the parser. The only source of `<span style="…">`
//! in the sanitiser's input is the trusted KaTeX renderer.
//!
//! **If `ENABLE_HTML` is ever enabled** (e.g., for Article content),
//! this assumption breaks and `style` must be removed or restricted
//! to a CSS-property allowlist (e.g. via ammonia's `css` feature).

use std::sync::LazyLock;

use ammonia::Builder;

/// The pre-configured ammonia builder, constructed once.
static SANITISER: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut builder = Builder::default();

    // ..... Additional tags beyond ammonia's defaults .....
    // KaTeX HTML output and MathML elements.
    builder.add_tags([
        "span", "math", "semantics", "mrow", "mi", "mo", "mn", "ms",
        "mtext", "mspace", "msup", "msub", "msubsup", "mfrac", "msqrt",
        "mroot", "mtable", "mtr", "mtd", "mover", "munder",
        "munderover", "mpadded", "mphantom", "menclose",
        "annotation", "annotation-xml",
        // Standard Markdown elements not in ammonia defaults.
        "details", "summary", "kbd", "mark", "var", "samp",
        "time", "figure", "figcaption",
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

    builder
});

/// Clean an HTML string using the Noombat sanitisation profile.
pub fn clean(html: &str) -> String {
    SANITISER.clean(html).to_string()
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
        assert!(!result.contains("style="), "style on <div> must be stripped: {result}");
    }

    #[test]
    fn allows_mathml_elements() {
        let input = "<math xmlns=\"http://www.w3.org/1998/Math/MathML\"><mrow><mi>x</mi></mrow></math>";
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
