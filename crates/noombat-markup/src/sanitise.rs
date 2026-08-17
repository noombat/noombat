// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! HTML sanitisation via `ammonia`.
//!
//! Configures an allowlist that permits standard Markdown-generated HTML,
//! rendered maths (MathML elements and spans with classes), hashtag and
//! DOI annotation elements, and task-list checkboxes.
//!
//! # Trust model for the `style` attribute
//!
//! [`clean`] allows `style` on `<span>`, which is safe only while the
//! trusted maths renderer is the sole source of `<span style="...">`. It
//! is used for Notes, profile summaries and every non-Article Markdown
//! field, where users are not expected to author raw HTML.
//!
//! [`clean_strict`] omits it, and is used for Article content, where
//! user-authored raw HTML is expected and `style` would enable CSS-based
//! attacks: tracking pixels via `background-image: url(...)`, UI spoofing
//! via `position: fixed`.
//!
//! pulldown-cmark always passes raw HTML through per CommonMark, so the
//! two profiles differ in what they permit in the sanitised output, not in
//! what reaches the sanitiser.

use std::collections::HashSet;
use std::sync::LazyLock;

use ammonia::Builder;

/// Tags allowed beyond ammonia's defaults: MathML elements, additional
/// semantic HTML, and task-list checkboxes.
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

/// CSS properties permitted in `style` on `<span>` under the non-strict
/// profile, being those the maths renderer uses.
///
/// Excludes anything enabling tracking pixels (`background-image`), UI
/// spoofing (`position`, `z-index`) or content injection (`content`). The
/// deployed CSP (`style-src 'self'` without `'unsafe-inline'`) already
/// blocks inline `style` in the browser; this restriction is what holds if
/// that CSP is ever relaxed.
const MATH_STYLE_PROPERTIES: &[&str] = &[
    "border-bottom-color",
    "border-bottom-style",
    "border-bottom-width",
    "border-top-width",
    "bottom",
    "color",
    "font-size",
    "height",
    "left",
    "margin-left",
    "margin-right",
    "margin-top",
    "margin-bottom",
    "max-width",
    "min-width",
    "padding-left",
    "padding-right",
    "right",
    "top",
    "vertical-align",
    "width",
];

/// Apply the tag and attribute allowlist shared by both sanitisation
/// profiles. The only difference between the two profiles is whether
/// `style` is permitted on `<span>` (controlled by
/// `allow_span_style`).
fn configure_builder(builder: &mut Builder<'_>, allow_span_style: bool) {
    builder.add_tags(EXTRA_TAGS.iter().copied());

    // `class` and `aria-hidden` are always allowed; `style` only in the
    // non-strict profile, and there only for the properties the maths
    // renderer actually uses.
    if allow_span_style {
        builder.add_tag_attributes("span", ["class", "style", "aria-hidden"]);

        let allowed_props: HashSet<&str> = MATH_STYLE_PROPERTIES.iter().copied().collect();
        builder.filter_style_properties(allowed_props);
    } else {
        builder.add_tag_attributes("span", ["class", "aria-hidden"]);
    }

    builder.add_tag_attributes("div", ["class"]);
    builder.add_tag_attributes("a", ["class", "data-doi"]);
    builder.add_tag_attributes("math", ["xmlns", "display"]);
    builder.add_tag_attributes("annotation", ["encoding"]);
    builder.add_tag_attributes("annotation-xml", ["encoding"]);

    // MathML layout attributes.
    //
    // These are not decoration. MathML expresses part of an
    // expression's meaning in attributes, so stripping them changes
    // what the reader sees into a different expression rather than an
    // uglier one. `\binom{n}{k}` is the clearest case: it is an
    // `mfrac` with `linethickness="0px"`, so dropping that attribute
    // draws a division bar that the author never wrote. `stretchy`
    // and `fence` decide whether delimiters grow to their content,
    // and `mathvariant` is the difference between a variable and a
    // unit.
    //
    // Every attribute below is presentational and inert. None takes a
    // URL and none names a script. Deliberately absent: `href` and the
    // `xlink:*` family, which MathML does define and which would be a
    // navigation vector, and `style`, which the CSP refuses anyway.
    builder.add_tag_attributes("mfrac", ["linethickness"]);
    builder.add_tag_attributes(
        "mo",
        [
            "fence",
            "stretchy",
            "separator",
            "form",
            "largeop",
            "movablelimits",
            "symmetric",
            "lspace",
            "rspace",
            "minsize",
            "maxsize",
        ],
    );
    for tag in ["mi", "mn", "ms", "mtext"] {
        builder.add_tag_attributes(tag, ["mathvariant"]);
    }
    builder.add_tag_attributes("mspace", ["width", "height", "depth"]);
    builder.add_tag_attributes("mpadded", ["width", "height", "depth", "lspace", "voffset"]);
    builder.add_tag_attributes("menclose", ["notation"]);
    // `displaystyle` and `scriptlevel` are what make a matrix render at
    // text size inside a paragraph instead of inheriting display sizing.
    // math-core emits both on every `mtable`.
    //
    // Not allowed, and worth knowing: math-core also puts inline `style`
    // on `mtd` for column padding and justification. That is stripped
    // here and would be refused by the deployed CSP anyway
    // (`style-src 'self'`, no `style-src-attr`), so matrices lay out
    // with browser default spacing. The same class of loss as a
    // positioned span layer, but bounded to table padding.
    builder.add_tag_attributes(
        "mtable",
        [
            "columnalign",
            "rowspacing",
            "columnspacing",
            "displaystyle",
            "scriptlevel",
        ],
    );
    builder.add_tag_attributes("mtr", ["columnalign", "rowalign"]);
    builder.add_tag_attributes("mtd", ["columnalign", "rowalign", "columnspan", "rowspan"]);
    for tag in ["mover", "munder", "munderover"] {
        builder.add_tag_attributes(tag, ["accent", "accentunder"]);
    }
    builder.add_tag_attributes("msqrt", ["mathvariant"]);
    builder.add_tag_attributes("mroot", ["mathvariant"]);
    builder.add_tag_attributes("time", ["datetime"]);

    // Task-list checkboxes: permit only the attributes that
    // pulldown-cmark emits (`type="checkbox"`, `disabled`,
    // `checked`). The `type` attribute is restricted to the value
    // `"checkbox"` via `add_tag_attribute_values`.
    builder.add_tag_attributes("input", ["disabled", "checked"]);
    builder.add_tag_attribute_values("input", "type", ["checkbox"]);
}

/// Default profile: `style` allowed on `<span>`, trusting the maths
/// renderer to be its only source.
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
/// Allows `style` on `<span>` because the only source of styled spans in
/// normal operation is the trusted maths renderer. Where raw user-authored
/// HTML may be present, use [`clean_strict`] instead.
pub fn clean(html: &str) -> String {
    SANITISER.clean(html).to_string()
}

/// Strict sanitisation profile for content rendered with
/// `strict_sanitisation`, and the ingestion profile for all federated
/// HTML.
///
/// Identical to [`clean`] except that `style` is **not** permitted on
/// `<span>`, preventing CSS-based attacks from user-authored HTML.
///
/// Remote content is sanitised with this profile rather than [`clean`]
/// because a peer's `content` is user-authored raw HTML by definition,
/// i.e. exactly the case [`clean`]'s `style` allowance is unsafe for.
pub fn clean_strict(html: &str) -> String {
    SANITISER_STRICT.clean(html).to_string()
}

/// Version of the [`clean_strict`] policy that produced a stored value.
///
/// Sanitised HTML persisted in the database is a *derived projection* of
/// the wire record, not the record itself, so it has to be re-derivable.
/// Rows carry the version that produced them (`posts.sanitiser_version`,
/// `actors.sanitiser_version`); when this constant is raised, every row
/// behind it is stale and the backfill re-derives it.
///
/// **Raise this whenever the strict allowlist changes in a way that
/// alters output**, e.g. a tag or attribute removed, a URL scheme
/// disallowed, an `ammonia` upgrade that tightens defaults. Raising it
/// unnecessarily costs one backfill pass; failing to raise it leaves
/// hostile markup live in rows nobody will revisit.
///
/// Version 0 is reserved for rows written before the column existed.
pub const STRICT_VERSION: i16 = 1;

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
    fn allows_math_span_with_style() {
        // Rendered maths uses style on <span> for strut sizing.
        let input = r#"<span class="math" style="height:0.6444em"><span class="math-inner">x</span></span>"#;
        let result = clean(input);
        assert!(result.contains(r#"class="math""#));
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
    fn strips_tracking_pixel_from_span_style() {
        // background-image is not in MATH_STYLE_PROPERTIES and must
        // be stripped even in the default (non-strict) profile.
        let input = r#"<span style="background-image:url(https://evil.example/t)">track</span>"#;
        let result = clean(input);
        assert!(
            !result.contains("background-image"),
            "background-image must be stripped by CSS property filter: {result}"
        );
    }

    #[test]
    fn allows_math_style_properties() {
        // The allowed properties (height, vertical-align) must survive.
        let input = r#"<span class="math" style="height:0.6444em;vertical-align:-0.35em">x</span>"#;
        let result = clean(input);
        assert!(
            result.contains("height"),
            "height must be allowed: {result}"
        );
        assert!(
            result.contains("vertical-align"),
            "vertical-align must be allowed: {result}"
        );
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
    fn strict_preserves_span_class() {
        let input = r#"<span class="math">math</span>"#;
        let result = clean_strict(input);
        assert!(
            result.contains(r#"class="math""#),
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
