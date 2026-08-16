// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! (Markdown + KaTeX) to HTML pipeline, hashtag extraction, DOI detection,
//! and Markdown to Typst converter.
//!
//! This crate is the single source of truth for all user-authored rich
//! text in Noombat. Every Markdown field is processed through [`render`]
//! (or [`render_with_options`] for Article content that permits raw HTML).

pub mod doi;
pub mod hashtag;
pub mod headings;
pub mod sanitise;
pub mod typst_conv;

pub use headings::{extract_headings, inject_ids};
pub use typst_conv::{TYPST_PRELUDE, md_to_typst_expr};

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

use crate::doi::DoiReference;
use crate::headings::Heading;

/// The result of rendering a (Markdown + KaTeX) source string.
#[derive(Debug, Clone)]
pub struct MarkupOutput {
    /// Sanitised HTML suitable for storage and federation.
    pub html: String,
    /// Hashtags extracted from the source (normalised, lowercase, no `#`).
    pub hashtags: Vec<String>,
    /// DOIs detected in the source.
    pub dois: Vec<DoiReference>,
    /// Headings extracted from the source (depth, text, slug).
    /// Always populated; empty when the source contains no headings.
    pub headings: Vec<Heading>,
}

/// Options controlling the rendering pipeline.
///
/// The default options match the behaviour of [`render`]: the strict
/// sanitisation profile is **not** applied (i.e. `style` is permitted
/// on `<span>` because only the trusted KaTeX renderer produces styled
/// spans in normal Note/profile content).
#[derive(Debug, Clone, Default)]
pub struct MarkupOptions {
    /// When `true`, the strict sanitisation profile ([`sanitise::clean_strict`])
    /// is used, which strips `style` from `<span>`. This is appropriate
    /// for Article content where user-authored raw HTML may contain
    /// `<span style="...">` elements that would otherwise enable
    /// CSS-based attacks (tracking pixels, UI spoofing, etc.).
    ///
    /// When `false` (the default), [`sanitise::clean`] is used, which
    /// permits `style` on `<span>`. This is safe when KaTeX output is
    /// the sole source of styled spans (the case for Notes, profile
    /// summaries, and all non-Article Markdown fields).
    ///
    /// Note: pulldown-cmark always passes raw HTML through per the
    /// CommonMark specification. This flag does **not** toggle parser
    /// behaviour; it controls only which sanitisation profile is
    /// applied to the output.
    pub strict_sanitisation: bool,
    /// When `true`, heading `id` attributes are injected into the
    /// rendered HTML via [`headings::inject_ids`]. This bakes the
    /// anchor targets into the stored `content_html` so that
    /// federated HTML is self-contained (remote instances need not
    /// re-extract headings to make TOC links functional).
    ///
    /// Defaults to `false` (Notes do not need heading anchors).
    pub inject_heading_ids: bool,
}

/// Render a (Markdown + KaTeX) source string to sanitised HTML.
///
/// Equivalent to `render_with_options(input, &MarkupOptions::default())`.
///
/// The pipeline:
/// 1. Parse with `pulldown-cmark` (CommonMark + math + tables + strikethrough).
/// 2. Intercept `InlineMath` or `DisplayMath` events to render via the `katex` crate.
/// 3. Extract hashtags from `Text` events.
/// 4. Detect DOI URIs in `Text` events and annotate the output.
/// 5. Feed the transformed event stream to `pulldown-cmark`'s HTML renderer.
/// 6. Sanitise with `ammonia`.
pub fn render(input: &str) -> MarkupOutput {
    render_with_options(input, &MarkupOptions::default())
}

/// Render with explicit options.
///
/// See [`MarkupOptions`] for the available settings.
pub fn render_with_options(input: &str, opts: &MarkupOptions) -> MarkupOutput {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_MATH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);
    // Note: pulldown-cmark always passes raw HTML through to the event
    // stream (Event::Html and Event::InlineHtml) per the CommonMark
    // specification. There is no flag to toggle this behaviour. The
    // `strict_sanitisation` option controls only which sanitisation
    // profile is applied to the output: `clean` (permits `style` on
    // `<span>`, safe when KaTeX is the sole source of styled spans)
    // or `clean_strict` (strips `style` from `<span>`, safe when
    // user-authored HTML may also contain styled spans).

    let parser = Parser::new_ext(input, options);

    let mut hashtags = Vec::new();
    let mut dois = Vec::new();

    // Transform the event stream: render math, extract metadata.
    let events: Vec<Event<'_>> = parser
        .flat_map(|event| transform_event(event, &mut hashtags, &mut dois))
        .collect();

    // Extract headings from the already-collected event stream,
    // avoiding a second parser pass. The heading extraction logic
    // mirrors headings::extract_headings but operates on the
    // transformed event list rather than re-parsing the source.
    let headings = extract_headings_from_events(&events);

    // Render to HTML.
    let mut raw_html = String::with_capacity(input.len() * 2);
    pulldown_cmark::html::push_html(&mut raw_html, events.into_iter());

    // Sanitise. When strict_sanitisation is enabled, user-authored
    // HTML reaches the sanitiser directly. Use the strict profile,
    // which strips `style` from `<span>` to prevent CSS-based attacks.
    let mut html = if opts.strict_sanitisation {
        sanitise::clean_strict(&raw_html)
    } else {
        sanitise::clean(&raw_html)
    };

    // Inject heading `id` attributes when requested. This bakes the
    // anchor targets into the HTML at render time (i.e. at post
    // creation), so the stored content_html and federated HTML are
    // self-contained.
    if opts.inject_heading_ids && !headings.is_empty() {
        html = headings::inject_ids(&html, &headings);
    }

    // Deduplicate hashtags.
    hashtags.sort();
    hashtags.dedup();

    MarkupOutput {
        html,
        hashtags,
        dois,
        headings,
    }
}

/// Async wrapper that offloads [`render`] to a blocking thread pool.
///
/// The `katex` crate embeds QuickJS for server-side LaTeX rendering,
/// which is CPU-bound (typically 1-10 ms per math expression).
/// Calling [`render`] directly on a Tokio worker thread would starve
/// the runtime under load. This wrapper uses
/// [`tokio::task::spawn_blocking`] to prevent that.
pub async fn render_async(input: String) -> noombat_core::error::Result<MarkupOutput> {
    render_async_with_options(input, MarkupOptions::default()).await
}

/// Async wrapper for [`render_with_options`].
pub async fn render_async_with_options(
    input: String,
    opts: MarkupOptions,
) -> noombat_core::error::Result<MarkupOutput> {
    tokio::task::spawn_blocking(move || render_with_options(&input, &opts))
        .await
        .map_err(|e| {
            noombat_core::error::NoombatError::Internal(format!("markup render task failed: {e}"))
        })
}

/// Transform a single pulldown-cmark event.
///
/// - `InlineMath` or `DisplayMath` to KaTeX-rendered HTML fragment.
/// - `Text` to extract hashtags and DOIs, pass through.
/// - Everything else to pass through unchanged.
fn transform_event<'a>(
    event: Event<'a>,
    hashtags: &mut Vec<String>,
    dois: &mut Vec<DoiReference>,
) -> Vec<Event<'a>> {
    match event {
        Event::InlineMath(ref math_src) => {
            let rendered = render_katex(math_src, false);
            vec![Event::InlineHtml(rendered.into())]
        }
        Event::DisplayMath(ref math_src) => {
            let rendered = render_katex(math_src, true);
            vec![Event::Html(rendered.into())]
        }
        Event::Text(ref text) => {
            // Extract hashtags.
            hashtag::extract_from_text(text, hashtags);

            // Detect DOIs, collect references, and render as rich links.
            let detected = doi::detect_in_text(text);
            if detected.is_empty() {
                return vec![event];
            }
            dois.extend(detected.clone());

            // Split the text around each detected DOI and emit
            // alternating Text or InlineHtml events.
            let mut events: Vec<Event<'a>> = Vec::new();
            let mut remaining = text.as_ref();
            for doi_ref in &detected {
                if let Some(pos) = remaining.find(&doi_ref.source_uri) {
                    let before = &remaining[..pos];
                    if !before.is_empty() {
                        events.push(Event::Text(before.to_owned().into()));
                    }
                    // Render the DOI as a rich link with a data-doi attribute
                    // for optional client-side metadata enrichment. Degrades
                    // to a standard hyperlink on non-Noombat Fediverse clients.
                    let link_html = format!(
                        "<a href=\"https://doi.org/{}\" class=\"doi-link\" data-doi=\"{}\">{}</a>",
                        escape_html(&doi_ref.doi),
                        escape_html(&doi_ref.doi),
                        escape_html(&doi_ref.source_uri),
                    );
                    events.push(Event::InlineHtml(link_html.into()));
                    remaining = &remaining[pos + doi_ref.source_uri.len()..];
                }
            }
            if !remaining.is_empty() {
                events.push(Event::Text(remaining.to_owned().into()));
            }
            events
        }
        _ => vec![event],
    }
}

/// Extract headings from an already-collected pulldown-cmark event
/// stream, avoiding a second parser pass. The logic mirrors
/// [`headings::extract_headings`] but operates on `&[Event]` rather
/// than re-parsing the Markdown source.
fn extract_headings_from_events(events: &[Event<'_>]) -> Vec<Heading> {
    use std::collections::HashMap;

    let mut headings_out = Vec::new();
    let mut current_depth: Option<u8> = None;
    let mut current_text = String::new();
    let mut slug_counts: HashMap<String, u32> = HashMap::new();

    for event in events {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                current_depth = Some(*level as u8);
                current_text.clear();
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some(depth) = current_depth.take() {
                    let text = current_text.trim().to_owned();
                    if !text.is_empty() {
                        let base_slug = headings::slugify_heading(&text);
                        let count = slug_counts.entry(base_slug.clone()).or_insert(0);
                        let slug = if *count == 0 {
                            base_slug
                        } else {
                            format!("{base_slug}-{count}")
                        };
                        *count += 1;
                        headings_out.push(Heading { depth, text, slug });
                    }
                }
                current_text.clear();
            }
            Event::Text(t) if current_depth.is_some() => {
                current_text.push_str(t);
            }
            Event::Code(c) if current_depth.is_some() => {
                current_text.push_str(c);
            }
            _ => {}
        }
    }

    headings_out
}

/// Render a KaTeX math expression to MathML.
///
/// MathML only, deliberately, rather than KaTeX's default of MathML
/// plus a visually-rendered HTML span layer. That layer positions
/// every glyph with inline `style` attributes, and this project
/// destroys them twice over: `sanitise::clean_strict` strips `style`
/// from `<span>` on articles, and the deployed Content-Security-Policy
/// sets `style-src 'self'` with no `'unsafe-inline'`, which a test
/// asserts. So the browser was refusing the styles even where the
/// sanitiser left them, and the layer could only ever render as
/// unpositioned glyphs.
///
/// Dropping it also decouples the server from the stylesheet. The span
/// layer depends on KaTeX's CSS class names, which are versioned: 0.18
/// renamed twenty-one of them (`base` became `katex-base`, and so on),
/// so the frontend's npm KaTeX and this vendored one had to be upgraded
/// in lockstep, and nothing enforced that. MathML carries no class
/// names, so the two halves are now independent.
///
/// What is kept is what carries meaning: MathML is what a screen reader
/// reads, and the `<annotation encoding="application/x-tex">` inside it
/// is what a federated peer reads. Mastodon's transformer recovers the
/// original LaTeX from that annotation.
///
/// On failure (e.g. invalid LaTeX), returns the raw source wrapped
/// in a `<code>` element so that the user sees their input rather
/// than a blank space.
fn render_katex(source: &str, display_mode: bool) -> String {
    let display = if display_mode {
        math_core::MathDisplay::Block
    } else {
        math_core::MathDisplay::Inline
    };

    let Some(converter) = converter() else {
        return format!("<code>{}</code>", escape_html(source));
    };

    match converter.convert_with_local_state(source, display) {
        Ok(result) => result.mathml,
        // Invalid LaTeX. Show the author what they typed.
        Err(_) => format!("<code>{}</code>", escape_html(source)),
    }
}

/// The process-wide LaTeX converter.
///
/// Built once: construction parses the macro table, and there is no
/// reason to repeat that per expression. `None` if construction ever
/// fails, which keeps this module's promise that bad maths degrades to
/// visible source rather than panicking a request.
///
/// `annotation` and `xml_namespace` are both on deliberately, and both
/// are load-bearing rather than cosmetic:
///
/// - `annotation` wraps the output in `<semantics>` with an
///   `<annotation encoding="application/x-tex">` child holding the
///   original source. That annotation is the federation contract:
///   Mastodon's transformer reads the LaTeX back out of it, so without
///   it a remote reader gets no recoverable source. Off by default in
///   this crate, so it must be asked for.
/// - `xml_namespace` emits the `xmlns` attribute. Optional for inline
///   MathML in HTML5, but peers re-serialise what they receive and not
///   all of them treat a bare `<math>` as MathML.
fn converter() -> Option<&'static math_core::LatexToMathML> {
    static CONVERTER: std::sync::OnceLock<Option<math_core::LatexToMathML>> =
        std::sync::OnceLock::new();

    CONVERTER
        .get_or_init(|| {
            let config = math_core::MathCoreConfig {
                annotation: true,
                xml_namespace: true,
                ..Default::default()
            };
            math_core::LatexToMathML::new(config).ok()
        })
        .as_ref()
}

/// Minimal HTML entity escaping (used only for KaTeX fallback).
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ..... Tests .....

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_markdown() {
        let output = render("Hello **world**!");
        assert!(output.html.contains("<strong>world</strong>"));
        assert!(output.hashtags.is_empty());
        assert!(output.dois.is_empty());
    }

    // ..... Maths output, characterised .....
    //
    // These replaced two tests that asserted only
    // `output.html.contains("katex")`. That substring came from the
    // renderer's own CSS class, so it tested the brand of the
    // implementation rather than anything a reader depends on, and it
    // would have passed for any KaTeX-derived output no matter how
    // broken. It also became false the moment the renderer changed,
    // which is how a swap this size stayed honest: every assertion
    // below survived the move from KaTeX to math-core untouched,
    // because each one names a property of the MathML rather than of
    // the tool that produced it.
    //
    // Maths is emitted as MathML, and it is the MathML that has to
    // survive: it is what carries meaning to screen readers, and it is
    // what federates. Mastodon's FEP-8b32 transformer reads the
    // `<annotation encoding="application/x-tex">` back out of a
    // `<semantics>` block to recover the source, so a remote reader
    // sees the LaTeX only if these elements reach the wire intact.
    //
    // Each of these asserts on output that has already been through
    // `sanitise`, because that is the only shape a reader ever gets.

    #[test]
    fn inline_math_emits_mathml_the_sanitiser_keeps() {
        let html = render("Energy: $E = mc^2$").html;

        assert!(
            html.contains(r#"<math xmlns="http://www.w3.org/1998/Math/MathML">"#),
            "the MathML root did not survive sanitisation: {html}"
        );
        assert!(
            html.contains("<semantics>") && html.contains("<mrow>"),
            "the semantics wrapper did not survive: {html}"
        );
        assert!(
            html.contains(r#"<annotation encoding="application/x-tex">E = mc^2</annotation>"#),
            "the TeX annotation federation depends on is missing: {html}"
        );
        assert!(
            html.contains("<msup>"),
            "the superscript became flat text: {html}"
        );
    }

    #[test]
    fn display_math_is_marked_as_a_block() {
        let html = render("$$\\frac{a}{b}$$").html;

        // `display="block"` is the only thing distinguishing display
        // maths from inline once the HTML span layer is gone.
        assert!(
            html.contains(r#"display="block""#),
            "display maths lost its block marker: {html}"
        );
        assert!(html.contains("<mfrac>"), "the fraction flattened: {html}");
    }

    #[test]
    fn presentation_attributes_survive_sanitisation() {
        // `\binom` renders as a fraction with the rule suppressed by
        // `linethickness="0px"`. Strip that attribute and the reader
        // sees a division bar that is not in the source, i.e. a
        // different expression, silently. The sanitiser allowlist has
        // to carry the layout attributes for this reason, and this
        // test is what stops one being dropped again.
        let html = render(r"$\binom{n}{k}$").html;

        assert!(
            html.contains("linethickness="),
            "binomial gained a fraction bar it should not have: {html}"
        );
    }

    #[test]
    fn matrices_keep_their_sizing_attributes() {
        // `displaystyle` and `scriptlevel` on `mtable` are what keep a
        // matrix at text size inside a paragraph. Strip them and it
        // inherits display sizing and grows.
        let html = render(r"$\begin{pmatrix}a&b\\c&d\end{pmatrix}$").html;

        assert!(html.contains("<mtable"), "the matrix flattened: {html}");
        assert!(
            html.contains("displaystyle=") && html.contains("scriptlevel="),
            "the matrix lost its sizing attributes: {html}"
        );
    }

    #[test]
    fn the_html_span_layer_is_gone() {
        // The span layer was styled entirely by inline `style`
        // attributes, which `clean_strict` strips and which the
        // deployed CSP refuses (`style-src 'self'`, no
        // `'unsafe-inline'`). Emitting it produced markup that could
        // not lay out and that federated to peers as glyph soup.
        let html = render("Energy: $E = mc^2$").html;

        assert!(
            !html.contains("katex-html"),
            "the unstyleable span layer is back: {html}"
        );
        assert!(
            !html.contains("katex-mathml"),
            "MathML is wrapped in the class katex.css hides: {html}"
        );
    }

    #[test]
    fn invalid_maths_falls_back_to_the_source() {
        // `throw_on_error(false)` plus the `<code>` fallback: a reader
        // must see what they typed rather than a blank space.
        let html = render(r"$\frac{$").html;
        assert!(
            html.contains("frac"),
            "invalid maths rendered as nothing: {html}"
        );
    }

    #[test]
    fn hashtag_extraction() {
        let output = render("Check out #Rust and #ActivityPub!");
        assert!(output.hashtags.contains(&"rust".to_owned()));
        assert!(output.hashtags.contains(&"activitypub".to_owned()));
    }

    #[test]
    fn doi_detection() {
        let output = render("See https://doi.org/10.1000/xyz123 for details.");
        assert_eq!(output.dois.len(), 1);
        assert_eq!(output.dois[0].doi, "10.1000/xyz123");
    }

    #[test]
    fn script_tags_are_stripped() {
        let output = render("<script>alert('xss')</script> Hello");
        assert!(!output.html.contains("<script>"));
        assert!(output.html.contains("Hello"));
    }

    #[test]
    fn task_list_checkboxes_preserved() {
        let output = render("- [x] Done\n- [ ] Pending");
        assert!(
            output.html.contains("<input"),
            "task-list checkbox must survive the full pipeline: {}",
            output.html
        );
    }

    #[test]
    fn hashtags_are_deduplicated() {
        let output = render("#Rust is great. I love #rust.");
        assert_eq!(output.hashtags.len(), 1);
        assert_eq!(output.hashtags[0], "rust");
    }

    // ..... strict_sanitisation mode .....

    #[test]
    fn strict_sanitisation_passes_safe_tags() {
        let opts = MarkupOptions {
            strict_sanitisation: true,
            ..Default::default()
        };
        let output = render_with_options("<details><summary>More</summary>Hidden</details>", &opts);
        assert!(
            output.html.contains("<details>"),
            "safe HTML tags must survive in strict_sanitisation mode: {}",
            output.html
        );
    }

    #[test]
    fn strict_sanitisation_strips_script() {
        let opts = MarkupOptions {
            strict_sanitisation: true,
            ..Default::default()
        };
        let output = render_with_options("<script>alert('xss')</script>", &opts);
        assert!(
            !output.html.contains("<script>"),
            "script tags must be stripped even in strict_sanitisation mode"
        );
    }

    #[test]
    fn strict_sanitisation_strips_style_from_span() {
        let opts = MarkupOptions {
            strict_sanitisation: true,
            ..Default::default()
        };
        let output = render_with_options(
            r#"<span style="background-image:url(https://evil.example/t)">track</span>"#,
            &opts,
        );
        assert!(
            !output.html.contains("style="),
            "style on <span> must be stripped in strict_sanitisation mode: {}",
            output.html
        );
    }

    #[test]
    fn default_mode_sanitises_raw_html() {
        // pulldown-cmark always passes raw HTML through. The sanitiser
        // strips dangerous elements; safe elements survive.
        let output = render("<details><summary>Info</summary>Content</details>");
        assert!(
            output.html.contains("<details>"),
            "safe raw HTML should survive sanitisation in default mode: {}",
            output.html
        );
        // Scripts are stripped regardless of mode.
        let output = render("<script>alert('xss')</script>");
        assert!(
            !output.html.contains("<script>"),
            "script tags must be stripped in default mode"
        );
    }
}
