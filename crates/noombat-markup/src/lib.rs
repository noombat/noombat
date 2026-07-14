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
pub mod sanitise;
pub mod typst_conv;

pub use typst_conv::md_to_typst;

use pulldown_cmark::{Event, Options, Parser};

use crate::doi::DoiReference;

/// The result of rendering a (Markdown + KaTeX) source string.
#[derive(Debug, Clone)]
pub struct MarkupOutput {
    /// Sanitised HTML suitable for storage and federation.
    pub html: String,
    /// Hashtags extracted from the source (normalised, lowercase, no `#`).
    pub hashtags: Vec<String>,
    /// DOIs detected in the source.
    pub dois: Vec<DoiReference>,
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

    // Render to HTML.
    let mut raw_html = String::with_capacity(input.len() * 2);
    pulldown_cmark::html::push_html(&mut raw_html, events.into_iter());

    // Sanitise. When strict_sanitisation is enabled, user-authored
    // HTML reaches the sanitiser directly. Use the strict profile,
    // which strips `style` from `<span>` to prevent CSS-based attacks.
    let html = if opts.strict_sanitisation {
        sanitise::clean_strict(&raw_html)
    } else {
        sanitise::clean(&raw_html)
    };

    // Deduplicate hashtags.
    hashtags.sort();
    hashtags.dedup();

    MarkupOutput {
        html,
        hashtags,
        dois,
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

/// Render a KaTeX math expression to (HTML + MathML).
///
/// On failure (e.g. invalid LaTeX), returns the raw source wrapped
/// in a `<code>` element so that the user sees their input rather
/// than a blank space.
fn render_katex(source: &str, display_mode: bool) -> String {
    let opts = katex::Opts::builder()
        .display_mode(display_mode)
        .output_type(katex::OutputType::HtmlAndMathml)
        .throw_on_error(false)
        .build();

    let opts = match opts {
        Ok(o) => o,
        Err(_) => return format!("<code>{}</code>", escape_html(source)),
    };

    match katex::render_with_opts(source, &opts) {
        Ok(html) => html,
        Err(_) => format!("<code>{}</code>", escape_html(source)),
    }
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

    #[test]
    fn inline_math() {
        let output = render("Energy: $E = mc^2$");
        // KaTeX output contains a <span class="katex"> wrapper.
        assert!(output.html.contains("katex"));
    }

    #[test]
    fn display_math() {
        let output = render("$$\\sum_{i=1}^{n} i$$");
        assert!(output.html.contains("katex"));
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
        let opts = MarkupOptions { strict_sanitisation: true };
        let output = render_with_options("<details><summary>More</summary>Hidden</details>", &opts);
        assert!(
            output.html.contains("<details>"),
            "safe HTML tags must survive in strict_sanitisation mode: {}",
            output.html
        );
    }

    #[test]
    fn strict_sanitisation_strips_script() {
        let opts = MarkupOptions { strict_sanitisation: true };
        let output = render_with_options("<script>alert('xss')</script>", &opts);
        assert!(
            !output.html.contains("<script>"),
            "script tags must be stripped even in strict_sanitisation mode"
        );
    }

    #[test]
    fn strict_sanitisation_strips_style_from_span() {
        let opts = MarkupOptions { strict_sanitisation: true };
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
