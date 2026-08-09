// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! (Markdown + KaTeX) to Typst converter for CV generation.
//!
//! This emits a Typst *expression*, not Typst markup, and the
//! difference is the whole point.
//!
//! Markup was the previous design: user text was backslash-escaped and
//! interpolated into a content block. That is a denylist against a
//! grammar this project does not own, and it leaked in four separate
//! places. `escape_typst` never escaped `[` or `]`, so `]` closed the
//! block and returned the parser to code context. Math bodies were
//! emitted between `$` delimiters with no escaping at all, and Typst
//! evaluates `#`-prefixed code inside math. Link destinations were
//! interpolated into `#link("...")` with no escaping whatsoever, so a
//! quote in a URL was a direct breakout. A code span whose content held
//! a backtick closed its own raw span. Each was independently confirmed
//! to execute `#panic()` against typst 0.15.
//!
//! So user text no longer reaches markup. Every user-derived byte is
//! emitted as a *string literal argument* to a prelude function
//! ([`TYPST_PRELUDE`]), and the structure around it is built from
//! function calls this module writes. Inside a Typst string literal
//! only `\` and `"` are special: `#`, `$`, `[`, `]`, `*`, `_`, `@` and
//! backtick are inert there. That set is closed and specified, rather
//! than inherited from whatever Typst's markup grammar grows next.
//!
//! Formatting survives, because bold, italic, strikethrough, links,
//! lists, quotes and code all have function forms.

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

/// Definitions the generated source must contain before any expression
/// from [`md_to_typst_expr`] is evaluated.
///
/// `cv.rs` writes this at the top of the assembled source rather than
/// into a template file, so that it precedes the `#let` bindings and
/// applies to every template including custom ones.
pub const TYPST_PRELUDE: &str = r#"// Noombat prelude: the only route by which user text enters the
// document. Each of these takes strings and arrays, never markup.
#let nb-text(s) = s
#let nb-seq(parts) = parts.join()
#let nb-strong(parts) = strong(parts.join())
#let nb-emph(parts) = emph(parts.join())
#let nb-strike(parts) = strike(parts.join())
#let nb-raw(s) = raw(s)
#let nb-link(url, parts) = link(url, parts.join())
#let nb-quote(parts) = quote(block: true, parts.join())
#let nb-heading(level, parts) = heading(level: level, parts.join())
#let nb-par(parts) = par(parts.join())
#let nb-item(parts) = parts.join()
#let nb-list(items) = if items.len() == 0 { none } else { list(..items) }
#let nb-enum(items) = if items.len() == 0 { none } else { enum(..items) }
#let nb-rule() = line(length: 100%)
#let nb-break() = linebreak()
#let nb-doc(blocks) = blocks.join()
"#;

/// URL schemes a profile link may use.
///
/// Anything else (`javascript:`, `file:`, `data:`) renders as ordinary
/// text with no link attached, rather than being passed to `link()`.
const ALLOWED_SCHEMES: [&str; 3] = ["https://", "http://", "mailto:"];

/// Whether the current list context is ordered (`enum`) or unordered
/// (`list`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Ordered,
    Unordered,
}

/// Convert a (Markdown + KaTeX) source string to a Typst expression.
///
/// The result is a single expression and is meant to be used as one:
/// `#let summary = <result>`. It is never valid to wrap it in a content
/// block, which would put it back in markup context and undo the point.
pub fn md_to_typst_expr(input: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_MATH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);

    let parser = Parser::new_ext(input, options);
    let mut out = String::with_capacity(input.len() * 2);
    out.push_str("nb-doc((");

    let mut list_stack: Vec<ListKind> = Vec::new();

    for event in parser {
        match event {
            Event::Start(tag) => push_start(&tag, &mut out, &mut list_stack),
            Event::End(tag) => push_end(&tag, &mut out, &mut list_stack),
            Event::Text(text) => push_call(&mut out, "nb-text", &text),
            Event::Code(code) => push_call(&mut out, "nb-raw", &code),
            Event::InlineMath(math) => push_math(&mut out, &math, false),
            Event::DisplayMath(math) => push_math(&mut out, &math, true),
            // A soft break is a line wrap in the source, not in the
            // output, so it becomes the space it stood for.
            Event::SoftBreak => push_call(&mut out, "nb-text", " "),
            Event::HardBreak => out.push_str("nb-break(),"),
            Event::Rule => out.push_str("nb-rule(),"),
            // Not representable in Typst, and never worth guessing at.
            Event::Html(_) | Event::InlineHtml(_) => {}
            _ => {}
        }
    }

    out.push_str("))");
    out
}

/// Open a container.
///
/// Anything without a specific mapping opens a plain sequence, so that
/// [`push_end`] can close every tag the same way. An unhandled `Start`
/// that emitted nothing while its `End` emitted a delimiter would
/// unbalance the whole expression, and the failure would be a compile
/// error in generated source rather than anything a reader could see
/// here.
fn push_start(tag: &Tag<'_>, out: &mut String, list_stack: &mut Vec<ListKind>) {
    match tag {
        Tag::Paragraph => out.push_str("nb-par(("),
        Tag::Heading { level, .. } => {
            // `heading` counts from 1; pulldown's H1 is level 1 too.
            out.push_str(&format!("nb-heading({}, (", *level as usize));
        }
        Tag::Emphasis => out.push_str("nb-emph(("),
        Tag::Strong => out.push_str("nb-strong(("),
        Tag::Strikethrough => out.push_str("nb-strike(("),
        Tag::BlockQuote(_) => out.push_str("nb-quote(("),
        Tag::List(Some(_)) => {
            list_stack.push(ListKind::Ordered);
            out.push_str("nb-enum((");
        }
        Tag::List(None) => {
            list_stack.push(ListKind::Unordered);
            out.push_str("nb-list((");
        }
        Tag::Item => out.push_str("nb-item(("),
        Tag::Link { dest_url, .. } => match safe_url(dest_url) {
            Some(url) => {
                out.push_str("nb-link(");
                push_string(out, &url);
                out.push_str(", (");
            }
            // A scheme that is not on the list keeps its text and loses
            // its destination.
            None => out.push_str("nb-seq(("),
        },
        _ => out.push_str("nb-seq(("),
    }
}

/// Close a container. Every form opened by [`push_start`] closes alike.
fn push_end(tag: &TagEnd, out: &mut String, list_stack: &mut Vec<ListKind>) {
    if matches!(tag, TagEnd::List(_)) {
        list_stack.pop();
    }
    out.push_str(")),");
}

/// Emit a math fragment.
///
/// Never as math. Typst evaluates `#`-prefixed code inside `$...$`, and
/// a fragment arriving from a profile edit is exactly the input that
/// must not be evaluated, so the fragment is rendered as the literal
/// text the author typed, delimiters included.
///
/// This is the safety half of the KaTeX work. The other half, a mapping
/// table that turns the supported subset into Typst math *calls* with
/// literal operands, needs the golden corpus to decide what it covers,
/// and can be added here without changing anything else.
fn push_math(out: &mut String, body: &str, display: bool) {
    let delimiter = if display { "$$" } else { "$" };
    push_call(out, "nb-text", &format!("{delimiter}{body}{delimiter}"));
}

/// `name("value"),`
fn push_call(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push('(');
    push_string(out, value);
    out.push_str("),");
}

/// Write `value` as a Typst string literal, quotes included.
fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            // The only two that can alter or end the literal.
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            // Legible generated source rather than embedded newlines.
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Remaining control characters have no literal spelling.
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The URL if its scheme is allowed, otherwise `None`.
fn safe_url(url: &str) -> Option<String> {
    let lowered = url.trim().to_ascii_lowercase();
    ALLOWED_SCHEMES
        .iter()
        .any(|scheme| lowered.starts_with(scheme))
        .then(|| url.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything a hostile author might reach for, in the four places
    /// that were previously reachable. Each was confirmed to execute
    /// `#panic()` against typst 0.15 under the old emitter.
    const INJECTIONS: &[&str] = &[
        // The four vectors of the old emitter.
        "]\n#panic(\"NB_EXEC_MARKER\")\n#let ignored = [",
        "Formula: $#panic(\"NB_EXEC_MARKER\")$",
        "[text](https://x\"+panic(\"NB_EXEC_MARKER\")+\"y)",
        "`a` #panic(\"NB_EXEC_MARKER\") `b`",
        "#import \"@preview/evil:1.0.0\": *",
        "text ] #eval(\"1+1\") [ more",
        "$$#sys.inputs$$",
        "\\ #panic(\"NB_EXEC_MARKER\")",
        // Aimed at *this* emitter: close the string literal, call, reopen.
        r#""); #panic("NB_EXEC_MARKER"); nb-text(""#,
        r#"\"); #panic("NB_EXEC_MARKER"); nb-text(""#,
        // No `#` at all. Math mode resolves bare identifiers, so a rule
        // of "reject fragments containing #" would have let this through
        // and is why math is literal text instead.
        "Formula: $std.panic(\"NB_EXEC_MARKER\")$",
        "Formula: $std.eval(\"panic(\\\"NB_EXEC_MARKER\\\")\")$",
        // Local file disclosure rather than code execution.
        "#image(\"/etc/hostname\")",
        "#panic(read(\"/etc/hostname\"))",
        // Typst comments as a context switch.
        "x$]\n#panic(\"NB_EXEC_MARKER\")\n//",
        "x$]\n#panic(\"NB_EXEC_MARKER\")\n/*",
        // Doubled backslash, against an escaper that runs more than once.
        r#"\\#panic("NB_EXEC_MARKER")"#,
        // Fenced raw, and nested evaluation.
        "```#panic(\"NB_EXEC_MARKER\")```",
        "] #eval(\"panic(\\\"NB_EXEC_MARKER\\\")\") [",
    ];

    /// No user-derived byte may appear outside a string literal.
    ///
    /// Checked structurally: walk the generated expression, and collect
    /// only what lies between unescaped quotes. Anything a payload
    /// contributes must be found there and nowhere else.
    fn code_context_of(expr: &str) -> String {
        let mut code = String::new();
        let mut in_string = false;
        let mut escaped = false;

        for ch in expr.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
            } else if ch == '"' {
                in_string = true;
            } else {
                code.push(ch);
            }
        }

        code
    }

    #[test]
    fn injections_never_reach_code_context() {
        for payload in INJECTIONS {
            let code = code_context_of(&md_to_typst_expr(payload));

            for marker in ["panic", "eval", "import", "sys.inputs"] {
                assert!(
                    !code.contains(marker),
                    "`{marker}` reached code context for payload {payload:?}; code was {code:?}"
                );
            }
        }
    }

    #[test]
    fn the_expression_is_balanced() {
        for payload in INJECTIONS {
            let code = code_context_of(&md_to_typst_expr(payload));
            let opens = code.matches('(').count();
            let closes = code.matches(')').count();
            assert_eq!(opens, closes, "unbalanced for payload {payload:?}");
        }
    }

    /// The old escaper's gap.
    ///
    /// Asserted as a property rather than as an exact string, because
    /// pulldown-cmark splits text at the brackets and emits one `Text`
    /// event per run. Where the boundaries fall is its business; that
    /// no bracket lands in code context is ours.
    #[test]
    fn brackets_are_inert_rather_than_escaped() {
        let expr = md_to_typst_expr("a ] b [ c");
        let code = code_context_of(&expr);

        assert!(
            !code.contains(']'),
            "a bracket reached code context: {expr}"
        );
        assert!(
            !code.contains('['),
            "a bracket reached code context: {expr}"
        );
        // And they survive into the document rather than being dropped.
        assert!(expr.contains(r#"nb-text("]")"#), "{expr}");
        assert!(expr.contains(r#"nb-text("[")"#), "{expr}");
    }

    #[test]
    fn a_quote_in_a_link_cannot_end_the_literal() {
        let expr = md_to_typst_expr("[t](https://x\"+panic()+\"y)");
        assert!(!code_context_of(&expr).contains("panic"), "{expr}");
        assert!(expr.contains(r#"\""#), "the quote must be escaped: {expr}");
    }

    #[test]
    fn disallowed_schemes_lose_their_destination() {
        let expr = md_to_typst_expr("[click](javascript:alert(1))");
        assert!(!expr.contains("nb-link"), "{expr}");
        assert!(expr.contains("nb-seq"), "{expr}");
    }

    #[test]
    fn allowed_schemes_keep_theirs() {
        for url in [
            "https://example.org/a",
            "http://example.org/a",
            "mailto:a@example.org",
        ] {
            let expr = md_to_typst_expr(&format!("[t]({url})"));
            assert!(expr.contains("nb-link("), "{url} should link: {expr}");
        }
    }

    #[test]
    fn math_is_text_not_math() {
        let expr = md_to_typst_expr("Energy is $E = mc^2$.");
        assert!(expr.contains(r#"nb-text("$E = mc^2$")"#), "{expr}");
        // The delimiters are inside the literal, so no math context is
        // ever opened.
        assert!(!code_context_of(&expr).contains('$'), "{expr}");
    }

    #[test]
    fn formatting_survives() {
        let expr = md_to_typst_expr("**bold** and *italic* and ~~gone~~");
        assert!(expr.contains("nb-strong(("), "{expr}");
        assert!(expr.contains("nb-emph(("), "{expr}");
        assert!(expr.contains("nb-strike(("), "{expr}");
    }

    #[test]
    fn headings_and_lists_survive() {
        let expr = md_to_typst_expr("# Title\n\n- alpha\n- beta");
        assert!(expr.contains("nb-heading(1, ("), "{expr}");
        assert!(expr.contains("nb-list(("), "{expr}");
        assert!(expr.contains("nb-item(("), "{expr}");
    }

    #[test]
    fn ordered_lists_are_enums() {
        let expr = md_to_typst_expr("1. first\n2. second");
        assert!(expr.contains("nb-enum(("), "{expr}");
        assert!(!expr.contains("nb-list(("), "{expr}");
    }

    #[test]
    fn backslashes_and_quotes_are_escaped() {
        let expr = md_to_typst_expr(r#"a\b"c"#);
        assert!(expr.contains(r#"\\"#), "{expr}");
        assert!(expr.contains(r#"\""#), "{expr}");
    }

    /// Escaping order is load-bearing, so pin it.
    ///
    /// An implementation that replaced quotes first and backslashes
    /// second would turn `\"` into `\\"`: the quote it added gets
    /// escaped by the later pass, and the author's quote ends the
    /// literal. `push_string` walks the input once and so has no order
    /// to get wrong, which is the property this asserts.
    #[test]
    fn a_backslash_before_a_quote_cannot_end_the_literal() {
        let expr = md_to_typst_expr(r#"a\"; #panic("x") ; ""#);
        assert!(
            !code_context_of(&expr).contains("panic"),
            "escaping order let the payload out: {expr}"
        );
    }

    #[test]
    fn control_characters_get_a_spelling() {
        let expr = md_to_typst_expr("a\u{0}b");
        assert!(expr.contains(r"\u{0}"), "{expr}");
    }

    /// A hash is not escaped, because `\#` is not a Typst string escape:
    /// the compiler keeps both characters, so escaping it would print a
    /// stray backslash. Verified against typst 0.15.
    #[test]
    fn a_hash_is_left_alone() {
        let expr = md_to_typst_expr("C# and F#");
        assert!(expr.contains(r#"nb-text("C# and F#")"#), "{expr}");
    }

    #[test]
    fn empty_input_is_still_an_expression() {
        assert_eq!(md_to_typst_expr(""), "nb-doc(())");
    }

    /// Ordinary documents, to keep the compile check honest.
    ///
    /// A corpus of nothing but attacks would still pass if the emitter
    /// were changed to discard its input.
    const BENIGN: &[&str] = &[
        "# Title\n\nA paragraph with **bold**, *italic* and ~~struck~~ text.",
        "- alpha\n- beta\n\n1. first\n2. second",
        "A [link](https://example.org/x) and `code` and a C# mention.",
        "> quoted\n\n---\n\nEnergy is $E = mc^2$ inline.",
        "Unicode: \u{4f60}\u{597d} \u{1f600} and an em dash character.",
    ];

    /// Write the corpus as compilable Typst for `check-typst-injection.sh`.
    ///
    /// Not an assertion: the assertion is the compile, which needs the
    /// `typst` binary and therefore cannot run in the same place as the
    /// unit tests. Skips silently when the script has not asked for it.
    #[test]
    fn emit_typst_corpus() {
        let Ok(dir) = std::env::var("NOOMBAT_TYPST_CORPUS_DIR") else {
            return;
        };
        std::fs::create_dir_all(&dir).expect("corpus directory");

        for (label, payloads) in [("attack", INJECTIONS), ("benign", BENIGN)] {
            for (i, payload) in payloads.iter().enumerate() {
                let source = format!(
                    "{TYPST_PRELUDE}\n#let summary = {}\n#summary\n",
                    md_to_typst_expr(payload)
                );
                std::fs::write(format!("{dir}/{label}_{i:02}.typ"), source)
                    .expect("corpus file written");
            }
        }
    }
}
