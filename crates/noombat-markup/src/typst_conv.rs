// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! (Markdown + KaTeX) to Typst converter for CV generation.
//!
//! Converts CommonMark Markdown with KaTeX math delimiters into Typst
//! markup. KaTeX `$...$` (inline) and `$$...$$` (display) delimiters
//! map directly to Typst's `$...$` math mode (inline) and `$ ... $`
//! (display, with surrounding newlines).

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

/// Whether the current list context is ordered (`+ `) or unordered (`- `).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Ordered,
    Unordered,
}

/// Convert a (Markdown + KaTeX) source string to Typst markup.
pub fn md_to_typst(input: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_MATH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);

    let parser = Parser::new_ext(input, options);
    let mut output = String::with_capacity(input.len());

    // Stack tracks nested list contexts so that `Tag::Item` emits the
    // correct Typst marker: `+ ` for ordered, `- ` for unordered.
    let mut list_stack: Vec<ListKind> = Vec::new();

    for event in parser {
        match event {
            Event::Start(tag) => write_start_tag(&tag, &mut output, &mut list_stack),
            Event::End(tag) => write_end_tag(&tag, &mut output, &mut list_stack),
            Event::Text(text) => {
                // Escape Typst-special characters in plain text.
                output.push_str(&escape_typst(&text));
            }
            Event::Code(code) => {
                output.push_str(&format!("`{code}`"));
            }
            Event::InlineMath(math) => {
                // Typst inline math: $...$
                output.push('$');
                output.push_str(&math);
                output.push('$');
            }
            Event::DisplayMath(math) => {
                // Typst display math: $ ... $ on its own line.
                output.push_str("\n$ ");
                output.push_str(&math);
                output.push_str(" $\n");
            }
            Event::SoftBreak | Event::HardBreak => {
                output.push('\n');
            }
            Event::Rule => {
                output.push_str("\n#line(length: 100%)\n");
            }
            Event::Html(_) | Event::InlineHtml(_) => {
                // HTML is not representable in Typst; skip.
            }
            _ => {}
        }
    }

    output
}

fn write_start_tag(tag: &Tag<'_>, out: &mut String, list_stack: &mut Vec<ListKind>) {
    match tag {
        Tag::Heading { level, .. } => {
            let marker = "=".repeat(*level as usize);
            out.push_str(&format!("\n{marker} "));
        }
        Tag::Paragraph => {
            out.push('\n');
        }
        Tag::Emphasis => {
            out.push('_');
        }
        Tag::Strong => {
            out.push('*');
        }
        Tag::Strikethrough => {
            out.push_str("#strike[");
        }
        Tag::List(Some(_start)) => {
            list_stack.push(ListKind::Ordered);
            out.push('\n');
        }
        Tag::List(None) => {
            list_stack.push(ListKind::Unordered);
            out.push('\n');
        }
        Tag::Item => {
            let marker = match list_stack.last() {
                Some(ListKind::Ordered) => "+ ",
                _ => "- ",
            };
            out.push_str(marker);
        }
        Tag::BlockQuote(_) => {
            out.push_str("#quote[");
        }
        Tag::Link { dest_url, .. } => {
            out.push_str(&format!("#link(\"{dest_url}\")["));
        }
        _ => {}
    }
}

fn write_end_tag(tag: &TagEnd, out: &mut String, list_stack: &mut Vec<ListKind>) {
    match tag {
        TagEnd::Heading(_) => {
            out.push('\n');
        }
        TagEnd::Paragraph => {
            out.push('\n');
        }
        TagEnd::Emphasis => {
            out.push('_');
        }
        TagEnd::Strong => {
            out.push('*');
        }
        TagEnd::Strikethrough => {
            out.push(']');
        }
        TagEnd::Item => {
            out.push('\n');
        }
        TagEnd::List(_) => {
            list_stack.pop();
        }
        TagEnd::BlockQuote(_) => {
            out.push(']');
        }
        TagEnd::Link => {
            out.push(']');
        }
        _ => {}
    }
}

/// Escape characters that are special in Typst markup.
///
/// Typst uses `#` for function calls, `$` for math mode, `*` and `_`
/// for bold and italic, `@` for references, `\` for escape sequences,
/// and `` ` `` for raw/code spans. All must be backslash-escaped when
/// they appear in plain text.
fn escape_typst(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '#' | '$' | '*' | '_' | '@' | '\\' | '`' => {
                result.push('\\');
                result.push(ch);
            }
            _ => result.push(ch),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text() {
        let result = md_to_typst("Hello world.");
        assert!(result.contains("Hello world."));
    }

    #[test]
    fn bold_and_italic() {
        let result = md_to_typst("**bold** and *italic*");
        assert!(result.contains("*bold*"));
        assert!(result.contains("_italic_"));
    }

    #[test]
    fn inline_math_preserved() {
        let result = md_to_typst("Energy is $E = mc^2$.");
        assert!(result.contains("$E = mc^2$"));
    }

    #[test]
    fn display_math_preserved() {
        let result = md_to_typst("$$\\sum_{i=1}^{n} i$$");
        assert!(result.contains("$ \\sum_{i=1}^{n} i $"));
    }

    #[test]
    fn headings() {
        let result = md_to_typst("# Title\n## Subtitle");
        assert!(result.contains("= Title"));
        assert!(result.contains("== Subtitle"));
    }

    #[test]
    fn special_chars_escaped() {
        assert_eq!(escape_typst("$10"), "\\$10");
        assert_eq!(escape_typst("#tag"), "\\#tag");
        assert_eq!(escape_typst("it`s"), "it\\`s");
    }

    #[test]
    fn unordered_list() {
        let result = md_to_typst("- alpha\n- beta\n- gamma");
        assert!(result.contains("- alpha"));
        assert!(result.contains("- beta"));
        assert!(!result.contains("+ "));
    }

    #[test]
    fn ordered_list() {
        let result = md_to_typst("1. first\n2. second\n3. third");
        assert!(result.contains("+ first"));
        assert!(result.contains("+ second"));
        assert!(!result.contains("- first"));
    }

    #[test]
    fn nested_mixed_lists() {
        // Outer ordered, inner unordered.
        let input = "1. outer\n   - inner\n2. next";
        let result = md_to_typst(input);
        assert!(result.contains("+ outer"));
        assert!(result.contains("- inner"));
        assert!(result.contains("+ next"));
    }
}
