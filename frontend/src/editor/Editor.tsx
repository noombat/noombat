// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Live (Markdown + KaTeX) editor island.
 *
 * Renders a split editor (textarea | preview) on wide viewports and a
 * tabbed view (edit / preview) on narrow viewports. Math delimiters
 * `$...$` (inline) and `$$...$$` (display) are rendered via KaTeX in
 * the preview pane. The canonical render remains the server-side
 * `noombat-markup` pipeline; this client-side preview is for authoring
 * convenience only.
 */

import { createSignal, createEffect, onCleanup, type JSX } from "solid-js";
import MarkdownIt from "markdown-it";
import katex from "katex";

// ..... i18n .....

/** Translation keys used by the editor island. */
interface EditorStrings {
  tab_edit: string;
  tab_preview: string;
  placeholder: string;
}

const TRANSLATIONS: Record<string, EditorStrings> = {
  "en-US": {
    tab_edit: "Edit",
    tab_preview: "Preview",
    placeholder:
      "Write Markdown here\u2026 Use $\u2026$ for inline math, $$\u2026$$ for display math.",
  },
  "en-AU": {
    tab_edit: "Edit",
    tab_preview: "Preview",
    placeholder:
      "Write Markdown here\u2026 Use $\u2026$ for inline math, $$\u2026$$ for display math.",
  },
  "pt-BR": {
    tab_edit: "Editar",
    tab_preview: "Pr\u00e9-visualizar",
    placeholder:
      "Escreva Markdown aqui\u2026 Use $\u2026$ para f\u00f3rmulas em linha, $$\u2026$$ para f\u00f3rmulas em destaque.",
  },
};

/** Resolve translations for the given locale, falling back to en-US. */
function t(locale: string): EditorStrings {
  return TRANSLATIONS[locale] ?? TRANSLATIONS["en-US"];
}

// ..... Markdown-it instance .....

const md = new MarkdownIt({ html: false, linkify: true, typographer: true });

// ..... KaTeX rendering helpers .....
//
// Math is extracted from the raw Markdown source before markdown-it
// runs, replaced with inert placeholders, and restored in the HTML
// output. This avoids applying math regexes to HTML (where `$` might
// appear inside attributes or entity references).

const DISPLAY_MATH_RE = /\$\$([\s\S]+?)\$\$/g;
const INLINE_MATH_RE = /\$([^\s$](?:[^$]*[^\s$])?)\$/g;

/** Render a single TeX fragment to KaTeX HTML. */
function renderKatex(tex: string, displayMode: boolean): string {
  try {
    // MathML only, to match what the server publishes.
    //
    // `noombat-markup`'s `render_katex` emits `OutputType::Mathml`, so
    // a preview using KaTeX's HTML span layer would show the author
    // something no reader ever receives. It would also be a preview of
    // markup that cannot render here either: the layer positions every
    // glyph with inline `style` attributes, injected through
    // `innerHTML`, and the deployed policy is `style-src 'self'` with
    // no `style-src-attr`, so the browser refuses them on this page
    // exactly as it does on an article.
    return katex.renderToString(tex, {
      displayMode,
      throwOnError: false,
      output: "mathml",
    });
  } catch {
    return `<code class="katex-error">${escapeForHtml(tex)}</code>`;
  }
}

/** Minimal HTML escaping for error display. */
function escapeForHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Extract math spans from raw Markdown source, render them with KaTeX,
 * and return the source with placeholders plus a map to restore them.
 */
function extractMath(source: string): {
  processed: string;
  fragments: Map<string, string>;
} {
  const fragments = new Map<string, string>();
  let counter = 0;

  // Display math first ($$ is greedy over $).
  let processed = source.replace(DISPLAY_MATH_RE, (_m, tex: string) => {
    const id = `\uE000MATH${counter++}\uE000`;
    fragments.set(id, renderKatex(tex.trim(), true));
    return id;
  });

  // Inline math.
  processed = processed.replace(INLINE_MATH_RE, (_m, tex: string) => {
    const id = `\uE000MATH${counter++}\uE000`;
    fragments.set(id, renderKatex(tex.trim(), false));
    return id;
  });

  return { processed, fragments };
}

/** Replace placeholders in rendered HTML with KaTeX output. */
function restoreMath(html: string, fragments: Map<string, string>): string {
  for (const [placeholder, rendered] of fragments) {
    html = html.replaceAll(placeholder, rendered);
  }
  return html;
}

// ..... Editor component .....

export interface EditorProps {
  /** Initial Markdown source. */
  initialValue?: string;
  /** Hidden input name for form submission. */
  name?: string;
  /** Override placeholder text (takes precedence over locale). */
  placeholder?: string;
  /** Minimum rows for the textarea. */
  rows?: number;
  /** BCP 47 locale tag (e.g. "en-US", "pt-BR"). Defaults to "en-US". */
  locale?: string;
}

export default function Editor(props: EditorProps): JSX.Element {
  const strings = () => t(props.locale ?? "en-US");

  const [source, setSource] = createSignal(props.initialValue ?? "");
  const [preview, setPreview] = createSignal("");
  const [activeTab, setActiveTab] = createSignal<"edit" | "preview">("edit");

  // Debounced render: re-render preview after 150 ms of inactivity.
  let timer: ReturnType<typeof setTimeout> | undefined;

  createEffect(() => {
    const text = source();
    clearTimeout(timer);
    timer = setTimeout(() => {
      // 1: extract math from raw source to placeholders + KaTeX.
      const { processed, fragments } = extractMath(text);
      // 2: render Markdown (placeholders survive untouched).
      const html = md.render(processed);
      // 3: restore placeholders with KaTeX output.
      setPreview(restoreMath(html, fragments));
    }, 150);
  });

  onCleanup(() => clearTimeout(timer));

  return (
    <div class="noombat-editor">
      {/* Hidden input carries the Markdown source for form submission. */}
      <input type="hidden" name={props.name ?? "content_md"} value={source()} />

      {/* Mobile tab bar (visible below md breakpoint). */}
      <div class="noombat-editor__tabs">
        <button
          type="button"
          class={`noombat-editor__tab ${activeTab() === "edit" ? "noombat-editor__tab--active" : ""}`}
          onClick={() => setActiveTab("edit")}
        >
          {strings().tab_edit}
        </button>
        <button
          type="button"
          class={`noombat-editor__tab ${activeTab() === "preview" ? "noombat-editor__tab--active" : ""}`}
          onClick={() => setActiveTab("preview")}
        >
          {strings().tab_preview}
        </button>
      </div>

      {/* Split pane container. */}
      <div class="noombat-editor__panes">
        <textarea
          class={`noombat-editor__source ${activeTab() === "edit" ? "" : "noombat-editor__source--hidden"}`}
          rows={props.rows ?? 12}
          placeholder={props.placeholder ?? strings().placeholder}
          value={source()}
          onInput={(e) => setSource(e.currentTarget.value)}
        />
        <div
          class={`noombat-editor__preview ${activeTab() === "preview" ? "" : "noombat-editor__preview--hidden"}`}
          innerHTML={preview()}
        />
      </div>
    </div>
  );
}
