// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Markdown editor island with a server-rendered preview.
 *
 * Renders a split editor (textarea | preview) on wide viewports and a
 * tabbed view (edit / preview) on narrow viewports.
 *
 * The preview is produced by `POST /api/v1/preview`, which calls the
 * same `noombat-markup` function the persist path calls. There is
 * deliberately no Markdown or maths renderer in this file: per
 * `adr/0010`, a preview from a second engine shows the author a
 * different document than the one that will be stored and federated,
 * and a federated `Create` cannot be recalled. The engines had already
 * drifted (markdown-it ran with `linkify` and `typographer` on, and did
 * no hashtag, DOI or heading-anchor extraction at all).
 *
 * The cost of that correctness is a round trip per preview, debounced
 * below, and no preview while offline. The editor itself keeps working.
 */

import { createSignal, createEffect, onCleanup, Show, type JSX } from "solid-js";

// ..... i18n .....

/** Translation keys used by the editor island. */
interface EditorStrings {
  tab_edit: string;
  tab_preview: string;
  placeholder: string;
  preview_unavailable: string;
}

const TRANSLATIONS: Record<string, EditorStrings> = {
  "en-US": {
    tab_edit: "Edit",
    tab_preview: "Preview",
    placeholder:
      "Write Markdown here\u2026 Use $\u2026$ for inline math, $$\u2026$$ for display math.",
    preview_unavailable: "Preview unavailable. Your text is unaffected.",
  },
  "en-AU": {
    tab_edit: "Edit",
    tab_preview: "Preview",
    placeholder:
      "Write Markdown here\u2026 Use $\u2026$ for inline math, $$\u2026$$ for display math.",
    preview_unavailable: "Preview unavailable. Your text is unaffected.",
  },
  "pt-BR": {
    tab_edit: "Editar",
    tab_preview: "Pr\u00e9-visualizar",
    placeholder:
      "Escreva Markdown aqui\u2026 Use $\u2026$ para f\u00f3rmulas em linha, $$\u2026$$ para f\u00f3rmulas em destaque.",
    preview_unavailable:
      "Pr\u00e9-visualiza\u00e7\u00e3o indispon\u00edvel. Seu texto n\u00e3o foi afetado.",
  },
};

/** Resolve translations for the given locale, falling back to en-US. */
function t(locale: string): EditorStrings {
  return TRANSLATIONS[locale] ?? TRANSLATIONS["en-US"];
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
  /**
   * Render as an Article rather than a Note.
   *
   * Selects the same `MarkupOptions` the outbox handler selects: strict
   * sanitisation and heading anchors. Must match what the submitting
   * form will produce, or the preview is accurate about the wrong mode.
   */
  article?: boolean;
}

export default function Editor(props: EditorProps): JSX.Element {
  const strings = () => t(props.locale ?? "en-US");

  const [source, setSource] = createSignal(props.initialValue ?? "");
  const [preview, setPreview] = createSignal("");
  const [activeTab, setActiveTab] = createSignal<"edit" | "preview">("edit");
  // Kept separate from `preview` so that the only thing ever assigned to
  // `preview` is a response body from the server, which has been through
  // the same sanitiser as the stored document. The failure message is
  // rendered as text below instead of being built into an HTML string
  // here, so nothing this file composes can reach `innerHTML`.
  const [failed, setFailed] = createSignal(false);

  // Debounced server render.
  //
  // 500 ms rather than the old 150 ms, because a pause now costs a
  // request rather than a local parse. adr/0010 names debouncing as
  // what keeps this to one request per typing pause.
  let timer: ReturnType<typeof setTimeout> | undefined;
  let inFlight: AbortController | undefined;

  createEffect(() => {
    const text = source();
    clearTimeout(timer);

    if (text === "") {
      inFlight?.abort();
      setPreview("");
      return;
    }

    timer = setTimeout(() => {
      // Supersede rather than race: a slow response for older text
      // must not overwrite a newer one.
      inFlight?.abort();
      const controller = new AbortController();
      inFlight = controller;

      const body = new URLSearchParams({ content: text });
      if (props.article === true) {
        body.set("article", "true");
      }

      void fetch("/api/v1/preview", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
        signal: controller.signal,
        credentials: "same-origin",
      })
        .then((response) =>
          response.ok
            ? response.text()
            : Promise.reject(new Error(`preview failed: ${String(response.status)}`)),
        )
        .then((html) => {
          setPreview(html);
          setFailed(false);
        })
        .catch((error: unknown) => {
          // A superseded request is not a failure.
          if (error instanceof DOMException && error.name === "AbortError") {
            return;
          }
          // Say so rather than leaving stale HTML on screen looking
          // current. The preview is the author's only check before
          // publishing, so a silent stale pane is the worst outcome.
          setPreview("");
          setFailed(true);
        });
    }, 500);
  });

  onCleanup(() => {
    clearTimeout(timer);
    inFlight?.abort();
  });

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
        >
          <Show when={failed()}>
            <p class="noombat-editor__preview-error">{strings().preview_unavailable}</p>
          </Show>
          {/*
            The one place this application assigns innerHTML, and the
            rule is right to ask. What makes it safe is not that the
            string came from our own server, but that it came from
            `POST /api/v1/preview`, which runs the same
            `noombat-markup` render and the same ammonia sanitiser as
            the path that stores and federates the document, under the
            same `MarkupOptions`. That equivalence is asserted by the
            parity test in `crates/noombat-api/src/routes/preview.rs`.
            Nothing composed in this file reaches here: the failure
            message above is rendered as text, and `preview` is only
            ever assigned a response body.
          */}
          {/* eslint-disable-next-line solid/no-innerhtml */}
          <div innerHTML={preview()} />
        </div>
      </div>
    </div>
  );
}
