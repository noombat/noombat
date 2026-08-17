// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Island entry point for the Markdown editor.
 *
 * The server-rendered template places a `<div id="editor-mount">` with
 * optional `data-*` attributes for initial state. This script hydrates
 * that element into an interactive editor.
 *
 * No renderer is bundled here. Markdown and maths are rendered by
 * `POST /api/v1/preview`, which is the same code path that produces the
 * stored and federated bytes.
 */

import { createSignal } from "solid-js";
import { render } from "solid-js/web";
import Editor from "./Editor";
import "./editor.css";

const mount = document.getElementById("editor-mount");

if (mount) {
  const initial = mount.dataset.initialValue ?? "";
  const name = mount.dataset.name ?? "content_md";
  const placeholder = mount.dataset.placeholder;
  const rows = mount.dataset.rows ? parseInt(mount.dataset.rows, 10) : undefined;
  const locale = mount.dataset.locale ?? document.documentElement.lang ?? "en-US";

  // Article mode, tracked live.
  //
  // The server renders Articles with a different sanitisation profile
  // and with heading anchors, so a preview in the wrong mode is exactly
  // the divergence the server-rendered preview exists to remove. It
  // cannot be a static attribute: compose.html carries a post-type
  // radio the author can flip at any time, and the preview has to
  // follow it.
  //
  // `data-article-selector` names the control that means "Article" when
  // checked. A mount without it is always a Note, which is right for
  // the profile summary editor.
  const articleSelector = mount.dataset.articleSelector;
  const [isArticle, setIsArticle] = createSignal(false);

  if (articleSelector !== undefined) {
    const readArticleState = () => {
      const control = document.querySelector(articleSelector);
      setIsArticle(control instanceof HTMLInputElement && control.checked);
    };
    readArticleState();
    // Delegated: the radios live outside the island, and a `change`
    // event from any of them can flip the answer.
    document.addEventListener("change", readArticleState);
  }

  render(
    () => (
      <Editor
        initialValue={initial}
        name={name}
        placeholder={placeholder}
        rows={rows}
        locale={locale}
        article={isArticle()}
      />
    ),
    mount,
  );
}
