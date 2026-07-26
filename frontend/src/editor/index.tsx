// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Island entry point for the (Markdown + KaTeX) editor.
 *
 * The server-rendered template places a `<div id="editor-mount">` with
 * optional `data-*` attributes for initial state. This script hydrates
 * that element into an interactive editor.
 */

import { render } from "solid-js/web";
import Editor from "./Editor";
import "katex/dist/katex.min.css";
import "./editor.css";

const mount = document.getElementById("editor-mount");

if (mount) {
  const initial = mount.dataset.initialValue ?? "";
  const name = mount.dataset.name ?? "content_md";
  const placeholder = mount.dataset.placeholder;
  const rows = mount.dataset.rows
    ? parseInt(mount.dataset.rows, 10)
    : undefined;
  const locale =
    mount.dataset.locale ?? document.documentElement.lang ?? "en-US";

  render(
    () => (
      <Editor
        initialValue={initial}
        name={name}
        placeholder={placeholder}
        rows={rows}
        locale={locale}
      />
    ),
    mount,
  );
}
