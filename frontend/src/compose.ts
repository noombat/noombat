// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Entry point for the compose page (`/compose`).
 *
 * Toggles the article-specific form fields in response to the
 * post-type radio selection.
 *
 * This module replaces an inline `<script>` block previously
 * embedded in `templates/compose.html` so that the served
 * Content-Security-Policy can specify `script-src 'self'`
 * without `'unsafe-inline'`.
 */

/** Bind the post-type radios to the visibility of the article fields. */
function setupPostTypeToggle(): void {
  const note = document.getElementById("post-type-note");
  const article = document.getElementById("post-type-article");
  const fields = document.getElementById("article-fields");
  if (!note || !article || !fields) return;

  note.addEventListener("change", () => {
    fields.hidden = true;
  });
  article.addEventListener("change", () => {
    fields.hidden = false;
  });
}

// The module is loaded with `type="module"`, which defers execution
// until after the document has been parsed, so the elements are
// already present. The readyState guard keeps the behaviour correct
// should the script ever be loaded earlier.
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", setupPostTypeToggle);
} else {
  setupPostTypeToggle();
}
