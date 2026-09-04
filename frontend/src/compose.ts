// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Entry point for the compose page (`/compose`).
 *
 * Toggles the article-specific form fields in response to the
 * post-type radio selection, and drives the image attachment picker.
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

/** One image that has been uploaded and is waiting for a post to claim it. */
interface Uploaded {
  id: string;
  url: string;
}

/**
 * Bind the attachment picker: upload each chosen image, then keep the
 * hidden field that tells the outbox which ones this post claims.
 *
 * The upload happens before the post exists, which is what lets the
 * page show the image and collect a description for it. The container
 * starts hidden and is revealed here: without JavaScript there is no
 * second request to make the upload with, and a file picker that
 * silently discards what it is given is worse than no picker.
 */
function setupAttachments(): void {
  const container = document.getElementById("attachments");
  const picker = document.getElementById("attachment-file");
  const list = document.getElementById("attachment-list");
  const ids = document.getElementById("attachment-ids");
  if (
    !container ||
    !(picker instanceof HTMLInputElement) ||
    !(list instanceof HTMLElement) ||
    !(ids instanceof HTMLInputElement)
  ) {
    return;
  }

  container.hidden = false;

  picker.addEventListener("change", () => {
    const chosen = Array.from(picker.files ?? []);
    // Cleared at once, so choosing the same file twice in a row still
    // fires `change` and still uploads.
    picker.value = "";
    for (const file of chosen) {
      void uploadOne(file, list, ids, container);
    }
  });
}

/**
 * The ids of every attachment still on the form, in document order.
 *
 * Recomputed from the list rather than tracked alongside it, so
 * removing a row cannot leave the hidden field naming an image the
 * author took back.
 */
function refreshIds(list: HTMLElement, ids: HTMLInputElement): void {
  const rows = Array.from(list.querySelectorAll<HTMLElement>("[data-attachment-id]"));
  ids.value = rows.map((row) => row.dataset.attachmentId ?? "").join(",");
}

/** Upload one image and append its row, or report why it was refused. */
async function uploadOne(
  file: File,
  list: HTMLElement,
  ids: HTMLInputElement,
  labels: HTMLElement,
): Promise<void> {
  const row = document.createElement("li");
  row.className = "text-sm text-text-secondary";
  row.textContent = file.name;
  list.append(row);

  const body = new FormData();
  body.append("file", file);

  let response: Response;
  try {
    response = await fetch("/api/v1/media", { method: "POST", body });
  } catch {
    // The server never answered, so there is nothing to report but
    // that the upload did not arrive.
    row.textContent = `${file.name}: upload failed`;
    return;
  }

  if (!response.ok) {
    // The route answers in plain text a person can act on, so that is
    // shown rather than replaced with a message of our own.
    row.textContent = `${file.name}: ${await response.text()}`;
    return;
  }

  const uploaded = (await response.json()) as Uploaded;
  row.textContent = "";
  row.dataset.attachmentId = uploaded.id;
  row.append(buildRow(uploaded, file.name, row, list, ids, labels));
  refreshIds(list, ids);
}

/**
 * The controls for one uploaded image: a preview, the field that
 * describes it, and the control that takes it back off the post.
 */
function buildRow(
  uploaded: Uploaded,
  filename: string,
  row: HTMLElement,
  list: HTMLElement,
  ids: HTMLInputElement,
  labels: HTMLElement,
): HTMLElement {
  const wrapper = document.createElement("div");
  wrapper.className = "flex items-start gap-3";

  const preview = document.createElement("img");
  preview.src = uploaded.url;
  // Decorative: it is a thumbnail of the file the author just chose,
  // shown beside the field where they describe it.
  preview.alt = "";
  preview.className = "w-16 h-16 object-cover rounded border border-border-default";

  const fields = document.createElement("div");
  fields.className = "flex-1";

  const altId = `attachment-alt-${uploaded.id}`;
  const label = document.createElement("label");
  label.className = "block text-sm mb-1";
  label.htmlFor = altId;
  label.textContent = labels.dataset.altLabel ?? "";

  const alt = document.createElement("input");
  alt.type = "text";
  alt.id = altId;
  alt.className = "w-full border border-border-default rounded p-2 bg-bg-primary text-text-primary";
  // Sent on its own rather than with the post, because the row exists
  // already and the document the post federates is built from it.
  alt.addEventListener("change", () => {
    void describe(uploaded.id, alt.value);
  });

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "text-sm text-text-secondary underline mt-1";
  remove.textContent = labels.dataset.removeLabel ?? "";
  remove.addEventListener("click", () => {
    // Taken off the form only. The uploaded row stays unattached, which
    // is the state an unclaimed upload is expected to be left in.
    row.remove();
    refreshIds(list, ids);
  });

  const name = document.createElement("p");
  name.className = "sr-only";
  name.textContent = filename;

  fields.append(label, alt, remove, name);
  wrapper.append(preview, fields);
  return wrapper;
}

/** Record the description against the uploaded image. */
async function describe(id: string, alt: string): Promise<void> {
  try {
    await fetch(`/api/v1/media/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ alt }),
    });
  } catch {
    // Left as the author typed it. The next change fires this again,
    // and a description that failed to save is not worth interrupting
    // the writing for.
  }
}

// The module is loaded with `type="module"`, which defers execution
// until after the document has been parsed, so the elements are
// already present. The readyState guard keeps the behaviour correct
// should the script ever be loaded earlier.
function setup(): void {
  setupPostTypeToggle();
  setupAttachments();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", setup);
} else {
  setup();
}
