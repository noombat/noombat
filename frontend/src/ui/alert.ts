// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Inline form alert rendering.
 *
 * Shared by the authentication and account-upgrade entry points so
 * that a single implementation governs the markup and ARIA role of
 * error messages presented above a form.
 */

/**
 * Display an error message above the given form.
 *
 * Reuses an existing `[role=alert]` element when present, so that
 * repeated failures replace rather than accumulate messages. The
 * message is assigned via `textContent`, never `innerHTML`, so
 * server-supplied strings cannot introduce markup.
 */
export function showFormAlert(form: HTMLFormElement, message: string): void {
  let alert = form.querySelector("[role=alert]") as HTMLElement | null;
  if (!alert) {
    alert = document.createElement("div");
    alert.setAttribute("role", "alert");
    alert.className =
      "bg-bg-danger-subtle border border-border-danger text-text-danger rounded px-4 py-3 mb-6 text-sm";
    form.prepend(alert);
  }
  alert.textContent = message;
}
