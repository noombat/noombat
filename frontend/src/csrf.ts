// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The session's CSRF token. A write the session cookie authenticates is
 * refused without it in the `X-CSRF-Token` header, and each page carries
 * it in a meta tag; a visitor with no session has none.
 */
export function csrfToken(): string | null {
  const token = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content;
  return token && token.length > 0 ? token : null;
}

/** The parts of htmx's `htmx:configRequest` detail read here. */
export interface HtmxRequestDetail {
  verb: string;
  headers: Record<string, string>;
}

/**
 * Add the CSRF token to an htmx request that writes. A hidden field could
 * not carry it: htmx 2 sends a DELETE's parameters in the URL.
 */
export function addCsrfHeader(detail: HtmxRequestDetail): void {
  const token = csrfToken();
  if (token && detail.verb !== "get") {
    detail.headers["X-CSRF-Token"] = token;
  }
}

/** `headers` with the CSRF token added, when the page has one. */
export function withCsrf(headers: Record<string, string> = {}): Record<string, string> {
  const token = csrfToken();
  return token ? { ...headers, "X-CSRF-Token": token } : { ...headers };
}

/** The parts of a refused request's `XMLHttpRequest` read here. */
export type RefusedRequest = Pick<XMLHttpRequest, "status" | "getResponseHeader" | "responseText">;

/**
 * The message of a write the server refused for its CSRF token, or of a
 * request made after the session ended, which the server sends as text
 * marked by the `X-CSRF-Refused` or the `X-Signed-Out` header; `null` for
 * any other answer.
 */
export function refusalMessage(xhr: RefusedRequest): string | null {
  const refused = xhr.status === 403 && xhr.getResponseHeader("X-CSRF-Refused") !== null;
  const signedOut = xhr.status === 401 && xhr.getResponseHeader("X-Signed-Out") !== null;
  return refused || signedOut ? xhr.responseText : null;
}

/**
 * Show a refused write's message at the top of the page's main content,
 * as an alert, so a screen reader announces it too: htmx swaps nothing
 * for a refusal, and the member would otherwise see no change.
 */
export function showRefusal(xhr: RefusedRequest): void {
  const message = refusalMessage(xhr);
  if (message === null) return;
  let notice = document.getElementById("csrf-refused");
  if (notice === null) {
    notice = document.createElement("p");
    notice.id = "csrf-refused";
    notice.setAttribute("role", "alert");
    notice.className =
      "mb-4 border border-border-default rounded px-3 py-2 text-sm text-text-danger";
    document.querySelector("main")?.prepend(notice);
  }
  notice.textContent = message;
}
