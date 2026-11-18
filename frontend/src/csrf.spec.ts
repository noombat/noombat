// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The CSRF token on the front end's writes: htmx's, `fetch`'s, and the chat
 * calls', which carry it only when the session cookie authenticates them.
 * The suites run without a DOM, so the page's meta tag and session storage
 * are stubbed.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { addCsrfHeader, refusalMessage, withCsrf } from "./csrf";
import { authHeaders } from "./chat/session";

/** A page carrying `token` in its meta tag, or none, with `bearer` stored. */
function page(token: string | null, bearer: string | null = null): void {
  vi.stubGlobal("document", {
    querySelector: (selector: string) =>
      selector === 'meta[name="csrf-token"]' && token !== null ? { content: token } : null,
  });
  vi.stubGlobal("sessionStorage", { getItem: () => bearer });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the CSRF token", () => {
  it("goes on every htmx write and on no read", () => {
    page("t0k");
    for (const verb of ["post", "put", "patch", "delete"]) {
      const detail = { verb, headers: {} as Record<string, string> };
      addCsrfHeader(detail);
      expect(detail.headers, verb).toEqual({ "X-CSRF-Token": "t0k" });
    }
    const read = { verb: "get", headers: {} as Record<string, string> };
    addCsrfHeader(read);
    expect(read.headers).toEqual({});
  });

  it("is added to a fetch's headers when the page carries one", () => {
    page("t0k");
    expect(withCsrf({ "Content-Type": "application/json" })).toEqual({
      "Content-Type": "application/json",
      "X-CSRF-Token": "t0k",
    });
  });

  it("is left out when the page carries none", () => {
    page(null);
    expect(withCsrf({ "Content-Type": "application/json" })).toEqual({
      "Content-Type": "application/json",
    });
    const detail = { verb: "post", headers: {} as Record<string, string> };
    addCsrfHeader(detail);
    expect(detail.headers).toEqual({});
  });

  it("goes on a chat call the cookie authenticates, not on one the bearer token does", () => {
    page("t0k");
    expect(authHeaders({ "Content-Type": "application/json" })).toEqual({
      "Content-Type": "application/json",
      "X-CSRF-Token": "t0k",
    });
    page("t0k", "bearer-token");
    expect(authHeaders({ "Content-Type": "application/json" })).toEqual({
      "Content-Type": "application/json",
      Authorization: "Bearer bearer-token",
    });
  });

  it("is named in the message of a refused write, and of nothing else", () => {
    const answer = (status: number, marked: boolean) => ({
      status,
      responseText: "Reload the page and try again.",
      getResponseHeader: (name: string) =>
        name.toLowerCase() === "x-csrf-refused" && marked ? "1" : null,
    });
    expect(refusalMessage(answer(403, true))).toBe("Reload the page and try again.");
    expect(refusalMessage(answer(403, false))).toBeNull();
    expect(refusalMessage(answer(500, true))).toBeNull();
  });
});
