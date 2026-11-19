// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * A chat report carries the member's credentials as their other chat calls
 * do: the bearer token when one is stored, and otherwise, the session
 * cookie authenticating it, the page's CSRF token. The suite runs without a
 * DOM, so the page's meta tag, session storage and `fetch` are stubbed.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { reportMessage } from "./report";

const message = { from: "bob@chat.example", body: "hello", timestamp: 1_700_000_000 };

/** The request a report sends from a page holding `token`, with `bearer` stored. */
async function sent(token: string, bearer: string | null): Promise<RequestInit> {
  vi.stubGlobal("document", {
    querySelector: (selector: string) =>
      selector === 'meta[name="csrf-token"]' ? { content: token } : null,
  });
  vi.stubGlobal("sessionStorage", { getItem: () => bearer });
  const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 201 }));
  vi.stubGlobal("fetch", fetch);
  await reportMessage(message);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0]?.[0]).toBe("/api/v1/chat/reports");
  return fetch.mock.calls[0]?.[1] as RequestInit;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a chat report", () => {
  it("from a member signed in by cookie carries the CSRF token and no bearer", async () => {
    const request = await sent("t0k", null);
    expect(request.headers).toEqual({ "Content-Type": "application/json", "X-CSRF-Token": "t0k" });
  });

  it("from a member holding a bearer token carries that token", async () => {
    const request = await sent("t0k", "b34r");
    expect(request.headers).toEqual({
      "Content-Type": "application/json",
      Authorization: "Bearer b34r",
    });
  });

  it("names the sender, the text and when it was sent", async () => {
    const request = await sent("t0k", null);
    // Nothing else, so the browser's default sends the session cookie.
    expect(Object.keys(request).sort()).toEqual(["body", "headers", "method"]);
    expect(request.method).toBe("POST");
    expect(JSON.parse(request.body as string)).toEqual({
      target_addr: "bob@chat.example",
      message_content: "hello",
      message_date: "2023-11-14T22:13:20.000Z",
      reason: "other",
    });
  });

  it("never rejects, since nothing waits for it", async () => {
    vi.stubGlobal("document", { querySelector: () => null });
    vi.stubGlobal("sessionStorage", { getItem: () => null });
    vi.stubGlobal("fetch", () => Promise.reject(new TypeError("offline")));
    await expect(reportMessage(message)).resolves.toBeUndefined();
  });
});
