// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Security-header and Content-Security-Policy regression tests.
//
// These run against a live instance, which is what makes them worth
// having: the headers are applied by a tower layer wrapped around the
// whole router, and the CSP is only meaningful if the pages it governs
// actually load under it. Neither property is observable from a unit
// test of the header-construction functions.
//
// Three classes of regression are covered:
//
//   1. A header stops being emitted, or is emitted on pages but not on
//      static assets.
//   2. `connect-src` reverts to a scheme-wide `wss:` source, which
//      would permit exfiltration to any host over that scheme.
//   3. Inline script, an inline handler, or an inline style is
//      reintroduced, which the policy blocks silently: the console
//      records a violation, the page still renders, and the defect
//      survives review.
//
// The instance must be running with a seeded test actor; see
// smoke.spec.ts.

import { test, expect, type Page } from "@playwright/test";

const BASE_URL = process.env.BASE_URL ?? "http://localhost:8443";

/** Pages that must carry the full header set. */
const PAGES = ["/", "/auth/login", "/auth/register", "/chat", "/settings/chat", "/compose"];

/** Headers required on every response, with their exact values. */
const EXACT_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
};

/**
 * The WebSocket origin the policy must name.
 *
 * Derived from BASE_URL so the expectation tracks the deployment
 * rather than assuming one: the server emits `ws://` for a local
 * instance served over HTTP and `wss://` otherwise, and a test that
 * hard-coded either would pass only in one environment.
 */
function expectedWebSocketOrigin(): string {
  const url = new URL(BASE_URL);
  const scheme = url.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${url.host}`;
}

// ..... Header presence .....

test.describe("Security headers", () => {
  for (const path of PAGES) {
    test(`${path} carries the full header set`, async ({ request }) => {
      const res = await request.get(path, { maxRedirects: 0 });
      const headers = res.headers();

      for (const [name, value] of Object.entries(EXACT_HEADERS)) {
        expect(headers[name], `${path}: ${name}`).toBe(value);
      }

      expect(headers["content-security-policy"], `${path}: CSP`).toBeDefined();
      expect(headers["permissions-policy"], `${path}: Permissions-Policy`).toBeDefined();
    });
  }

  test("static assets carry the header set too", async ({ request }) => {
    // The layer is applied outside the /assets service. A regression
    // that moved it inside would leave exactly this response bare.
    const res = await request.get("/assets/htmx.js");
    expect(res.ok()).toBeTruthy();

    const headers = res.headers();
    for (const [name, value] of Object.entries(EXACT_HEADERS)) {
      expect(headers[name], `/assets/htmx.js: ${name}`).toBe(value);
    }
    expect(headers["content-security-policy"]).toBeDefined();
  });

  test("an error response carries the header set too", async ({ request }) => {
    const res = await request.get("/this-path-does-not-exist");
    expect(res.status()).toBe(404);
    expect(res.headers()["content-security-policy"]).toBeDefined();
  });
});

// ..... Policy content .....

test.describe("Content-Security-Policy", () => {
  test("denies by default and permits no unsafe source", async ({ request }) => {
    const res = await request.get("/auth/login", { maxRedirects: 0 });
    const csp = res.headers()["content-security-policy"];

    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");

    // Either would defeat the point of extracting the inline scripts.
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
  });

  test("pins the WebSocket host rather than the scheme", async ({ request }) => {
    const res = await request.get("/auth/login", { maxRedirects: 0 });
    const csp = res.headers()["content-security-policy"];

    expect(csp).toContain(`connect-src 'self' ${expectedWebSocketOrigin()}`);
    // A scheme-wide source permits exfiltration to any host.
    expect(csp).not.toMatch(/connect-src[^;]*\bwss:(?!\/\/)/);
    expect(csp).not.toMatch(/connect-src[^;]*\bws:(?!\/\/)/);
  });

  test("is emitted exactly once", async ({ request }) => {
    // Browsers enforce multiple policies as an intersection, so a
    // duplicate is safe but signals that the proxy and the
    // application have both started emitting one, which is the drift
    // the single-emitter decision exists to prevent.
    const res = await request.get("/auth/login", { maxRedirects: 0 });
    const raw = res
      .headersArray()
      .filter((h) => h.name.toLowerCase() === "content-security-policy");

    expect(raw).toHaveLength(1);
  });
});

// ..... Violations and inline script .....

/**
 * Collect `securitypolicyviolation` events fired on the page.
 *
 * The listener is registered through an init script so that it is in
 * place before any document script runs; a listener added after load
 * would miss violations raised during parsing.
 */
async function collectViolations(page: Page): Promise<string[]> {
  const violations: string[] = [];

  await page.exposeFunction("__recordCspViolation", (detail: string) => {
    violations.push(detail);
  });

  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      const event = e as SecurityPolicyViolationEvent;
      const record = `${event.violatedDirective} blocked ${event.blockedURI || "inline"} (${event.sourceFile ?? "?"}:${event.lineNumber ?? 0})`;
      (window as unknown as { __recordCspViolation?: (d: string) => void }).__recordCspViolation?.(
        record,
      );
    });
  });

  return violations;
}

test.describe("Policy compliance", () => {
  for (const path of PAGES) {
    test(`${path} loads with no policy violation and no inline script`, async ({ page }) => {
      const violations = await collectViolations(page);

      await page.goto(path, { waitUntil: "networkidle" });

      // Every script must be external, so that `script-src 'self'`
      // without 'unsafe-inline' is satisfiable.
      const inlineScripts = await page.evaluate(
        () => document.querySelectorAll("script:not([src])").length,
      );
      expect(inlineScripts, `${path}: inline <script> elements`).toBe(0);

      // Inline handlers and inline styles are blocked by the same
      // policy and fail just as silently.
      const inlineHandlers = await page.evaluate(
        () =>
          Array.from(document.querySelectorAll("*")).filter((el) =>
            Array.from(el.attributes).some((a) => a.name.startsWith("on")),
          ).length,
      );
      expect(inlineHandlers, `${path}: inline event handlers`).toBe(0);

      expect(violations, `${path}: CSP violations`).toEqual([]);
    });
  }

  test("the login flow raises no policy violation", async ({ page }) => {
    const violations = await collectViolations(page);

    await page.goto("/auth/login", { waitUntil: "networkidle" });
    await page.fill("#login-username", "testuser");
    await page.fill("#login-password", "not-the-real-password");
    await page.click("#login-form button[type=submit]");

    // The credentials are wrong on purpose: the assertion is about
    // the key derivation and fetch running under the policy at all,
    // not about the outcome of the attempt.
    await page.waitForTimeout(2000);

    expect(violations).toEqual([]);
  });
});

// ..... Asset provenance .....

test.describe("Asset provenance", () => {
  test("every script a page loads is named in the served manifest", async ({ page, request }) => {
    // The manifest is a set of hashes for files that exist. On its own
    // it constrains nothing about which files a page loads, so an
    // instance could add a same-origin script absent from the manifest
    // and every manifest entry would still verify. `script-src 'self'`
    // permits it. This closes that gap by checking the complement:
    // nothing outside the manifest is loaded.
    const res = await request.get("/.well-known/noombat/assets.json");
    test.skip(!res.ok(), "this deployment serves no asset manifest");

    const manifest = (await res.json()) as { assets?: Record<string, string> };
    const known = new Set(Object.keys(manifest.assets ?? {}));
    expect(known.size, "manifest lists no assets").toBeGreaterThan(0);

    for (const path of PAGES) {
      await page.goto(path, { waitUntil: "networkidle" });
      const origin = new URL(page.url()).origin;

      const sources = await page.evaluate(() =>
        Array.from(document.querySelectorAll("script[src]")).map(
          (el) => (el as HTMLScriptElement).src,
        ),
      );

      for (const src of sources) {
        const url = new URL(src);
        expect(url.origin, `${path}: ${src} is not same-origin`).toBe(origin);
        expect(
          url.pathname.startsWith("/assets/"),
          `${path}: ${url.pathname} is served from outside /assets/`,
        ).toBe(true);

        const relative = url.pathname.slice("/assets/".length);
        expect(
          known.has(relative),
          `${path}: ${url.pathname} is not named in the asset manifest`,
        ).toBe(true);
      }
    }
  });
});
