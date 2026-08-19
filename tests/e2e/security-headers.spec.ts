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
// Pages are split by authentication level, and the split is load-bearing.
// Every page behind `require_auth` answers an unauthenticated request
// with a 307 to /auth/login, and both the browser and the request
// context follow redirects by default, so a suite that presents no
// credential scans the login page under the name of each page behind
// one and reports a pass. The authenticated groups present a session and
// then assert that the page they asked for is the page they got; see
// `expectServedPage`.
//
// A session, not the development bearer token: that token resolves to a
// principal with no actor id and, on these four paths, no username
// either, so it is refused by exactly the pages this file is here to
// measure. See session.ts, which also holds the CI guard: a session that
// cannot be obtained is a hard error there rather than a silent skip.
//
// The instance must be running with a seeded test actor and article; see
// smoke.spec.ts.

import {
  test,
  expect,
  type APIRequestContext,
  type APIResponse,
  type Page,
} from "@playwright/test";

import { authenticateBrowser, requireSession } from "./session";

// ..... Configuration .....

const BASE_URL = process.env.BASE_URL ?? "http://localhost:8443";

/**
 * The seeded permalinks, one per template: the article renders
 * article.html, the note renders post.html. Held apart from the page
 * lists only because the ids are long; see smoke.spec.ts for what the
 * seed contains.
 */
const ARTICLE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000001";
const NOTE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000002";

/** Pages served to anyone, which must carry the full header set. */
const PUBLIC_PAGES = ["/", "/auth/login", "/auth/register", ARTICLE_PATH, NOTE_PATH];

/**
 * Pages behind `require_auth`, which must carry it too.
 *
 * /auth/upgrade is here because upgrade.html is the sole referrer of
 * /assets/upgrade.js, so nothing else puts that asset under the
 * manifest gate below.
 */
const AUTHENTICATED_PAGES = ["/chat", "/settings/chat", "/compose", "/auth/upgrade"];

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

// ..... Shared assertions .....

/** Assert one response carries every required header. */
function expectHeaderSet(res: APIResponse, path: string): void {
  const headers = res.headers();

  for (const [name, value] of Object.entries(EXACT_HEADERS)) {
    expect(headers[name], `${path}: ${name}`).toBe(value);
  }

  expect(headers["content-security-policy"], `${path}: CSP`).toBeDefined();
  expect(headers["permissions-policy"], `${path}: Permissions-Policy`).toBeDefined();
}

/**
 * Assert the browser is on the page that was requested.
 *
 * Without this, every assertion an authenticated group makes is
 * satisfied by the login page, which carries the same headers, loads
 * the same policy and has no inline script either. The path pins which
 * handler answered; the absence of the login form catches a future
 * redirect that preserved the path.
 */
async function expectServedPage(page: Page, path: string): Promise<void> {
  const expected = new URL(path, BASE_URL).pathname;
  expect(new URL(page.url()).pathname, `${path}: served ${page.url()} instead`).toBe(expected);
  await expect(page.locator("#login-form"), `${path}: the login page was served`).toHaveCount(0);
}

// ..... Header presence .....

test.describe("Security headers", () => {
  for (const path of PUBLIC_PAGES) {
    test(`${path} carries the full header set`, async ({ request }) => {
      const res = await request.get(path, { maxRedirects: 0 });
      expect(res.status(), `${path}: not served directly`).toBe(200);
      expectHeaderSet(res, path);
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

test.describe("Security headers: authenticated pages", () => {
  for (const path of AUTHENTICATED_PAGES) {
    test(`${path} carries the full header set`, async ({ request }, testInfo) => {
      const token = await requireSession(request, testInfo.workerIndex);
      // `maxRedirects: 0` turns the redirect into an observable status
      // rather than a silent hop, so this doubles as the identity
      // assertion for the request-level group: a 307 here means the
      // credential was not accepted and the rest of the group is
      // measuring the login page.
      const res = await request.get(path, {
        maxRedirects: 0,
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(res.status(), `${path}: not served, the credential was refused`).toBe(200);
      expectHeaderSet(res, path);
    });
  }
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

    // Featured images render an author-supplied absolute URL into
    // <img src>, unvalidated on both the local and the federated write
    // path. This directive is the only thing that stops that becoming a
    // per-reader IP disclosure to whatever host the URL names, and it
    // was the one directive neither suite asserted.
    expect(csp).toContain("img-src 'self' data:");

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

/** Assert the loaded page satisfies the policy it was served under. */
async function expectPolicyCompliance(
  page: Page,
  path: string,
  violations: string[],
): Promise<void> {
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
}

test.describe("Policy compliance", () => {
  for (const path of PUBLIC_PAGES) {
    test(`${path} loads with no policy violation and no inline script`, async ({ page }) => {
      const violations = await collectViolations(page);
      await page.goto(path);
      await expectPolicyCompliance(page, path, violations);
    });
  }

  test("the login flow raises no policy violation", async ({ page }) => {
    const violations = await collectViolations(page);

    await page.goto("/auth/login");
    await page.locator("#login-username").fill("testuser");
    await page.locator("#login-password").fill("not-the-real-password");

    // The credentials are wrong on purpose: the assertion is about the key
    // derivation and fetch running under the policy at all, not about the
    // outcome of the attempt. Wait for the POST that frontend/src/auth.ts
    // issues once it has derived the auth key, rather than for a fixed
    // interval, which would have no relationship to the thing waited for.
    //
    // Registered before the click, because Playwright does not buffer
    // network events: a response arriving in between is never seen and the
    // wait runs to its timeout.
    const loginPosted = page.waitForResponse(
      (r) => r.url().includes("/api/v1/auth/login") && r.request().method() === "POST",
      { timeout: 15_000 },
    );
    await page.locator("#login-form button[type=submit]").click();
    await loginPosted;

    expect(violations).toEqual([]);
  });
});

test.describe("Policy compliance: authenticated pages", () => {
  for (const path of AUTHENTICATED_PAGES) {
    test(`${path} loads with no policy violation and no inline script`, async ({
      page,
      context,
      request,
    }, testInfo) => {
      // The cookie rather than a header: the browser sends it with every
      // same-origin navigation, and the server prefers a header over it,
      // so setting both would put the request back on the credential
      // these pages refuse.
      await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
      const violations = await collectViolations(page);
      await page.goto(path);
      await expectServedPage(page, path);
      await expectPolicyCompliance(page, path, violations);
    });
  }
});

// ..... Asset provenance .....

/**
 * The asset names the served manifest lists, or null when this
 * deployment serves no manifest.
 */
async function servedManifest(request: APIRequestContext): Promise<Set<string> | null> {
  const res = await request.get("/.well-known/noombat/assets.json");
  if (!res.ok()) {
    // A deployment may legitimately serve no manifest, so this is a skip
    // locally. CI always serves one, because ci-e2e.yml generates it
    // before starting the server, so an absent manifest there means that
    // step regressed. Skipping would report that as a pass.
    if (process.env.CI) {
      throw new Error(
        `no asset manifest at /.well-known/noombat/assets.json (${res.status()}). ` +
          "ci-e2e.yml generates it before starting the server; without it the " +
          "provenance assertions below inspect nothing.",
      );
    }
    return null;
  }

  const manifest = (await res.json()) as { assets?: Record<string, string> };
  return new Set(Object.keys(manifest.assets ?? {}));
}

/**
 * Assert every subresource the loaded page pulls in is one the manifest
 * names.
 *
 * Scripts and stylesheets both, because `style-src 'self'` is as
 * permissive as `script-src 'self'`: a same-origin sheet absent from
 * the manifest loads exactly as readily as a same-origin script, and a
 * stylesheet can carry a request to an arbitrary host in a
 * `background-image` URL.
 */
async function expectManifestedAssets(page: Page, path: string, known: Set<string>): Promise<void> {
  const origin = new URL(page.url()).origin;

  const sources = await page.evaluate(() => [
    ...Array.from(document.querySelectorAll("script[src]")).map(
      (el) => (el as HTMLScriptElement).src,
    ),
    ...Array.from(document.querySelectorAll("link[rel~=stylesheet]")).map(
      (el) => (el as HTMLLinkElement).href,
    ),
  ]);

  for (const src of sources) {
    const url = new URL(src);
    expect(url.origin, `${path}: ${src} is not same-origin`).toBe(origin);
    expect(
      url.pathname.startsWith("/assets/"),
      `${path}: ${url.pathname} is served from outside /assets/`,
    ).toBe(true);

    const relative = url.pathname.slice("/assets/".length);
    expect(known.has(relative), `${path}: ${url.pathname} is not named in the asset manifest`).toBe(
      true,
    );
  }
}

test.describe("Asset provenance", () => {
  // The manifest is a set of hashes for files that exist. On its own
  // it constrains nothing about which files a page loads, so an
  // instance could add a same-origin subresource absent from the
  // manifest and every manifest entry would still verify. `script-src
  // 'self'` and `style-src 'self'` permit it. These tests close that
  // gap by checking the complement: nothing outside the manifest is
  // loaded.

  test("every asset a public page loads is named in the served manifest", async ({
    page,
    request,
  }) => {
    const known = await servedManifest(request);
    // Unreachable under CI, where servedManifest throws instead.
    // eslint-disable-next-line playwright/no-skipped-test -- deployment-conditional
    test.skip(known === null, "this deployment serves no asset manifest");
    expect(known?.size, "manifest lists no assets").toBeGreaterThan(0);

    for (const path of PUBLIC_PAGES) {
      await page.goto(path);
      await expectManifestedAssets(page, path, known ?? new Set());
    }
  });

  test.describe("authenticated pages", () => {
    test("every asset an authenticated page loads is named in the served manifest", async ({
      page,
      context,
      request,
    }, testInfo) => {
      await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));

      const known = await servedManifest(request);
      // Unreachable under CI, where servedManifest throws instead.
      // eslint-disable-next-line playwright/no-skipped-test -- deployment-conditional
      test.skip(known === null, "this deployment serves no asset manifest");
      expect(known?.size, "manifest lists no assets").toBeGreaterThan(0);

      for (const path of AUTHENTICATED_PAGES) {
        await page.goto(path);
        await expectServedPage(page, path);
        await expectManifestedAssets(page, path, known ?? new Set());
      }
    });
  });
});
