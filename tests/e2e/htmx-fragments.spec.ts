// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * htmx drops a script element that arrives in an answer it swaps in, even
 * when the page's htmx-config meta element asks it to run it, as a
 * modified server's page could. The feed page loads its items with htmx as
 * it opens; these tests answer that request with a fragment carrying a
 * same-origin script element, which the page's policy would let run, and
 * check the browser never asks for it. The setting does not cover the
 * other ways an answer can carry a script: an iframe's srcdoc, a
 * declarative shadow root, or a template's contents.
 */

import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

const PROBE = "/e2e-fragment-probe.js";

/** Answer the feed's items with a fragment carrying a script; record requests for it. */
async function serveScriptInFragment(page: Page): Promise<string[]> {
  const requested: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === PROBE) requested.push(request.url());
  });
  await page.route(
    (url) => url.pathname === "/feed",
    (route) =>
      route.fulfill({
        contentType: "text/html; charset=utf-8",
        body: `<p id="fragment-probe">swapped</p><script src="${PROBE}"></script>`,
      }),
  );
  await page.route(
    (url) => url.pathname === PROBE,
    (route) =>
      route.fulfill({
        contentType: "text/javascript",
        body: "document.documentElement.dataset.fragmentScriptRan = '1';",
      }),
  );
  return requested;
}

async function expectTheScriptNotRun(page: Page, requested: string[]) {
  await expect(page.locator("#fragment-probe")).toBeVisible();
  // htmx inserts a fragment's scripts with the rest of it, so once the
  // fragment shows, a script it kept would be in the page.
  await expect(page.locator(`script[src="${PROBE}"]`)).toHaveCount(0);
  expect(requested, "the browser asked for the fragment's script").toEqual([]);
  const ran = await page.evaluate(() => document.documentElement.dataset.fragmentScriptRan);
  expect(ran, "the fragment's script ran").toBeUndefined();
}

test("a script element in a fragment htmx swaps in does not run", async ({ page }) => {
  const requested = await serveScriptInFragment(page);
  await page.goto("/");
  await expectTheScriptNotRun(page, requested);
});

test("nor when the page's htmx configuration asks htmx to run it", async ({ page }) => {
  const requested = await serveScriptInFragment(page);
  await page.route(
    (url) => url.pathname === "/",
    async (route) => {
      const response = await route.fetch();
      const served = await response.text();
      const asking = served.replace(
        `content='{"includeIndicatorStyles":false,`,
        `content='{"includeIndicatorStyles":false,"allowScriptTags":true,`,
      );
      expect(asking, "the page's htmx-config meta element has changed shape").not.toBe(served);
      await route.fulfill({ response, body: asking });
    },
  );
  await page.goto("/");
  await expectTheScriptNotRun(page, requested);
});
