// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Trusted Types, as the server's policy requires them. The browser refuses
 * a plain string wherever it would become markup or code; only the front
 * end's three policies exist, and each lets through only its own strings.
 * The pages that build markup still work: htmx's answers through the
 * allowlist's parse, and the islands through Solid's templates. A page
 * that arrives without the directive says so.
 */

import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";
import { authenticateBrowser, requireSession } from "./session";

const REQUIRE = "require-trusted-types-for 'script'";
const POLICIES = "trusted-types noombat-parse noombat-solid default";

/** Trusted Types violations on the page, by directive and sample. */
async function watchTrustedTypes(page: Page): Promise<string[]> {
  const seen: string[] = [];
  await page.exposeFunction("__ttViolation", (entry: string) => seen.push(entry));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      if (/trusted-types/.test(event.effectiveDirective)) {
        void (window as unknown as { __ttViolation: (e: string) => void }).__ttViolation(
          `${event.effectiveDirective}: ${event.sample}`,
        );
      }
    });
  });
  return seen;
}

test("the policy requires Trusted Types and names the front end's policies", async ({
  request,
}) => {
  const csp = (await request.get("/")).headers()["content-security-policy"] ?? "";
  expect(csp).toContain(`${REQUIRE};`);
  expect(csp).toContain(`${POLICIES};`);
});

test("a plain string where markup is made is refused", async ({ page }) => {
  await page.goto("/");
  const outcome = await page.evaluate(() => {
    try {
      document.createElement("div").innerHTML = "<b>made here</b>";
      return "assigned";
    } catch (error) {
      return (error as Error).name;
    }
  });
  expect(outcome).toBe("TypeError");
  await expect(page.locator("#policy-missing")).toHaveCount(0);
});

test("htmx still swaps the feed in, through the allowlist's parse", async ({ page }) => {
  const violations = await watchTrustedTypes(page);
  await page.goto("/");
  await expect(page.locator("#feed-items #feed-loading")).toHaveCount(0);
  expect(violations).toEqual([]);
});

test("the islands render through Solid's templates", async ({
  context,
  page,
  request,
}, testInfo) => {
  await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
  const violations = await watchTrustedTypes(page);
  await page.goto("/compose");
  await page.locator('form[action$="/outbox"] textarea').first().fill("Rendered *here*.");
  await expect(page.locator(".noombat-editor__preview em")).toHaveText("here");
  await page.goto("/chat");
  await expect(page.locator("#chat-mount > *").first()).toBeVisible();
  expect(violations).toEqual([]);
});

test("a page that arrives without the directive says so", async ({ page }) => {
  await page.route(
    (url) => url.pathname === "/",
    async (route) => {
      const response = await route.fetch();
      const headers = { ...response.headers() };
      headers["content-security-policy"] = (headers["content-security-policy"] ?? "")
        .replace(`${REQUIRE}; `, "")
        .replace(`${POLICIES}; `, "");
      await route.fulfill({ response, headers });
    },
  );
  await page.goto("/");
  await expect(page.locator("main #policy-missing[role=alert]")).toBeVisible();
});
