// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The chat and editor islands' stylesheets reach their pages. A script
 * entry does not load its own stylesheet: the server links it, by its
 * hashed name, from Vite's manifest.
 */

import { test, expect } from "@playwright/test";
import { authenticateBrowser, requireSession } from "./session";

test.beforeEach(async ({ context, request }, testInfo) => {
  const token = await requireSession(request, testInfo.workerIndex);
  await authenticateBrowser(context, token);
});

for (const [path, entry] of [
  ["/chat", "chat"],
  ["/compose", "editor"],
  ["/settings/profile", "editor"],
] as const) {
  test(`${path} links the ${entry} island's stylesheet`, async ({ page }) => {
    await page.goto(path);
    const link = page.locator(`link[rel="stylesheet"][href^="/assets/${entry}-"]`);
    await expect(link).toHaveCount(1);
    // Loaded and parsed, not only named: a missing or refused file
    // leaves the link without rules.
    const rules = await link.evaluate(
      (element) => (element as HTMLLinkElement).sheet?.cssRules.length ?? 0,
    );
    expect(rules, `${path}: the ${entry} stylesheet has no rules`).toBeGreaterThan(0);
  });
}

test("an asset keeps its year's caching when a member fetches it", async ({ page }) => {
  // The session's `private, no-store` covers what a route leaves open, and
  // `/assets` says how its files are cached.
  await page.goto("/chat");
  const href = await page
    .locator('link[rel="stylesheet"][href^="/assets/chat-"]')
    .getAttribute("href");
  const res = await page.request.get(href ?? "");
  expect(res.ok()).toBeTruthy();
  expect(res.headers()["cache-control"]).toBe("public, max-age=31536000, immutable");
});
