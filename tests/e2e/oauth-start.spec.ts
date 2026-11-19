// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The login page's ORCID button reaches the provider. A sign-in starts with
 * a form's POST and must leave for another site, which a redirect cannot do
 * under `form-action 'self'` in Chromium and WebKit: the start answers
 * with a page that moves on. The stack points ORCID at a stand-in.
 */

import { test, expect } from "@playwright/test";

test("the login page's ORCID button reaches the provider", async ({ page }) => {
  await page.goto("/auth/login");
  const home = new URL(page.url()).origin;
  await page.getByRole("button", { name: "Sign in with ORCID" }).click();
  await page.waitForURL(/\/oauth\/authorize\?/);
  const reached = new URL(page.url());
  expect(reached.origin, "the provider is another site").not.toBe(home);
  expect(reached.searchParams.get("state"), "the start's state reaches it").toBeTruthy();
});
