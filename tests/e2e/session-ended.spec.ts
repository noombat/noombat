// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * A part of a page that asks the server for more after the session has
 * ended says so, instead of filling with the login page. The privacy
 * settings page loads its preview with htmx; with the session cookie gone,
 * the server's redirect to the login page reaches htmx as a 401 carrying
 * the reason, which the page shows as an alert.
 */

import { test, expect } from "@playwright/test";
import { authenticateBrowser, requireSession } from "./session";

test("a preview asked for after the session ended says so, and the login page stays out", async ({
  context,
  page,
  request,
}, testInfo) => {
  await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
  await page.goto("/settings/privacy");
  await expect(page.locator("#privacy-preview > *").first()).toBeVisible();

  await context.clearCookies();
  const answered = page.waitForResponse((response) =>
    response.url().includes("/settings/privacy/preview?as=follower"),
  );
  await page.locator('[hx-get="/settings/privacy/preview?as=follower"]').click();
  expect((await answered).status()).toBe(401);

  await expect(page.locator("#csrf-refused[role=alert]")).toContainText("session has ended");
  await expect(page.locator("#privacy-preview form")).toHaveCount(0);
  await expect(page.locator("#privacy-preview input[type=password]")).toHaveCount(0);
  await expect(page).toHaveURL(/\/settings\/privacy$/);
});
