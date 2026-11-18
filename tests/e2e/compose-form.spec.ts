// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The compose page's form, a plain form post that htmx does not drive,
 * carries the session's CSRF token in a hidden field, and the server takes
 * it: the note is published and the browser lands on it. A write the
 * session cookie authenticates is refused without the token.
 *
 * Unlike most specs this one writes to a seeded account: each run
 * publishes one note, to followers only, and leaves it, since posts have
 * no route that deletes them.
 */

import { test, expect } from "@playwright/test";
import { authenticateBrowser, requireSession, sessionUsername } from "./session";

test.beforeEach(async ({ context, request }, testInfo) => {
  const token = await requireSession(request, testInfo.workerIndex);
  await authenticateBrowser(context, token);
});

test("the compose form publishes a note", async ({ page }, testInfo) => {
  const text = `Compose ${testInfo.workerIndex}-${Date.now()}`;
  const username = sessionUsername(testInfo.workerIndex);

  await page.goto("/compose");
  const form = page.locator('form[action$="/outbox"]');
  await expect(form.locator('input[name="csrf_token"]')).toHaveCount(1);
  await form.locator("textarea").first().fill(text);
  await form.locator('select[name="visibility"]').selectOption("followers");

  const [posted] = await Promise.all([
    page.waitForResponse(
      (response) => response.request().method() === "POST" && response.url().endsWith("/outbox"),
    ),
    form.locator('button[type="submit"]').click(),
  ]);
  expect(posted.status(), "the form post must not be refused").toBe(303);
  await expect(page).toHaveURL(new RegExp(`/users/${username}/posts/`));
  await expect(page.getByText(text)).toBeVisible();
});
