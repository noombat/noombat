// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * A settings list driven as a member drives it. The skills page's form
 * appends the skill it adds, and the skill's remove button takes the row,
 * and only that row, off the page. The route answers the removal with
 * 204, which htmx swaps only because base.html's htmx configuration says
 * so.
 *
 * Unlike the other specs this one writes to a seeded account: it adds two
 * skills and removes them again, through the API if the page did not.
 */

import type { APIRequestContext } from "@playwright/test";
import { test, expect } from "@playwright/test";
import { authenticateBrowser, requireSession, sessionUsername } from "./session";

let token = "";
let run = "";

/** Remove, through the API, every skill a run of this spec left behind. */
async function removeSkills(request: APIRequestContext, username: string, prefix: string) {
  const listed = await request.get(`/users/${username}/skills`);
  if (!listed.ok()) return;
  const skills = (await listed.json()) as { id: string; name: string }[];
  for (const skill of skills.filter((skill) => skill.name.startsWith(prefix))) {
    await request.delete(`/users/${username}/skills/${skill.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  }
}

test.beforeEach(async ({ context, request }, testInfo) => {
  token = await requireSession(request, testInfo.workerIndex);
  await authenticateBrowser(context, token);
  // The session accounts outlive a run, so the names are new each time.
  run = `Skill ${testInfo.workerIndex}-${Date.now()}`;
});

test.afterEach(async ({ request }, testInfo) => {
  await removeSkills(request, sessionUsername(testInfo.workerIndex), run);
});

test("a skill added on its page is removed without a reload", async ({ page }) => {
  const removed = `${run} removed`;
  const kept = `${run} kept`;

  await page.goto("/settings/skills");
  const form = page.locator('form[hx-post$="/skills"]');
  const row = (name: string) => page.locator("#skills-list > span").filter({ hasText: name });

  for (const name of [removed, kept]) {
    await form.locator('input[name="name"]').fill(name);
    await Promise.all([
      page.waitForResponse(
        (response) => response.request().method() === "POST" && response.url().endsWith("/skills"),
      ),
      form.locator('button[type="submit"]').click(),
    ]);
    await expect(row(name)).toHaveCount(1);
  }

  const [deleted] = await Promise.all([
    page.waitForResponse(
      (response) => response.request().method() === "DELETE" && response.url().includes("/skills/"),
    ),
    row(removed).locator("button").click(),
  ]);
  expect(deleted.status(), "the removal must be answered 204, as this test is about").toBe(204);
  await expect(row(removed)).toHaveCount(0);
  await expect(row(kept), "only the removed skill's row may leave the page").toHaveCount(1);

  await page.reload();
  await expect(row(removed)).toHaveCount(0);
});

test("a write the server refuses says so on the page", async ({ page }) => {
  const refused = `${run} refused`;

  await page.goto("/settings/skills");
  // A token the session never had, as a page left open across a sign-in
  // elsewhere holds.
  await page.evaluate(() => {
    document.querySelector('meta[name="csrf-token"]')?.setAttribute("content", "stale");
  });
  const form = page.locator('form[hx-post$="/skills"]');
  await form.locator('input[name="name"]').fill(refused);
  const [answer] = await Promise.all([
    page.waitForResponse(
      (response) => response.request().method() === "POST" && response.url().endsWith("/skills"),
    ),
    form.locator('button[type="submit"]').click(),
  ]);

  expect(answer.status(), "the stale token must be refused").toBe(403);
  await expect(page.getByRole("alert")).toContainText("Reload the page");
  await expect(page.locator("#skills-list > span").filter({ hasText: refused })).toHaveCount(0);
});
