// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * At 320 CSS pixels no page scrolls sideways (WCAG 1.4.10, Reflow), with
 * the navigation menu closed or open, and the bar's links and controls sit
 * behind its Menu disclosure until it is opened.
 *
 * The page's scrollWidth is compared with the width set here, not with
 * window.innerWidth: a phone browser (Chromium's mobile emulation) zooms
 * out to fit content that overflows, and innerWidth grows with the page.
 *
 * Each page's menu is opened by pointer and the items it reveals are
 * asserted visible, not only measured: a width check alone passes when
 * opening the menu draws nothing. One test opens it from the keyboard.
 */

import { test, expect, type Page } from "@playwright/test";
import { authenticateBrowser, requireAdminSession, requireSession } from "./session";

const WIDTH = 320;

const ARTICLE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000001";
const NOTE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000002";

const SIGNED_OUT = [
  "/",
  "/auth/login",
  "/auth/register",
  "/users/testuser",
  "/search/html",
  "/search/html?q=test&index=profiles",
  ARTICLE_PATH,
  NOTE_PATH,
];

const SIGNED_IN = [
  "/",
  "/compose",
  "/chat",
  "/settings",
  "/settings/profile",
  "/settings/experience",
  "/settings/education",
  "/settings/skills",
  "/settings/publications",
  "/settings/links",
  "/settings/jobs/new",
  "/settings/privacy",
  "/settings/blocked",
  "/settings/follow-requests",
  "/settings/chat",
  "/settings/migrate",
  "/settings/account",
  "/auth/upgrade",
  "/auth/totp",
];

const ADMIN = [
  "/admin/moderation",
  "/admin/users",
  "/admin/domains",
  "/admin/settings",
  "/admin/federation",
];

/**
 * Content an htmx partial supplies after the page loads, which the width
 * must include. Each selector names an element of the partial itself: the
 * feed's container ships a loading indicator as its own child.
 */
const PARTIALS: Record<string, string> = {
  "/": "#feed-items article",
  "/settings/privacy": "#privacy-preview > *",
};

test.use({ viewport: { width: WIDTH, height: 640 } });

async function pageWidth(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth);
}

/** The main bar is the body's own nav; other pages add navs inside main. */
function menu(page: Page) {
  return page.locator("body > nav > details > summary");
}

function menuItems(page: Page) {
  return page.locator("body > nav > details + div");
}

async function expectReflows(page: Page, path: string): Promise<void> {
  const response = await page.goto(path);
  expect(response?.status(), `${path} answered`).toBe(200);
  const served = new URL(path, page.url()).pathname;
  expect(new URL(page.url()).pathname, `expected to be served ${path}`).toBe(served);
  const partial = PARTIALS[path];
  if (partial) {
    await expect(page.locator(partial).first()).toBeAttached({ timeout: 10_000 });
  }
  expect(await pageWidth(page), `${path}, menu closed`).toBeLessThanOrEqual(WIDTH);
  await menu(page).click();
  await expect(menuItems(page), `${path}, menu opened`).toBeVisible();
  expect(await pageWidth(page), `${path}, menu open`).toBeLessThanOrEqual(WIDTH);
}

test.describe("Reflow at 320 pixels, signed out", () => {
  for (const path of SIGNED_OUT) {
    test(path, async ({ page }) => {
      await expectReflows(page, path);
    });
  }
});

test.describe("Reflow at 320 pixels, signed in", () => {
  test.beforeEach(async ({ context, request }, testInfo) => {
    await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
  });

  for (const path of SIGNED_IN) {
    test(path, async ({ page }) => {
      await expectReflows(page, path);
    });
  }
});

test.describe("Reflow at 320 pixels, admin pages", () => {
  test.beforeEach(async ({ context, request }) => {
    await authenticateBrowser(context, await requireAdminSession(request));
  });

  for (const path of ADMIN) {
    test(path, async ({ page }) => {
      await expectReflows(page, path);
    });
  }
});

/**
 * Usernames run to 30 characters with no break point, and display names and
 * a remote author's name to any length; the seeded ones are short. Each test
 * writes a long name into the served page and requires that it wraps.
 */
test.describe("Reflow at 320 pixels, long names", () => {
  const NAME = "m".repeat(30);

  async function widen(page: Page, selector: string, text: string): Promise<void> {
    const targets = page.locator(selector);
    expect(await targets.count(), `${selector} on ${page.url()}`).toBeGreaterThan(0);
    await targets.evaluateAll((elements, value) => {
      for (const element of elements) element.textContent = value;
    }, text);
  }

  test("profile heading and handle", async ({ page }) => {
    await page.goto("/users/testuser");
    await widen(page, "main header h1", "m".repeat(40));
    await widen(page, "main header p[aria-label]", `@${NAME}@example.org`);
    expect(await pageWidth(page)).toBeLessThanOrEqual(WIDTH);
  });

  test("feed post headers", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(PARTIALS["/"]).first()).toBeAttached({ timeout: 10_000 });
    await widen(page, "#feed-items article header a[href^='/users/']", NAME);
    expect(await pageWidth(page)).toBeLessThanOrEqual(WIDTH);
  });

  for (const [kind, path] of [
    ["note", NOTE_PATH],
    ["article", ARTICLE_PATH],
  ]) {
    test(`${kind} permalink header`, async ({ page }) => {
      await page.goto(path);
      await widen(page, "main article a[href^='/users/']", NAME);
      expect(await pageWidth(page)).toBeLessThanOrEqual(WIDTH);
    });
  }
});

test.describe("The navigation menu", () => {
  function signIn(page: Page) {
    return page.locator("body > nav").getByRole("link", { name: "Sign in" });
  }

  test("opens and closes on a pointer press", async ({ page }) => {
    await page.goto("/auth/login");
    await expect(menu(page)).toBeVisible();
    await expect(signIn(page)).toBeHidden();
    await menu(page).click();
    await expect(signIn(page)).toBeVisible();
    await expect(page.locator("body > nav form").first()).toBeVisible();
    await menu(page).click();
    await expect(signIn(page)).toBeHidden();
  });

  test("is reached with Tab and opened with Enter", async ({ page }) => {
    await page.goto("/auth/login");
    await page.locator("body > nav > a").first().focus();
    await page.keyboard.press("Tab");
    await expect(menu(page)).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(signIn(page)).toBeVisible();
  });

  test("wraps a 30-character username rather than widening the page", async ({
    page,
    context,
    request,
  }, testInfo) => {
    await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
    await page.goto("/settings");
    await page.locator('body > nav a[href^="/@"]').evaluate((link) => {
      link.textContent = `@${"m".repeat(30)}`;
    });
    await menu(page).click();
    await expect(menuItems(page)).toBeVisible();
    expect(await pageWidth(page)).toBeLessThanOrEqual(WIDTH);
  });

  test("is not shown on a wide screen, where the bar's items are", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto("/auth/login");
    await expect(menu(page)).toBeHidden();
    await expect(signIn(page)).toBeVisible();
  });
});
