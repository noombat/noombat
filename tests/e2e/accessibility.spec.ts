// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Automated WCAG 2.2 AA accessibility tests.
//
// These tests run axe-core against every user-facing page of the
// Noombat server. Each test navigates to a page, waits for it to
// settle (HTMX partial loads), and asserts zero WCAG 2.2 AA
// violations.
//
// Prerequisites:
//   - A running Noombat instance at BASE_URL (default: localhost:8443).
//   - A seeded test actor "testuser" and its seeded article (see the
//     smoke.spec.ts header).
//   - NOOMBAT_JWT_SECRET set on that instance, which is what lets it
//     issue the session the authenticated group signs in with.
//   - An admin-level bearer token in ADMIN_TOKEN, for the admin group.
//
// The tests are grouped by authentication level:
//   1. Unauthenticated pages (login, register, profile, feed, search).
//   2. Authenticated pages (settings, compose, chat).
//   3. Admin pages.
//
// The authenticated group signs a fixture account in and carries its
// session cookie; see session.ts for why the admin bearer token cannot
// stand in for one. Every page in that group is behind `require_auth`
// or reads the principal's actor id, and both answer a request holding
// the bearer token with a redirect to /auth/login, which axe scans
// without violations.
//
// Two variables are involved for the admin group and they are not
// interchangeable. The server reads NOOMBAT_ADMIN_TOKEN to decide which
// token it accepts; this suite reads ADMIN_TOKEN to decide which one to
// present. CI must set both, to the same value. Locally,
// `ADMIN_TOKEN=... pnpm test:a11y` is enough.
//
// When ADMIN_TOKEN is absent the admin group skips, which is convenient
// locally and unacceptable under CI, so CI is a hard error instead. See
// the guard below.

import { test, expect, expectNoViolations } from "./axe-fixture";
import { authenticateBrowser, requireSession } from "./session";

// ..... Configuration .....

const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "";

// The seeded article, addressed through the human-facing route alias.
// Public and so reachable unauthenticated; see smoke.spec.ts for what
// the seed contains and why it must be an article rather than a note.
const ARTICLE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000001";

// The seeded note, which renders post.html rather than article.html.
const NOTE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000002";

// Skipping when the token is absent is a convenience for local runs, and a
// trap in CI: it is silent, and a skipped accessibility suite looks exactly
// like a passing one. That is not hypothetical. CI set NOOMBAT_ADMIN_TOKEN
// (which the server reads) while this file read ADMIN_TOKEN, so the admin
// group never ran there at all. Refuse to start rather than skip. The
// authenticated group has the same guard, in session.ts.
if (process.env.CI && ADMIN_TOKEN === "") {
  throw new Error(
    "ADMIN_TOKEN is empty under CI. The admin accessibility group would skip " +
      "silently. Set ADMIN_TOKEN to the same value as NOOMBAT_ADMIN_TOKEN in " +
      "the workflow.",
  );
}

// ..... Helper: wait for HTMX partials to settle .....

/**
 * Wait for an HTMX target to receive its content.
 *
 * `selector` must name an element the partial itself supplies, not the
 * container: `#feed-items` ships a loading indicator as its own child,
 * so waiting for any child of it returns before the swap. A quiescence
 * check cannot serve either, since "no request in flight" is equally
 * true before one starts as after it ends.
 *
 * The timeout fails the test deliberately; a partial that never arrives
 * is a defect, not something to scan empty.
 */
async function waitForPartial(
  page: import("@playwright/test").Page,
  selector: string,
): Promise<void> {
  await expect(page.locator(selector).first()).toBeAttached({ timeout: 10_000 });
}

// 1. UNAUTHENTICATED PAGES

test.describe("Accessibility: unauthenticated pages", () => {
  test("login page", async ({ page, axeScan }) => {
    await page.goto("/auth/login");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("registration page", async ({ page, axeScan }) => {
    await page.goto("/auth/register");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("feed page", async ({ page, axeScan }) => {
    await page.goto("/");
    await waitForPartial(page, "#feed-items article");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("profile page", async ({ page, axeScan }) => {
    await page.goto("/users/testuser");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("article permalink", async ({ page, axeScan }) => {
    const res = await page.goto(ARTICLE_PATH);
    // axe reports no violations on a 404, so an unseeded fixture would
    // read as a pass.
    expect(res?.status(), "the seeded article was not served").toBe(200);
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("note permalink", async ({ page, axeScan }) => {
    const res = await page.goto(NOTE_PATH);
    expect(res?.status(), "the seeded note was not served").toBe(200);
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("search page (empty query)", async ({ page, axeScan }) => {
    await page.goto("/search/html");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("search page (with query)", async ({ page, axeScan }) => {
    // No wait: search.html carries no hx- attributes, so the results are
    // server-rendered and present in the first response.
    await page.goto("/search/html?q=test&index=profiles");
    const results = await axeScan();
    expectNoViolations(results);
  });
});

// 2. AUTHENTICATED PAGES

test.describe("Accessibility: authenticated pages", () => {
  // The session goes on the browser as a cookie rather than into an
  // Authorization header, because the server prefers a header over the
  // cookie: setting both would put every navigation back on the
  // credential these pages refuse.
  test.beforeEach(async ({ context, request }, testInfo) => {
    await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
  });

  // ----- Settings -----

  test("settings hub", async ({ page, axeScan }) => {
    await page.goto("/settings");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("edit profile", async ({ page, axeScan }) => {
    await page.goto("/settings/profile");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("edit experience", async ({ page, axeScan }) => {
    await page.goto("/settings/experience");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("edit education", async ({ page, axeScan }) => {
    await page.goto("/settings/education");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("edit skills", async ({ page, axeScan }) => {
    await page.goto("/settings/skills");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("edit publications", async ({ page, axeScan }) => {
    await page.goto("/settings/publications");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("edit verified links", async ({ page, axeScan }) => {
    await page.goto("/settings/links");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("post a job", async ({ page, axeScan }) => {
    await page.goto("/settings/jobs/new");
    const results = await axeScan();
    expectNoViolations(results);
  });

  // ----- Privacy & Safety -----

  test("privacy and safety settings", async ({ page, axeScan }) => {
    await page.goto("/settings/privacy");
    await waitForPartial(page, "#privacy-preview > *");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("blocked and muted accounts", async ({ page, axeScan }) => {
    await page.goto("/settings/blocked");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("follow requests", async ({ page, axeScan }) => {
    await page.goto("/settings/follow-requests");
    const results = await axeScan();
    expectNoViolations(results);
  });

  // ----- Chat -----

  test("chat credentials", async ({ page, axeScan }) => {
    await page.goto("/settings/chat");
    const results = await axeScan();
    expectNoViolations(results);
  });

  // ----- Account -----

  test("account migration", async ({ page, axeScan }) => {
    await page.goto("/settings/migrate");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("account settings (export and deletion)", async ({ page, axeScan }) => {
    await page.goto("/settings/account");
    const results = await axeScan();
    expectNoViolations(results);
  });

  // ----- Compose -----

  test("compose page", async ({ page, axeScan }) => {
    await page.goto("/compose");
    const results = await axeScan();
    expectNoViolations(results);
  });

  // ----- Password upgrade -----

  test("upgrade page", async ({ page, axeScan }) => {
    await page.goto("/auth/upgrade");
    // The page is behind require_auth, which answers a request without a
    // principal with a redirect to /auth/login. That page has no
    // violations either, so the scan alone cannot tell the two apart.
    await expect(page.locator("#upgrade-form"), "the upgrade page was not served").toHaveCount(1);
    const results = await axeScan();
    expectNoViolations(results);
  });

  // ----- Two-factor authentication -----

  test("TOTP setup page", async ({ page, axeScan }) => {
    await page.goto("/auth/totp");
    const results = await axeScan();
    expectNoViolations(results);
  });
});

// 3. ADMIN PAGES

test.describe("Accessibility: admin pages", () => {
  // As above: local convenience, unreachable under CI.
  // eslint-disable-next-line playwright/no-skipped-test -- conditional, and CI cannot reach it
  test.skip(
    () => ADMIN_TOKEN === "",
    "ADMIN_TOKEN not set; skipping admin-page accessibility tests",
  );

  test.use({
    extraHTTPHeaders: {
      Authorization: `Bearer ${ADMIN_TOKEN}`,
    },
  });

  test("moderation queue", async ({ page, axeScan }) => {
    await page.goto("/admin/moderation");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("user management", async ({ page, axeScan }) => {
    await page.goto("/admin/users");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("domain management", async ({ page, axeScan }) => {
    await page.goto("/admin/domains");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("instance settings", async ({ page, axeScan }) => {
    await page.goto("/admin/settings");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("federation health", async ({ page, axeScan }) => {
    await page.goto("/admin/federation");
    const results = await axeScan();
    expectNoViolations(results);
  });
});

// ..... Live region announcements .....
//
// A live region announces reliably only when it is already present
// and exposed and its content then mutates.
//
// These assertions cover one persistent region in base.html,
// updated out of band by the feed handler.

test.describe("Assistive-technology status region", () => {
  const PAGES = ["/", "/auth/login", "/auth/register"];

  for (const path of PAGES) {
    test(`${path} carries a persistent status region`, async ({ page }) => {
      await page.goto(path);

      const region = page.locator("#a11y-status");
      await expect(region).toHaveCount(1);
      await expect(region).toHaveRole("status");

      // `sr-only` hides the region visually by clipping it, not with
      // `display: none` or `visibility: hidden`, either of which would
      // remove it from the accessibility tree and defeat the purpose.
      const hiding = await region.evaluate((el) => {
        const s = getComputedStyle(el);
        return { display: s.display, visibility: s.visibility };
      });
      expect(hiding.display, `${path}: region is display:none`).not.toBe("none");
      expect(hiding.visibility, `${path}: region is visibility:hidden`).not.toBe("hidden");
    });
  }

  test("the feed announces its result into the region", async ({ page }) => {
    // The region starts empty and is filled by an out-of-band swap when
    // the feed partial arrives. Either outcome is a valid announcement:
    // a post count, or the end-of-feed message when there are none.
    await page.goto("/");

    const region = page.locator("#a11y-status");
    await expect(region).not.toBeEmpty();
  });

  test("no hidden element claims to be a live region", async ({ page }) => {
    // A region removed from the accessibility tree cannot announce, so
    // marking one live is at best inert and at worst misleading to a
    // reviewer.
    await page.goto("/");
    // Unlike the two tests above, this one scans with `page.evaluate`,
    // which does not retry. Without an explicit settle it reads the
    // page before the feed partial lands, so it would be scanning
    // almost nothing. `networkidle` did not wait for the partial
    // either: both it and the load event observe 18 nodes here.
    await waitForPartial(page, "#feed-items article");

    const offenders = await page.evaluate(() =>
      Array.from(document.querySelectorAll("[aria-live], [role=status], [role=alert]"))
        .filter((el) => {
          const s = getComputedStyle(el);
          return s.display === "none" || s.visibility === "hidden";
        })
        .map((el) => el.tagName.toLowerCase() + (el.id ? `#${el.id}` : "")),
    );

    expect(offenders, "live regions hidden from the accessibility tree").toEqual([]);
  });
});
