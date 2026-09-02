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
//     issue the sessions both authenticated groups sign in with.
//   - The seeded `e2e_admin` account, promoted to `instance_role =
//     'admin'` by `scripts/e2e-stack.sh` and by ci-e2e.yml.
//
// The tests are grouped by authentication level:
//   1. Unauthenticated pages (login, register, profile, feed, search).
//   2. Authenticated pages (settings, compose, chat).
//   3. Admin pages.
//
// Both authenticated groups sign a fixture account in and carry its
// session cookie, which is the only thing that identifies a caller.
// Every page in group 2 is behind `require_auth` or reads the
// principal's actor id, and every page in group 3 is behind
// `require_admin`, which reads `instance_role`. Without a session each
// redirects instead, to a page axe scans
// without violations.

import { test, expect, expectNoViolations } from "./axe-fixture";
import { authenticateBrowser, requireAdminSession, requireSession } from "./session";

// ..... Configuration .....

// The seeded article, addressed through the human-facing route alias.
// Public and so reachable unauthenticated; see smoke.spec.ts for what
// the seed contains and why it must be an article rather than a note.
const ARTICLE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000001";

// The seeded note, which renders post.html rather than article.html.
const NOTE_PATH = "/@testuser/posts/00000000-0000-4000-8000-000000000002";

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

// These pages need a session whose `instance_role` is admin. Anything
// less and `require_admin` answers `Redirect::temporary("/")`, which
// Playwright follows; the feed has no axe violations, so all five scans
// once passed having measured the feed.
//
// Hence a real session, and an assertion on the path actually served:
// without the second, the next redirect substitutes another page just as
// quietly as that one did.
test.describe("Accessibility: admin pages", () => {
  test.beforeEach(async ({ context, request }) => {
    await authenticateBrowser(context, await requireAdminSession(request));
  });

  async function expectAdminPageAccessible(
    page: import("@playwright/test").Page,
    axeScan: () => Promise<import("axe-core").AxeResults>,
    path: string,
  ): Promise<void> {
    await page.goto(path);
    expect(new URL(page.url()).pathname, `expected to be served ${path}`).toBe(path);
    expectNoViolations(await axeScan());
  }

  test("moderation queue", async ({ page, axeScan }) => {
    await expectAdminPageAccessible(page, axeScan, "/admin/moderation");
  });

  test("user management", async ({ page, axeScan }) => {
    await expectAdminPageAccessible(page, axeScan, "/admin/users");
  });

  test("domain management", async ({ page, axeScan }) => {
    await expectAdminPageAccessible(page, axeScan, "/admin/domains");
  });

  test("instance settings", async ({ page, axeScan }) => {
    await expectAdminPageAccessible(page, axeScan, "/admin/settings");
  });

  test("federation health", async ({ page, axeScan }) => {
    await expectAdminPageAccessible(page, axeScan, "/admin/federation");
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
