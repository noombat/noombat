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
//   - A seeded test actor "testuser" (see smoke.spec.ts header).
//   - An admin-level bearer token in ADMIN_TOKEN (for authenticated
//     pages), or a valid session cookie set via the login flow.
//
// The tests are grouped by authentication level:
//   1. Unauthenticated pages (login, register, profile, feed, search).
//   2. Authenticated pages (settings, compose, chat, admin).
//
// For authenticated pages, the tests use the development-only admin
// bearer token to inject an Authorization header into the browser
// context via `extraHTTPHeaders`.
//
// Two variables are involved and they are not interchangeable. The
// server reads NOOMBAT_ADMIN_TOKEN to decide which token it accepts;
// this suite reads ADMIN_TOKEN to decide which one to present. CI must
// set both, to the same value. Locally, `ADMIN_TOKEN=... pnpm test:a11y`
// is enough.
//
// When ADMIN_TOKEN is absent the authenticated groups skip, which is
// convenient locally and unacceptable under CI, so CI is a hard error
// instead. See the guard below.

import { test, expect, expectNoViolations } from "./axe-fixture";

// ..... Configuration .....

const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "";

// Skipping when the token is absent is a convenience for local runs, and a
// trap in CI: it is silent, and a skipped accessibility suite looks exactly
// like a passing one. That is not hypothetical. CI set NOOMBAT_ADMIN_TOKEN
// (which the server reads) while this file read ADMIN_TOKEN, so the
// authenticated and admin groups, 21 of the 29 tests here, never ran there
// at all. Refuse to start rather than skip.
if (process.env.CI && ADMIN_TOKEN === "") {
  throw new Error(
    "ADMIN_TOKEN is empty under CI. The authenticated and admin accessibility " +
      "groups would skip silently. Set ADMIN_TOKEN to the same value as " +
      "NOOMBAT_ADMIN_TOKEN in the workflow.",
  );
}

// ..... Helper: wait for HTMX partials to settle .....

/**
 * Wait for any in-flight HTMX requests to complete. Falls back to a
 * short delay if HTMX is not present on the page.
 */
async function waitForHtmx(page: import("@playwright/test").Page): Promise<void> {
  try {
    await page.waitForFunction(
      () => {
        const htmx = (window as unknown as Record<string, unknown>)["htmx"];
        if (!htmx) return true;
        // The internal request queue is empty when no XHRs are in flight.
        return document.querySelectorAll(".htmx-request").length === 0;
      },
      { timeout: 5_000 },
    );
  } catch {
    // HTMX not loaded or timed out; proceed anyway.
  }
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
    await waitForHtmx(page);
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("profile page", async ({ page, axeScan }) => {
    await page.goto("/users/testuser");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("search page (empty query)", async ({ page, axeScan }) => {
    await page.goto("/search/html");
    const results = await axeScan();
    expectNoViolations(results);
  });

  test("search page (with query)", async ({ page, axeScan }) => {
    await page.goto("/search/html?q=test&index=profiles");
    await waitForHtmx(page);
    const results = await axeScan();
    expectNoViolations(results);
  });
});

// 2. AUTHENTICATED PAGES

test.describe("Accessibility: authenticated pages", () => {
  // Skip the entire group if no admin token is available. Local
  // convenience only: under CI the guard at the top of this file throws
  // before reaching here, so this cannot silently drop coverage there.
  // eslint-disable-next-line playwright/no-skipped-test -- conditional, and CI cannot reach it
  test.skip(
    () => ADMIN_TOKEN === "",
    "ADMIN_TOKEN not set; skipping authenticated-page accessibility tests",
  );

  test.use({
    extraHTTPHeaders: {
      Authorization: `Bearer ${ADMIN_TOKEN}`,
    },
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
    await waitForHtmx(page);
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
    await waitForHtmx(page);

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
