// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Cross-browser smoke tests for the Noombat server.
//
// These tests run against a live Noombat instance (default: localhost:8443).
// The instance must be running with a seeded test actor before execution.
//
// Seeding (run once before the test suite):
//   INSERT INTO actors (actor_type, ap_id, username, domain,
//     public_key_pem, is_local)
//   VALUES ('individual', 'http://localhost:8443/users/testuser',
//     'testuser', 'localhost',
//     '-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----',
//     TRUE);

import { test, expect } from "@playwright/test";

// ── Health ──────────────────────────────────────────────────────

test.describe("Health", () => {
  test("GET /healthz returns 200", async ({ request }) => {
    const res = await request.get("/healthz");
    expect(res.status()).toBe(200);
  });
});

// ── NodeInfo ────────────────────────────────────────────────────

test.describe("NodeInfo", () => {
  test("well-known returns a link to /nodeinfo/2.1", async ({ request }) => {
    const res = await request.get("/.well-known/nodeinfo");
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.links).toBeDefined();
    expect(body.links[0].href).toContain("/nodeinfo/2.1");
  });

  test("nodeinfo 2.1 identifies software as noombat", async ({ request }) => {
    const res = await request.get("/nodeinfo/2.1");
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.software.name).toBe("noombat");
    expect(body.version).toBe("2.1");
  });
});

// ── WebFinger ───────────────────────────────────────────────────

test.describe("WebFinger", () => {
  test("returns 400 without resource parameter", async ({ request }) => {
    const res = await request.get("/.well-known/webfinger");
    expect(res.status()).toBe(400);
  });

  test("returns 404 for unknown user", async ({ request }) => {
    const res = await request.get(
      "/.well-known/webfinger?resource=acct:nobody@localhost"
    );
    expect(res.status()).toBe(404);
  });

  test("returns JRD for a known user", async ({ request }) => {
    const res = await request.get(
      "/.well-known/webfinger?resource=acct:testuser@localhost"
    );
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.subject).toBe("acct:testuser@localhost");
    expect(body.links[0].rel).toBe("self");
    expect(body.links[0].type).toBe("application/activity+json");
  });
});

// ── Actor (ActivityPub JSON) ────────────────────────────────────

test.describe("Actor — AP JSON", () => {
  test("returns AP actor when Accept: application/activity+json", async ({
    request,
  }) => {
    const res = await request.get("/users/testuser", {
      headers: { Accept: "application/activity+json" },
    });
    expect(res.ok()).toBeTruthy();
    const ct = res.headers()["content-type"] ?? "";
    expect(ct).toContain("application/activity+json");
    const body = await res.json();
    expect(body.type).toBe("Person");
    expect(body.preferredUsername).toBe("testuser");
    expect(body.inbox).toContain("/inbox");
    expect(body.outbox).toContain("/outbox");
    expect(body.publicKey).toBeDefined();
  });

  test("returns 404 for nonexistent actor", async ({ request }) => {
    const res = await request.get("/users/nonexistent", {
      headers: { Accept: "application/activity+json" },
    });
    expect(res.status()).toBe(404);
  });
});

// ── Actor (HTML profile page) ───────────────────────────────────

test.describe("Actor — HTML profile", () => {
  test("renders semantic HTML with ARIA landmarks", async ({ page }) => {
    await page.goto("/users/testuser");

    // The page has a skip-to-content link.
    const skipLink = page.locator("a.skip-link");
    await expect(skipLink).toBeAttached();

    // The page has a main landmark.
    const main = page.locator("main#main-content");
    await expect(main).toBeVisible();

    // The page has a navigation landmark.
    const nav = page.locator("nav");
    await expect(nav).toBeVisible();

    // The heading displays the username.
    const heading = page.locator("h1");
    await expect(heading).toContainText("testuser");
  });

  test("keyboard focus is visible on tab", async ({ page }) => {
    await page.goto("/users/testuser");

    // Press Tab to move focus to the first focusable element (skip link).
    await page.keyboard.press("Tab");
    const skipLink = page.locator("a.skip-link");
    await expect(skipLink).toBeFocused();
  });

  test("includes rel=alternate link for AP discovery", async ({ page }) => {
    await page.goto("/users/testuser");
    const link = page.locator('link[rel="alternate"][type="application/activity+json"]');
    await expect(link).toBeAttached();
  });
});

// ── Feed page ───────────────────────────────────────────────────

test.describe("Feed page", () => {
  test("renders with HTMX attributes", async ({ page }) => {
    await page.goto("/");

    const heading = page.locator("h1");
    await expect(heading).toBeVisible();

    // The feed container has HTMX trigger and swap attributes.
    const feedItems = page.locator("#feed-items");
    await expect(feedItems).toHaveAttribute("hx-get", /\/feed/);
    await expect(feedItems).toHaveAttribute("hx-trigger", "load");
    await expect(feedItems).toHaveAttribute("hx-swap", "innerHTML");
  });
});

// ── Outbox ──────────────────────────────────────────────────────

test.describe("Outbox", () => {
  test("GET outbox returns an OrderedCollection", async ({ request }) => {
    const res = await request.get("/users/testuser/outbox");
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.type).toBe("OrderedCollection");
    expect(typeof body.totalItems).toBe("number");
  });
});
