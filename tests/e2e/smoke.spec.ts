// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Cross-browser smoke tests for the Noombat server.
//
// These run against a live Noombat instance (default: localhost:8443),
// seeded by `scripts/e2e-stack.sh up` or by the matching statements in
// .github/workflows/ci-e2e.yml: an actor `testuser` and two posts it owns,
// each with a fixed id.
//
// post_type selects the template. The post route renders article.html for
// 'article' and post.html for anything else, so one post of each type is
// what keeps both templates covered.

import { test, expect } from "@playwright/test";

// ..... Seeded fixtures .....

const ARTICLE_ID = "00000000-0000-4000-8000-000000000001";
const ARTICLE_TITLE = "Seeded Test Article";
const ARTICLE_PATH = `/@testuser/posts/${ARTICLE_ID}`;

/** Both registered routes: `/@{username}` is an alias of `/users/{username}`. */
const ARTICLE_PATHS = [`/users/testuser/posts/${ARTICLE_ID}`, ARTICLE_PATH];

const NOTE_ID = "00000000-0000-4000-8000-000000000002";
const NOTE_PATH = `/@testuser/posts/${NOTE_ID}`;

// ..... Health .....

test.describe("Health", () => {
  test("GET /healthz returns 200", async ({ request }) => {
    const res = await request.get("/healthz");
    expect(res.status()).toBe(200);
  });
});

// ..... NodeInfo .....

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

// ..... WebFinger .....

test.describe("WebFinger", () => {
  test("returns 400 without resource parameter", async ({ request }) => {
    const res = await request.get("/.well-known/webfinger");
    expect(res.status()).toBe(400);
  });

  test("returns 404 for unknown user", async ({ request }) => {
    const res = await request.get("/.well-known/webfinger?resource=acct:nobody@localhost");
    expect(res.status()).toBe(404);
  });

  test("returns JRD for a known user", async ({ request }) => {
    const res = await request.get("/.well-known/webfinger?resource=acct:testuser@localhost");
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.subject).toBe("acct:testuser@localhost");
    expect(body.links[0].rel).toBe("self");
    expect(body.links[0].type).toBe("application/activity+json");
  });
});

// ..... Actor (ActivityPub JSON) .....

test.describe("Actor: AP JSON", () => {
  test("returns AP actor when Accept: application/activity+json", async ({ request }) => {
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

    // The @context must be an array containing the ActivityStreams
    // vocabulary and the W3C Security Vocabulary (required for the
    // publicKey sub-object to be valid JSON-LD).
    const ctx = body["@context"];
    expect(Array.isArray(ctx)).toBeTruthy();
    expect(ctx).toContain("https://www.w3.org/ns/activitystreams");
    expect(ctx).toContain("https://w3id.org/security/v1");
  });

  test("returns 404 for nonexistent actor", async ({ request }) => {
    const res = await request.get("/users/nonexistent", {
      headers: { Accept: "application/activity+json" },
    });
    expect(res.status()).toBe(404);
  });
});

// ..... Actor (HTML profile page) .....

test.describe("Actor: HTML profile", () => {
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

// ..... Feed page .....

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

// ..... Article permalink .....

test.describe("Article permalink", () => {
  for (const path of ARTICLE_PATHS) {
    test(`${path} renders the article template`, async ({ request }) => {
      const res = await request.get(path);
      expect(res.status()).toBe(200);

      const body = await res.text();
      expect(body).toContain(ARTICLE_TITLE);

      // A canonical link and a table of contents come from article.html
      // and from nowhere else. Their absence means post.html was
      // rendered instead, which puts article.html back under no
      // coverage while these tests still pass.
      expect(body, `${path}: post.html was rendered, not article.html`).toContain(
        'rel="canonical"',
      );
      // The entries are derived from the seeded Markdown, so this covers
      // heading extraction as well as the template.
      expect(body, `${path}: no table of contents was rendered`).toContain('href="#introduction"');
    });
  }

  test("the article page loads its stylesheet and its script", async ({ page }) => {
    // Asserted through the parsed DOM, not over the response text: a
    // runaway comment in the head block leaves all three references in
    // the bytes while the browser swallows them, so a substring check
    // passes against the broken page and only a parser tells them apart.
    await page.goto(ARTICLE_PATH);

    await expect(
      page.locator('link[rel="stylesheet"][href="/assets/main.css"]'),
      "the article page loads no stylesheet: <head> is being swallowed",
    ).toHaveCount(1);
    await expect(
      page.locator('script[src="/assets/htmx.js"]'),
      "the article page loads no htmx: <head> is being swallowed",
    ).toHaveCount(1);
    await expect(
      page.locator("a.skip-link"),
      "the article page has no skip link: the swallowed span reaches into <body>",
    ).toHaveCount(1);
  });
});

// ..... Note permalink .....

test.describe("Note permalink", () => {
  // post.html is the other half of the `post_type` branch, and extends
  // base.html exactly as article.html does, so it carries the same
  // exposure.

  test("the note permalink renders post.html", async ({ request }) => {
    const res = await request.get(NOTE_PATH);
    expect(res.status()).toBe(200);

    const body = await res.text();
    // `rel="canonical"` is emitted by article.html and by nothing else,
    // so its ABSENCE is what proves the note took the other branch. If
    // it appears here, both permalinks render the same template and one
    // of the two is uncovered again.
    expect(body, `${NOTE_PATH}: article.html was rendered, not post.html`).not.toContain(
      'rel="canonical"',
    );
  });

  test("the note page loads its stylesheet and its script", async ({ page }) => {
    // Asserted through the parsed DOM for the same reason as the article
    // case: the bytes survive inside a runaway comment, so only a parser
    // distinguishes a served <head> from a swallowed one.
    await page.goto(NOTE_PATH);

    await expect(
      page.locator('link[rel="stylesheet"][href="/assets/main.css"]'),
      "the note page loads no stylesheet: <head> is being swallowed",
    ).toHaveCount(1);
    await expect(
      page.locator('script[src="/assets/htmx.js"]'),
      "the note page loads no htmx: <head> is being swallowed",
    ).toHaveCount(1);
    await expect(
      page.locator("a.skip-link"),
      "the note page has no skip link: the swallowed span reaches into <body>",
    ).toHaveCount(1);
  });
});

// ..... Outbox .....

test.describe("Outbox", () => {
  test("GET outbox returns an OrderedCollection", async ({ request }) => {
    const res = await request.get("/users/testuser/outbox");
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.type).toBe("OrderedCollection");
    expect(typeof body.totalItems).toBe("number");
  });
});
