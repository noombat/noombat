// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * What a modified server could send htmx, and what reaches the page.
 *
 * The feed page loads its items with htmx as it opens. Most tests here
 * answer that request as such a server could: markup that runs a script,
 * loads a stylesheet, moves the page or changes its title, and headers
 * that steer htmx. Each checks that the answer's allowed part arrived and
 * nothing else did. The editor's preview is answered the same way. Each
 * group names the part of `frontend/src/htmx.ts` that stops it, and fails
 * when that part is taken out, but for a few cases a second part also
 * stops: a title (`ignoreTitle`), a pushed address (history off), and the
 * script elements htmx drops itself (`allowScriptTags` off).
 *
 * The last test is the other side: honest answers lose nothing. It runs
 * the pages whose parts htmx loads, and the editor's preview of text using
 * every element members may, and fails if the allowlist removed anything,
 * which `fragment.ts` reports on the console.
 */

import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";
import { authenticateBrowser, requireSession } from "./session";

const PROBE = "/e2e-fragment-probe";
const ELSEWHERE = "https://elsewhere.test";
// Marked by a class: the allowlist keeps an `id` only in the honest patterns.
const SHOWN = `<p class="fragment-probe">swapped</p>`;

interface Watch {
  /** Requests for the probe's resources or for elsewhere. */
  asked: string[];
  /** Policy violations, by directive. */
  violations: string[];
  /** What `fragment.ts` reported removing. */
  removed: string[];
  /** Navigations of the page itself, the first load included. */
  navigations: number;
}

/** Record what the page asks for, what the policy refuses and what the allowlist removes. */
async function watch(page: Page): Promise<Watch> {
  const seen: Watch = { asked: [], violations: [], removed: [], navigations: 0 };
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) seen.navigations += 1;
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith(PROBE) || url.origin === ELSEWHERE) seen.asked.push(request.url());
  });
  page.on("console", (message) => {
    if (message.text().startsWith("noombat: removed")) seen.removed.push(message.text());
  });
  await page.exposeFunction("__violation", (directive: string) => seen.violations.push(directive));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      void (window as unknown as { __violation: (d: string) => void }).__violation(
        event.effectiveDirective,
      );
    });
    // The page's own title, before htmx has swapped anything in.
    document.addEventListener("DOMContentLoaded", () => {
      (window as unknown as { __title: string }).__title = document.title;
    });
    document.addEventListener("htmx:afterSettle", () => {
      const w = window as unknown as { __settled?: number };
      w.__settled = (w.__settled ?? 0) + 1;
    });
  });
  await page.route(
    (url) => url.pathname.startsWith(PROBE),
    (route) =>
      route.fulfill({
        contentType: route.request().url().endsWith(".css") ? "text/css" : "text/javascript",
        body: route.request().url().endsWith(".css")
          ? "body{outline:3px solid red}"
          : "document.documentElement.dataset.probeRan='1'",
      }),
  );
  await page.route(`${ELSEWHERE}/**`, (route) => route.fulfill({ body: "elsewhere" }));
  return seen;
}

/** Answer the feed's htmx request with `body` and `headers`, once. */
async function answerFeed(page: Page, body: string, headers: Record<string, string> = {}) {
  await page.route(
    (url) => url.pathname === "/feed",
    (route) =>
      route.fulfill({ contentType: "text/html; charset=utf-8", headers, body: SHOWN + body }),
    { times: 1 },
  );
}

/** Open the feed page and wait until htmx has swapped its answer in and settled. */
async function openFeed(page: Page) {
  await page.goto("/");
  await expect(page.locator(".fragment-probe")).toBeVisible();
  await page.waitForFunction(() => ((window as { __settled?: number }).__settled ?? 0) >= 1);
}

/** Nothing the answer carried beyond the allowlist is in the page, ran, loaded or moved it. */
async function expectNothingGotThrough(page: Page, seen: Watch) {
  const found = await page.evaluate(() => ({
    elements: Array.from(
      document.querySelectorAll(
        "#feed-items :is(script, iframe, template, link, meta, style, base, title, svg, noscript, object, embed, form, font)",
      ),
    ).map((element) => element.localName),
    shadowRoots: Array.from(document.querySelectorAll("#feed-items *")).filter(
      (element) => element.shadowRoot !== null,
    ).length,
    ran: document.documentElement.dataset.probeRan ?? null,
    title: document.title,
    ownTitle: (window as unknown as { __title: string }).__title,
    path: location.pathname + location.search,
  }));
  expect(found.elements, "elements the allowlist should have removed").toEqual([]);
  expect(found.shadowRoots, "a declarative shadow root was attached").toBe(0);
  expect(found.ran, "the answer's script ran").toBeNull();
  expect(found.title, "the answer changed the page's title").toBe(found.ownTitle);
  expect(found.path, "the answer moved the page").toBe("/");
  expect(seen.navigations, "the page was loaded again or moved").toBe(1);
  expect(seen.asked, "the page asked for the answer's resources or went elsewhere").toEqual([]);
  expect(seen.violations, "the answer reached the policy").toEqual([]);
}

/** Markup a modified answer could carry; `fragment.ts`'s parse removes it (part 3). */
const MARKUP: Record<string, string> = {
  "a script element": `<script src="${PROBE}.js"></script>`,
  "a script in an iframe's srcdoc": `<iframe srcdoc="<script src='${PROBE}.js'></script>"></iframe>`,
  "a script in a declarative shadow root": `<div><template shadowrootmode="open"><script src="${PROBE}.js"></script></template></div>`,
  "a script in a template-wrapped out-of-band element": `<template><span id="a11y-status" hx-swap-oob="innerHTML"><script src="${PROBE}.js"></script></span></template>`,
  "a script in an hx-partial": `<hx-partial hx-target="#feed-loading"><script src="${PROBE}.js"></script></hx-partial>`,
  "an SVG script": `<svg><script href="${PROBE}.js"></script></svg>`,
  "a script in a foreignObject": `<svg><foreignObject><script src="${PROBE}.js"></script></foreignObject></svg>`,
  "a script in a MathML annotation": `<math><annotation-xml encoding="text/html"><script src="${PROBE}.js"></script></annotation-xml></math>`,
  "a script in noscript": `<noscript><script src="${PROBE}.js"></script></noscript>`,
  "a stylesheet": `<link rel="stylesheet" href="${PROBE}.css">`,
  "a stylesheet in a shadow root": `<div><template shadowrootmode="open"><link rel="stylesheet" href="${PROBE}.css"></template></div>`,
  "an alternate stylesheet chosen by meta": `<meta http-equiv="default-style" content="alt"><link rel="alternate stylesheet" title="alt" href="${PROBE}.css">`,
  "a meta refresh": `<meta http-equiv="refresh" content="0;url=${ELSEWHERE}/moved">`,
  "a meta refresh in noscript": `<noscript><meta http-equiv="refresh" content="0;url=${ELSEWHERE}/moved"></noscript>`,
  "a title": `<title>Spoofed</title>`,
  // The answer closes htmx's wrapper and names an element "body", which
  // shadows the parsed document's body for any code reading doc.body.
  "a frame behind an element named body": `<iframe srcdoc="<script src='${PROBE}.js'></script>"></iframe></template><img name="body">`,
  "a frame behind a form named body": `<iframe srcdoc="<script src='${PROBE}.js'></script>"></iframe></template><form name="body"></form>`,
  "a pushed URL": `<div hx-get="/feed?again=1" hx-trigger="load" hx-push-url="/pushed">x</div>`,
  "a presentational element": `<font color="#010203">presentational</font>`,
  "a form posting elsewhere": `<form action="${ELSEWHERE}/steal" method="post"><input name="p" type="password"><button>go</button></form>`,
};

test.describe("markup in an answer (the parse)", () => {
  for (const [name, markup] of Object.entries(MARKUP)) {
    test(`${name} does not reach the page`, async ({ page }) => {
      const seen = await watch(page);
      await answerFeed(page, markup);
      await page.goto("/");
      await expect(page.locator(".fragment-probe")).toBeVisible();
      await page.waitForFunction(() => ((window as { __settled?: number }).__settled ?? 0) >= 1);
      await expectNothingGotThrough(page, seen);
    });
  }

  test("a style attribute is removed before it applies", async ({ page }) => {
    const seen = await watch(page);
    await answerFeed(page, `<p class="styled" style="outline:3px solid red">styled</p>`);
    await openFeed(page);
    await expect(page.locator("#feed-items .styled")).toHaveCount(1);
    await expect(page.locator("#feed-items [style]")).toHaveCount(0);
    // Chromium and WebKit report the attribute to the policy as they parse
    // it, before it is removed; nothing else may reach the policy.
    expect(seen.violations.filter((directive) => directive !== "style-src-attr")).toEqual([]);
  });

  test("an id or a target outside the honest patterns is removed", async ({ page }) => {
    await watch(page);
    await answerFeed(
      page,
      `<span id="feed-loading">shadow</span><button hx-delete="/x" hx-target="body" type="button">b</button>` +
        `<button hx-delete="/users/x/skills/1" hx-target="#skill-00000000-0000-4000-8000-000000000000" type="button">ok</button>` +
        `<button class="outside" hx-delete="/x" hx-target="closest div" type="button">c</button>` +
        `<div><button class="inside" hx-delete="/x" hx-target="closest div" type="button">d</button></div>` +
        `<span class="owner" aria-owns="feed-items" aria-label="kept">o</span>` +
        `<div class="second-status" id="a11y-status">s</div>`,
    );
    await openFeed(page);
    const items = page.locator("#feed-items");
    await expect(items.locator("span:not([id])", { hasText: "shadow" })).toHaveCount(1);
    await expect(items.locator('[hx-target="body"]')).toHaveCount(0);
    await expect(items.locator('[hx-target^="#skill-"]')).toHaveCount(1);
    // A target around the answer, in the page, is refused; one inside it is kept.
    await expect(items.locator(".outside[hx-target]")).toHaveCount(0);
    await expect(items.locator(".inside[hx-target]")).toHaveCount(1);
    await expect(items.locator(".owner[aria-owns]")).toHaveCount(0);
    await expect(items.locator('.owner[aria-label="kept"]')).toHaveCount(1);
    await expect(items.locator(".second-status[id]")).toHaveCount(0);
  });
});

/** Headers a modified answer could send; `htmx.ts` hides them from htmx (part 2). */
const HEADERS: Record<string, Record<string, string>> = {
  "HX-Redirect": { "HX-Redirect": `${ELSEWHERE}/redirected` },
  "HX-Refresh": { "HX-Refresh": "true" },
  "HX-Location": { "HX-Location": "/feed?located=1" },
  "HX-Push-Url": { "HX-Push-Url": "/pushed" },
  "HX-Retarget": { "HX-Retarget": "body", "HX-Reswap": "innerHTML" },
};

test.describe("headers on an answer", () => {
  for (const [name, headers] of Object.entries(HEADERS)) {
    test(`${name} does not move the page or steer the swap`, async ({ page }) => {
      const seen = await watch(page);
      await answerFeed(page, "", headers);
      await page.goto("/");
      // htmx acts on these headers instead of swapping, or before it does,
      // so the answer showing in its place is half of the check.
      await expect(page.locator("#feed-items .fragment-probe")).toBeVisible();
      await page.waitForFunction(() => ((window as { __settled?: number }).__settled ?? 0) >= 1);
      await expectNothingGotThrough(page, seen);
    });
  }
});

test.describe("the page's htmx configuration (the frozen configuration)", () => {
  test("a meta element the server adds changes no setting", async ({ page }) => {
    const seen = await watch(page);
    await answerFeed(page, `<script src="${PROBE}.js"></script>`);
    await page.route(
      (url) => url.pathname === "/",
      async (route) => {
        const response = await route.fetch();
        const asking = (await response.text()).replace(
          "<head>",
          `<head><meta name="htmx-config" content='{"includeIndicatorStyles":true,"allowScriptTags":true,"allowEval":true,"historyEnabled":true,"selfRequestsOnly":false}'>`,
        );
        await route.fulfill({ response, body: asking });
      },
    );
    await page.goto("/");
    await expect(page.locator(".fragment-probe")).toBeVisible();
    await page.waitForFunction(() => ((window as { __settled?: number }).__settled ?? 0) >= 1);
    // htmx injects a style element at start-up unless the setting is off.
    await expect(page.locator("head style")).toHaveCount(0);
    await expectNothingGotThrough(page, seen);
  });
});

test.describe("the editor's preview (the same parse)", () => {
  test("carries nothing the allowlist does not name", async ({
    context,
    page,
    request,
  }, testInfo) => {
    await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
    const seen = await watch(page);
    await page.route(
      (url) => url.pathname === "/api/v1/preview",
      (route) =>
        route.fulfill({
          contentType: "text/html; charset=utf-8",
          body:
            `<p class="preview-probe">preview</p>` +
            `<iframe srcdoc="<script src='${PROBE}.js'></script>"></iframe>` +
            `<link rel="stylesheet" href="${PROBE}.css">` +
            `<meta http-equiv="refresh" content="0;url=${ELSEWHERE}/moved">` +
            `<img src="x" alt="" onerror="document.documentElement.dataset.probeRan='1'">`,
        }),
    );
    await page.goto("/compose");
    await page.locator("form textarea").first().fill("Some text to preview.");
    const box = page.locator(".noombat-editor__preview");
    await expect(box.locator(".preview-probe")).toHaveCount(1);
    await expect(box.locator("iframe, link, meta, script")).toHaveCount(0);
    await expect(box.locator("img[onerror]")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.dataset.probeRan ?? null)).toBeNull();
    expect(page.url()).toMatch(/\/compose$/);
    expect(seen.asked).toEqual([]);
  });
});

/**
 * Markup members may use in a post, through noombat-markup's ammonia
 * profile: every tag it allows with its attributes, formulas, a task list
 * and a DOI link.
 */
const EVERY_ELEMENT = [
  "Every element: $\\frac{a}{b} + \\sqrt{x^2}$ and https://doi.org/10.1000/182",
  "",
  "- [x] done",
  "- [ ] not done",
  "",
  '<p><a href="https://example.org/" hreflang="en" title="t" lang="en">a</a> <abbr>abbr</abbr> ' +
    '<acronym>acr</acronym> <b>b</b> <bdi>bdi</bdi> <bdo dir="rtl">bdo</bdo> <cite>cite</cite> ' +
    '<code>code</code> <data>data</data> <del cite="https://example.org/" datetime="2026-11-25">del</del> ' +
    '<dfn>dfn</dfn> <em>em</em> <i>i</i> <ins>ins</ins> <kbd>kbd</kbd> <mark>mark</mark> <q cite="x">q</q> ' +
    '<s>s</s> <samp>samp</samp> <small>small</small> <span class="c" aria-hidden="true">span</span> ' +
    '<strike>strike</strike> <strong>strong</strong> <sub>sub</sub> <sup>sup</sup> <time datetime="2026-11-25">time</time> ' +
    "<tt>tt</tt> <u>u</u> <var>var</var> a<wbr>b<br></p>",
  '<blockquote cite="https://example.org/"><p>quote</p></blockquote>',
  "<details><summary>summary</summary><p>details</p></details>",
  "<figure><figcaption>caption</figcaption></figure>",
  "<dl><dt>dt</dt><dd>dd</dd></dl>",
  '<ol start="3"><li>li</li></ol>',
  "<ruby>漢<rp>(</rp><rt>kan</rt><rp>)</rp></ruby>",
  '<hr align="left" size="2" width="50%">',
  '<table summary="s" align="left"><caption>c</caption><colgroup span="1"><col span="1"></colgroup>' +
    '<thead><tr><th scope="col" colspan="1">h</th></tr></thead>' +
    '<tbody><tr><td rowspan="1" headers="h">d</td></tr></tbody></table>',
  "<article><header>header</header><aside>aside</aside><nav>nav</nav><footer>footer</footer></article>",
  "<hgroup><h3>h3</h3><h4>h4</h4></hgroup><h5>h5</h5><h6>h6</h6><center>center</center>",
  '<pre>pre</pre><div class="d">div</div>',
  '<img src="/favicon.ico" alt="icon" width="16" height="16">',
].join("\n");

test.describe("honest answers", () => {
  test("lose nothing to the allowlist", async ({ context, page, request }, testInfo) => {
    await authenticateBrowser(context, await requireSession(request, testInfo.workerIndex));
    const seen = await watch(page);

    // Members' content, through the editor's preview: the same render and
    // ammonia profile as a published post, the same allowlist as the feed,
    // and nothing published for other tests' pages to show.
    await page.goto("/compose");
    await page.locator('form[action$="/outbox"] textarea').first().fill(EVERY_ELEMENT);
    const preview = page.locator(".noombat-editor__preview");
    await expect(preview.locator("math")).toHaveCount(1);
    await expect(preview.locator('input[type="checkbox"]')).toHaveCount(2);
    await expect(preview.locator("a.doi-link[data-doi]")).toHaveCount(1);
    await expect(preview.locator("table td")).toHaveCount(1);

    // The pages whose parts htmx loads.
    await page.goto("/");
    await page.waitForFunction(() => ((window as { __settled?: number }).__settled ?? 0) >= 1);
    await page.goto("/settings/privacy");
    await expect(page.locator("#privacy-preview > *").first()).toBeVisible();

    // An item added and removed on each settings list: the answers carry
    // the ids, targets and delete paths the allowlist pins.
    const stamp = `${testInfo.workerIndex}-${Date.now()}`;
    for (const [path, field, value, list] of [
      ["/settings/skills", "name", `Fragment ${stamp}`, "#skills-list > span"],
      ["/settings/links", "url", `https://example.org/${stamp}`, "#links-list > li"],
    ] as const) {
      await page.goto(path);
      const form = page.locator("form[hx-post]");
      await form.locator(`input[name="${field}"]`).fill(value);
      await form.locator('button[type="submit"]').click();
      const item = page.locator(list).filter({ hasText: value });
      await expect(item).toHaveCount(1);
      await item.locator("button[hx-delete]").click();
      await expect(item).toHaveCount(0);
    }

    expect(seen.removed, "an honest answer lost something to the allowlist").toEqual([]);
    expect(seen.violations).toEqual([]);
  });
});
