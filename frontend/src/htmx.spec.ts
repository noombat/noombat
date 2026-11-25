// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Guards the htmx behaviours the configuration in base.html depends on,
 * and those the `allowScriptTags` setting in htmx.ts depends on.
 *
 * The `responseHandling` setting there makes htmx swap a 204, so that a
 * removed row leaves its page; it has to stay htmx's own default but for
 * that one rule, and htmx has to keep replacing its list with it. The
 * rest of this comment is about the other setting.
 *
 * htmx appends a `<style>` element during initialisation, which
 * `style-src 'self'` without `'unsafe-inline'` blocks. The injection is
 * disabled by an `htmx-config` meta element in
 * `crates/noombat-api/templates/base.html`, which relies on htmx both
 * reading that element and honouring `includeIndicatorStyles`.
 *
 * An upgrade that dropped either would silently reintroduce a policy
 * violation on every page. There is nowhere useful to put a comment
 * warning about it: `package.json` cannot carry comments, and the
 * dependency is declared as a range rather than a version, so there is
 * no version string to annotate. This test is the reminder instead, and
 * it fails at the point an upgrade lands rather than in review.
 *
 * The end-to-end suite catches the same regression from the other
 * direction, by failing on any `securitypolicyviolation` event, but only
 * where a live instance is available.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// The module Vite bundles: the package's `main`.
const BUNDLE = readFileSync(new URL("../node_modules/htmx.org/dist/htmx.esm.js", import.meta.url), {
  encoding: "utf8",
});

const BASE_HTML = readFileSync(
  new URL("../../crates/noombat-api/templates/base.html", import.meta.url),
  { encoding: "utf8" },
);

interface Rule {
  code: string;
  swap: boolean;
  error?: boolean;
}

/** The configuration `base.html` gives htmx in its meta element. */
function metaConfig(): { responseHandling?: Rule[] } {
  const content = /<meta name="htmx-config" content='([^']*)'>/.exec(BASE_HTML)?.[1];
  expect(content, "base.html no longer carries the htmx-config meta element").toBeDefined();
  return JSON.parse(content ?? "{}") as ReturnType<typeof metaConfig>;
}

/** htmx's own default `responseHandling`, as the bundle declares it. */
function defaultResponseHandling(): Rule[] {
  const literal = /responseHandling:\s*(\[[\s\S]*?\])\s*,/.exec(BUNDLE)?.[1];
  expect(literal, "the bundle no longer declares a default responseHandling").toBeDefined();
  return JSON.parse((literal ?? "[]").replace(/'/g, '"').replace(/(\w+):/g, '"$1":')) as Rule[];
}

/** The first rule htmx would apply to a status, as htmx itself picks one. */
function ruleFor(status: number) {
  return metaConfig().responseHandling?.find((rule) => new RegExp(rule.code).test(String(status)));
}

describe("htmx configuration surface", () => {
  it("still reads responseHandling from its configuration", () => {
    expect(
      BUNDLE.includes("htmx.config.responseHandling"),
      "htmx no longer reads htmx.config.responseHandling; the rule in base.html that swaps a 204 is being ignored",
    ).toBe(true);
  });

  it("still honours includeIndicatorStyles", () => {
    expect(
      BUNDLE.includes("includeIndicatorStyles"),
      "htmx no longer references includeIndicatorStyles; the htmx-config meta element in base.html may no longer suppress the injected <style> element",
    ).toBe(true);
  });

  it("still reads configuration from the htmx-config meta element", () => {
    expect(
      BUNDLE.includes('meta[name="htmx-config"]'),
      "htmx no longer reads meta[name=htmx-config]; the option set in base.html is being ignored",
    ).toBe(true);
  });

  it("removes a swapped fragment's scripts when allowScriptTags is off", () => {
    // htmx.ts holds the option off, which stops nothing unless htmx still
    // removes the scripts of a fragment it parses while the option is off.
    expect(
      /if \(!htmx\.config\.allowScriptTags\) \{[^}]*script\.remove\(\)/.test(BUNDLE),
      "htmx keeps a fragment's scripts with allowScriptTags off; htmx.ts stops nothing",
    ).toBe(true);
  });

  it("replaces its configuration only by assigning htmx.config, once", () => {
    // The property htmx.ts defines catches that assignment; a configuration
    // replaced some other way would carry the option past it.
    expect(
      BUNDLE.match(/htmx\.config = /g)?.length,
      "htmx replaces its configuration elsewhere too, or nowhere; re-check htmx.ts",
    ).toBe(1);
  });

  it("reads its configuration through the object it exports", () => {
    const shape = /const htmx = \{[\s\S]*return htmx\s*\}\)\(\)[\s\S]*export default htmx/;
    expect(
      shape.test(BUNDLE),
      "htmx no longer exports the object it reads its configuration from; re-check htmx.ts",
    ).toBe(true);
  });

  it("gates the style injection on the option rather than always injecting", () => {
    // Pins the shape the suppression relies on: the injection must be
    // conditional. A change to an unconditional append would leave both
    // assertions above passing while the violation returned.
    expect(
      /includeIndicatorStyles\s*!==\s*false/.test(BUNDLE),
      "htmx no longer guards style injection on includeIndicatorStyles !== false; re-check how injection is suppressed",
    ).toBe(true);
  });
});

describe("the htmx configuration in base.html", () => {
  it("is htmx's own default without its rule for 204", () => {
    expect(
      metaConfig().responseHandling,
      "base.html's responseHandling has drifted from htmx's default; an upgrade may have changed it",
    ).toEqual(defaultResponseHandling().filter((rule) => rule.code !== "204"));
  });

  it("replaces htmx's default list rather than merging into it", () => {
    expect(/htmx\.config = mergeObjects\(htmx\.config, metaConfig\)/.test(BUNDLE)).toBe(true);
    expect(
      /function mergeObjects\(obj1, obj2\) \{\s*return Object\.assign\(\{\}, obj1, obj2\)/.test(
        BUNDLE,
      ),
      "htmx no longer merges its configuration shallowly; the default rule for 204 may now come first",
    ).toBe(true);
  });

  it("swaps a 204, so a removed row leaves the page", () => {
    expect(
      ruleFor(204)?.swap,
      "a 204 is not swapped: the remove buttons' rows stay on the page until it is reloaded",
    ).toBe(true);
  });

  it("still swaps a 200 and treats a 4xx or 5xx as an error, as htmx's default does", () => {
    expect(ruleFor(200)?.swap).toBe(true);
    expect(ruleFor(404)).toMatchObject({ swap: false, error: true });
    expect(ruleFor(500)).toMatchObject({ swap: false, error: true });
  });
});
