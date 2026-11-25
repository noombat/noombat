// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Guards the htmx behaviours `htmx.ts` relies on to keep an answer to the
 * part of the page that asked for it, and the release's htmx
 * configuration in `htmx-config.ts`.
 *
 * `htmx.ts` freezes the configuration, hides HX-* response headers,
 * makes `htmx.location` go nowhere, and replaces the two parse functions
 * htmx uses. Each holds only while htmx works the way these tests pin:
 * an upgrade that parsed answers some other way, read headers some other
 * way, or wrote to its configuration, would slip past it unnoticed.
 *
 * There is nowhere useful to put a comment warning about it:
 * `package.json` cannot carry comments, and the dependency is declared
 * as a range rather than a version, so there is no version string to
 * annotate. This test is the reminder instead, and it fails at the point
 * an upgrade lands rather than in review.
 *
 * The end-to-end suite checks the same from the other direction, in the
 * browsers: `htmx-fragments.spec.ts` answers htmx with what a modified
 * server could send.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { RELEASE_CONFIG } from "./htmx-config";

// The module Vite bundles: the package's `main`.
const BUNDLE = readFileSync(new URL("../node_modules/htmx.org/dist/htmx.esm.js", import.meta.url), {
  encoding: "utf8",
});

interface Rule {
  code: string;
  swap: boolean;
  error?: boolean;
}

/** htmx's own default `responseHandling`, as the bundle declares it. */
function defaultResponseHandling(): Rule[] {
  const literal = /responseHandling:\s*(\[[\s\S]*?\])\s*,/.exec(BUNDLE)?.[1];
  expect(literal, "the bundle no longer declares a default responseHandling").toBeDefined();
  return JSON.parse((literal ?? "[]").replace(/'/g, '"').replace(/(\w+):/g, '"$1":')) as Rule[];
}

/** The first rule htmx would apply to a status, as htmx itself picks one. */
function ruleFor(status: number): Rule | undefined {
  return RELEASE_CONFIG.responseHandling.find((rule) => new RegExp(rule.code).test(String(status)));
}

/** How many times `pattern` occurs in the bundle. */
function count(pattern: RegExp): number {
  return BUNDLE.match(new RegExp(pattern.source, "g"))?.length ?? 0;
}

describe("htmx configuration surface", () => {
  it("still reads every setting the release gives it from its configuration", () => {
    for (const key of Object.keys(RELEASE_CONFIG)) {
      expect(
        new RegExp(`htmx\\.config\\.${key}\\b`).test(BUNDLE),
        `htmx no longer reads htmx.config.${key}; htmx-config.ts sets a setting it ignores`,
      ).toBe(true);
    }
  });

  it("removes a swapped fragment's scripts when allowScriptTags is off", () => {
    // htmx.ts holds the option off, which stops nothing unless htmx still
    // removes the scripts of a fragment it parses while the option is off.
    expect(
      /if \(!htmx\.config\.allowScriptTags\) \{[^}]*script\.remove\(\)/.test(BUNDLE),
      "htmx keeps a fragment's scripts with allowScriptTags off; htmx.ts stops nothing",
    ).toBe(true);
  });

  it("replaces its configuration only by assigning htmx.config, once, and writes no setting", () => {
    // htmx.ts ignores that assignment and freezes the object: a setting
    // written in place would throw, and a configuration replaced some
    // other way would bypass the freeze.
    expect(
      count(/htmx\.config = /),
      "htmx replaces its configuration elsewhere too, or nowhere; re-check htmx.ts",
    ).toBe(1);
    expect(
      count(/htmx\.config\.\w+(\.\w+)* = /),
      "htmx now writes a setting in place, which the frozen configuration refuses",
    ).toBe(0);
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

describe("how htmx turns answers into nodes", () => {
  it("parses every answer in one function, with parseHTMLUnsafe or DOMParser", () => {
    // htmx.ts replaces both; a third way to parse would bypass the allowlist.
    expect(count(/Document\.parseHTMLUnsafe\(/), "htmx calls parseHTMLUnsafe elsewhere").toBe(1);
    expect(count(/\.parseFromString\(/), "htmx calls parseFromString elsewhere").toBe(1);
    expect(count(/function parseHTML\(/)).toBe(1);
    expect(count(/createContextualFragment|setHTMLUnsafe|\.innerHTML = |\.outerHTML = /)).toBe(0);
  });

  it("inserts no other HTML of its own but two fixed strings", () => {
    expect(count(/insertAdjacentHTML\(/)).toBe(2);
    expect(
      count(/insertAdjacentHTML\('afterend', "<div id='--htmx-preserve-pantry--'><\/div>"\)/),
    ).toBe(1);
    expect(count(/head\.insertAdjacentHTML\('beforeend',\s*`<style/)).toBe(1);
  });
});

describe("how htmx follows the server", () => {
  it("reads response headers only through getResponseHeader", () => {
    // htmx.ts hides HX-* headers there.
    expect(count(/getAllResponseHeaders/), "htmx reads all headers some other way").toBe(0);
    expect(count(/getResponseHeader\(/)).toBeGreaterThan(5);
  });

  it("moves the page only through htmx.location", () => {
    // htmx.ts makes htmx.location go nowhere.
    expect(
      count(/(?<!htmx\.)location\.(?:assign|replace|reload)\(|(?<!htmx\.)location\.href = /),
    ).toBe(0);
    expect(count(/htmx\.location\.(?:href = |reload\()/)).toBe(4);
  });
});

describe("the release's htmx configuration", () => {
  it("is htmx's own default responseHandling without its rule for 204", () => {
    expect(
      RELEASE_CONFIG.responseHandling,
      "htmx-config.ts's responseHandling has drifted from htmx's default; an upgrade may have changed it",
    ).toEqual(defaultResponseHandling().filter((rule) => rule.code !== "204"));
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
