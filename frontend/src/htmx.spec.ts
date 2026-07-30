// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Guards the two htmx behaviours the Content-Security-Policy depends on.
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

const BUNDLE = readFileSync(new URL("../node_modules/htmx.org/dist/htmx.js", import.meta.url), {
  encoding: "utf8",
});

describe("htmx configuration surface", () => {
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
