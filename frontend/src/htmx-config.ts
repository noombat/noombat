// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The settings htmx runs with, laid over its defaults and frozen by
 * `htmx.ts`, so that nothing the server sends can change one.
 *
 * Each closes a way an answer could reach past the swap it was asked for:
 * scripts, evaluated attributes, out-of-band swaps nested in an answer,
 * history and its cache, the page title, cross-origin requests. The
 * indicator styles stay out because the `<style>` htmx would inject
 * breaks `style-src 'self'`; the indicator rules are main.css's own.
 *
 * `responseHandling` is htmx's default without its rule for 204, so a
 * 204 is swapped and a removed row leaves its page. `htmx.spec.ts` holds
 * it to the installed bundle's default.
 */
export const RELEASE_CONFIG = {
  allowEval: false,
  allowScriptTags: false,
  allowNestedOobSwaps: false,
  historyEnabled: false,
  historyCacheSize: 0,
  refreshOnHistoryMiss: false,
  selfRequestsOnly: true,
  ignoreTitle: true,
  includeIndicatorStyles: false,
  inlineScriptNonce: "",
  inlineStyleNonce: "",
  withCredentials: false,
  getCacheBusterParam: false,
  globalViewTransitions: false,
  scrollIntoViewOnBoost: false,
  responseHandling: [
    { code: "[23]..", swap: true },
    { code: "[45]..", swap: false, error: true },
  ],
} as const;
