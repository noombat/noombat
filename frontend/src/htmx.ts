// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Bundled htmx entry point.
// Importing htmx starts it: it processes the page once the document is ready.
//
// Everything the server sends htmx passes through here first, so that an
// answer can change no more than the part of the page that asked for it.
// The modules below are the release's, attested by its manifest; nothing
// the server sends can switch any of it off.
//
// `htmx.spec.ts` checks that the installed bundle still works the way
// this relies on: one parse function, configuration read through the
// exported object and replaced only by assignment, response headers read
// through `getResponseHeader`, and page moves through `htmx.location`.
//
// The indicator rules in main.css are the project's own and use
// `display` rather than htmx's `opacity`/`visibility`, so they are not a
// copy of upstream and need no synchronisation with it.
import htmx from "htmx.org";
import "./trusted-types";
import { addCsrfHeader, showRefusal, type HtmxRequestDetail } from "./csrf";
import { parseAnswer } from "./fragment";
import { RELEASE_CONFIG } from "./htmx-config";

/*
 * The configuration is the release's alone. htmx replaces it, once the
 * document is ready, with a copy merged with any htmx-config meta element
 * the page carries, which the server writes; that assignment is ignored.
 */
const config = Object.freeze({ ...htmx.config, ...RELEASE_CONFIG });
Object.defineProperty(htmx, "config", {
  get: () => config,
  set: () => undefined,
  configurable: false,
});

/*
 * No HX-* response header reaches htmx: they move the page (HX-Redirect,
 * HX-Location, HX-Refresh, HX-Push-Url), retarget a swap or fire events,
 * and the honest server sends none. htmx reads them only through these
 * two methods. And htmx moves the page only through `htmx.location`,
 * which goes nowhere.
 */
const getResponseHeader = XMLHttpRequest.prototype.getResponseHeader;
XMLHttpRequest.prototype.getResponseHeader = function (this: XMLHttpRequest, name: string) {
  return /^hx-/i.test(name) ? null : getResponseHeader.call(this, name);
};
const getAllResponseHeaders = XMLHttpRequest.prototype.getAllResponseHeaders;
XMLHttpRequest.prototype.getAllResponseHeaders = function (this: XMLHttpRequest) {
  return getAllResponseHeaders
    .call(this)
    .split("\r\n")
    .filter((line) => !/^hx-/i.test(line))
    .join("\r\n");
};
Object.defineProperty(htmx, "location", {
  value: Object.freeze({
    get href() {
      return location.href;
    },
    set href(_: string) {},
    reload() {},
  }),
  writable: false,
  configurable: false,
});

/*
 * htmx turns every answer into nodes through `Document.parseHTMLUnsafe`
 * where the browser has it and `DOMParser` otherwise. Both parse without
 * declarative shadow roots and keep only what `fragment-allowlist.ts`
 * names; other documents parse as `DOMParser` does.
 */
Object.defineProperty(Document, "parseHTMLUnsafe", {
  value: parseAnswer,
  writable: false,
  configurable: false,
});
const parseFromString = DOMParser.prototype.parseFromString;
Object.defineProperty(DOMParser.prototype, "parseFromString", {
  value: function (this: DOMParser, text: string, type: DOMParserSupportedType) {
    return type === "text/html" ? parseAnswer(text) : parseFromString.call(this, text, type);
  },
  writable: false,
  configurable: false,
});

// Every htmx write carries the session's CSRF token as a header.
document.addEventListener("htmx:configRequest", (event) => {
  addCsrfHeader((event as CustomEvent<HtmxRequestDetail>).detail);
});

// A refused write says so on the page.
document.addEventListener("htmx:responseError", (event) => {
  showRefusal((event as CustomEvent<{ xhr: XMLHttpRequest }>).detail.xhr);
});

/*
 * Delegated disclosure toggles.
 *
 * `base.html` loads this module on every page, so a single
 * document-level listener serves all templates. Delegation also
 * covers markup inserted later by HTMX swaps, which a listener bound
 * at load time would miss.
 *
 * Inline event handlers are inline script, which a `script-src 'self'`
 * policy without `'unsafe-inline'` blocks, so the toggles use this
 * listener instead.
 */
document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) return;

  const trigger = target.closest("[data-toggle-target]");
  if (!(trigger instanceof HTMLElement)) return;

  const id = trigger.dataset.toggleTarget;
  if (!id) return;

  const panel = document.getElementById(id);
  if (!panel) return;

  const nowHidden = !panel.hasAttribute("hidden");
  panel.toggleAttribute("hidden", nowHidden);
  trigger.setAttribute("aria-expanded", String(!nowHidden));
});
