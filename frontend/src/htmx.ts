// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Bundled htmx entry point.
// Importing htmx starts it: it processes the page once the document is ready.
//
// Upgrading htmx: `crates/noombat-api/templates/base.html` carries an
// htmx-config meta element with two settings. includeIndicatorStyles is
// off, because the <style> element htmx injects during initialisation
// violates `style-src 'self'`; htmx reads the element while initialising,
// so that setting cannot be made from here, and it is the only thing
// preventing the violation. responseHandling makes htmx swap a 204, so a
// removed row leaves its page. An upgrade that stopped honouring the
// element or either setting would silently undo one of them.
//
// `htmx.spec.ts` asserts the installed bundle still supports all three,
// and the end-to-end suite fails on any securitypolicyviolation and
// removes a row in a browser.
//
// The indicator rules in main.css are the project's own and use
// `display` rather than htmx's `opacity`/`visibility`, so they are not a
// copy of upstream and need no synchronisation with it.
import htmx from "htmx.org";
import { addCsrfHeader, showRefusal, type HtmxRequestDetail } from "./csrf";

/*
 * htmx drops the script elements of an answer it swaps in: every script
 * the pages need loads with its page, so a script in an answer is one no
 * release attested. It covers the answer's own script elements only; an
 * iframe's srcdoc, a declarative shadow root or a template's contents can
 * still carry one. The option has to hold through every replacement of
 * the configuration, because once the document is ready htmx replaces it
 * with a copy merged with the htmx-config meta element, which the server
 * writes, after this module has run. It relies on htmx reading its
 * configuration through the object it exports, and replacing it only by
 * assignment; `htmx.spec.ts` checks the bundle for both.
 */
let config = { ...htmx.config, allowScriptTags: false };
Object.defineProperty(htmx, "config", {
  get: () => config,
  set: (value: typeof config) => {
    config = { ...value, allowScriptTags: false };
  },
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
