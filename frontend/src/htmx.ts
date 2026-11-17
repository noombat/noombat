// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Bundled htmx entry point.
// Importing the module registers htmx on `window.htmx` as a side effect.
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
import "htmx.org";

/*
 * Delegated disclosure toggles.
 *
 * `base.html` loads this module on every page, so a single
 * document-level listener serves all templates. Delegation also
 * covers markup inserted later by HTMX swaps, which a listener bound
 * at load time would miss.
 *
 * This replaces `onclick` attributes previously used on the report
 * buttons in `profile.html` and `post.html`. Inline event handlers
 * are executed as inline script and are therefore blocked by a
 * `script-src 'self'` policy that omits `'unsafe-inline'`, which
 * left those buttons inert whenever the policy was enforced.
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
