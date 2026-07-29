// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Bundled htmx entry point.
// Importing the module registers htmx on `window.htmx` as a side effect.
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
