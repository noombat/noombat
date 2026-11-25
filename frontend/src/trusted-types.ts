// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The page's Trusted Types policies, which the server's policy requires
 * (`require-trusted-types-for 'script'`) and names (`trusted-types`).
 * With them in force the browser itself refuses a plain string at every
 * place that turns one into nodes or code: this module's, htmx's, Solid's,
 * a dependency's, and any added later.
 *
 * - `noombat-parse` turns a server answer into input for the one parse
 *   `fragment.ts` does, whose result is cleaned before it is used.
 * - `noombat-solid` passes Solid's templates, and only them: the exact
 *   strings the build found in the islands' compiled code.
 * - `default` passes only text that cannot form markup, a string with no
 *   `<` in it, which can become a text node and nothing else (style rules
 *   a library writes into a style element, say), and refuses everything else. Passing the empty
 *   string also lets this module tell, without a violation, whether the
 *   browser routes plain strings through it, which it does only while the
 *   policy is in force.
 *
 * If the browser has Trusted Types and the page arrived without the
 * directive, the server dropped it, and the page says so.
 */

import { admitWith } from "./fragment";

/** The part of the Trusted Types API used here, which TypeScript's DOM library lacks. */
interface Policy {
  createHTML(html: string): unknown;
}
declare global {
  var trustedTypes:
    | {
        createPolicy(name: string, rules: { createHTML(html: string): string | null }): Policy;
      }
    | undefined;
}

/** The template strings in the islands, filled in by the build. */
declare const __NOOMBAT_SOLID_TEMPLATES__: readonly string[];
const TEMPLATES = new Set(
  typeof __NOOMBAT_SOLID_TEMPLATES__ === "undefined" ? [] : __NOOMBAT_SOLID_TEMPLATES__,
);

/** What Solid's templates are handed through; `null` where the browser has no Trusted Types. */
export let solidPolicy: Policy | null = null;

const NOTICE: Record<string, string> = {
  "en-US":
    "This page arrived without the security policy this release sends, which stops scripts from being added to it. Its server may have been modified: be careful what you enter here.",
  "en-AU":
    "This page arrived without the security policy this release sends, which stops scripts from being added to it. Its server may have been modified: be careful what you enter here.",
  "pt-BR":
    "Esta página chegou sem a política de segurança que esta versão envia, que impede que scripts sejam adicionados a ela. O servidor pode ter sido modificado: cuidado com o que você digita aqui.",
};

function showNotice(): void {
  const notice = document.createElement("p");
  notice.id = "policy-missing";
  notice.setAttribute("role", "alert");
  notice.className = "mb-4 border border-border-default rounded px-3 py-2 text-sm text-text-danger";
  notice.textContent = NOTICE[document.documentElement.lang] ?? NOTICE["en-US"];
  const place = () => document.querySelector("main")?.prepend(notice);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", place);
  else place();
}

if (globalThis.trustedTypes !== undefined) {
  const parse = globalThis.trustedTypes.createPolicy("noombat-parse", {
    createHTML: (html) => html,
  });
  admitWith((html) => parse.createHTML(html) as unknown as string);
  solidPolicy = globalThis.trustedTypes.createPolicy("noombat-solid", {
    createHTML: (html) => {
      if (TEMPLATES.has(html)) return html;
      throw new TypeError("not one of the islands' templates");
    },
  });
  let routed = false;
  globalThis.trustedTypes.createPolicy("default", {
    createHTML: (html) => {
      routed = true;
      return html.includes("<") ? null : html;
    },
  });
  document.createElement("template").innerHTML = "";
  if (!routed) showNotice();
}
