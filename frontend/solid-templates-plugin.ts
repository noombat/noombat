// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

import type { Plugin } from "vite";

/** An ESTree node, as much of it as this plugin reads. */
interface Node {
  type: string;
  [key: string]: unknown;
}

/**
 * Collects the template strings Solid's compiler emits, `_$template(`...`)`,
 * from every module it compiles, and writes them, sorted, into
 * `trusted-types.ts` in place of `__NOOMBAT_SOLID_TEMPLATES__`. That
 * module's `noombat-solid` policy passes exactly these strings and nothing
 * else, so the islands render under Trusted Types and no other string does.
 *
 * Read from the parsed code, so the strings are what the browser will be
 * handed, escapes and all. A template that is not a plain literal fails
 * the build, since the policy could not know it in advance.
 */
export default function solidTemplates(): Plugin {
  const templates = new Set<string>();
  return {
    name: "noombat-solid-templates",
    enforce: "post",
    transform(code, id) {
      if (!code.includes("_$template(")) return null;
      const visit = (node: unknown): void => {
        if (Array.isArray(node)) {
          node.forEach(visit);
          return;
        }
        if (node === null || typeof node !== "object") return;
        const n = node as Node;
        const callee = n.callee as Node | undefined;
        if (
          n.type === "CallExpression" &&
          callee?.type === "Identifier" &&
          callee.name === "_$template"
        ) {
          const first = (n.arguments as Node[])[0];
          const quasis = first?.quasis as { value: { cooked: string } }[] | undefined;
          if (first?.type !== "TemplateLiteral" || quasis?.length !== 1) {
            this.error(`a Solid template in ${id} is not a plain string`);
          }
          templates.add(quasis[0].value.cooked);
        }
        for (const value of Object.values(n)) {
          if (value !== null && typeof value === "object") visit(value);
        }
      };
      visit(this.parse(code));
      return null;
    },
    renderChunk(code) {
      if (!code.includes("__NOOMBAT_SOLID_TEMPLATES__")) return null;
      if (templates.size === 0) this.error("no Solid template was found to allow");
      const list = JSON.stringify([...templates].sort());
      return { code: code.replaceAll("__NOOMBAT_SOLID_TEMPLATES__", list), map: null };
    },
  };
}
