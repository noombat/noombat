// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The one way server HTML becomes nodes in a page: parsed by `DOMParser`,
 * which runs nothing and attaches no declarative shadow root, then walked
 * in place against `fragment-allowlist.ts`, and never serialised again,
 * so what was checked is exactly what gets inserted.
 *
 * Everything outside the allowlist goes, with its content: scripts in any
 * form, frames, templates, styles and stylesheets, meta and base elements,
 * titles, forms, SVG, unknown elements, and every attribute and value an
 * honest answer does not use. What was removed is reported on the console,
 * since an honest server sends nothing that is.
 */

import { GLOBAL, HTML, MATHML, MATHML_GLOBAL } from "./fragment-allowlist";

const HTML_NS = "http://www.w3.org/1999/xhtml";
const MATHML_NS = "http://www.w3.org/1998/Math/MathML";

/** `DOMParser`'s own parse, kept before `htmx.ts` replaces it. */
const parseFromString = DOMParser.prototype.parseFromString;

/** Turns the string handed to the parse into what the page's policy admits. */
let admit: (html: string) => string = (html) => html;

/** Hand the parse its input through `convert`: Trusted Types' policy, where it is in force. */
export function admitWith(convert: (html: string) => string): void {
  admit = convert;
}

/** `table[key]` if the table itself has it, never a property every object inherits. */
function own<T>(table: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

function attributeAllowed(element: Element, name: string, value: string): boolean {
  const mathml = element.namespaceURI === MATHML_NS;
  const rules = own(mathml ? MATHML : HTML, element.localName);
  const rule = (rules && own(rules, name)) ?? own(mathml ? MATHML_GLOBAL : GLOBAL, name);
  return rule?.(value, element) ?? false;
}

function elementAllowed(node: Element): boolean {
  if (node.namespaceURI === HTML_NS) return Object.hasOwn(HTML, node.localName);
  if (node.namespaceURI === MATHML_NS) return Object.hasOwn(MATHML, node.localName);
  return false;
}

/** Remove from `root`'s descendants, in place, everything the allowlist does not name. */
export function clean(root: ParentNode, removed: string[] = []): string[] {
  for (const node of Array.from(root.childNodes)) {
    if (node.nodeType === Node.TEXT_NODE || node.nodeType === Node.COMMENT_NODE) continue;
    if (!(node instanceof Element) || !elementAllowed(node)) {
      removed.push(node instanceof Element ? `<${node.localName}>` : node.nodeName);
      node.remove();
      continue;
    }
    for (const attribute of Array.from(node.attributes)) {
      if (!attributeAllowed(node, attribute.name, attribute.value)) {
        removed.push(`${node.localName}[${attribute.name}]`);
        node.removeAttributeNode(attribute);
      }
    }
    clean(node, removed);
  }
  return removed;
}

function report(removed: string[]): void {
  if (removed.length > 0) console.warn("noombat: removed from a server answer:", removed.join(" "));
}

/**
 * A document's own head and body, read through getters that an element in
 * it named "head" or "body" cannot shadow, as it shadows `doc.body`.
 */
function getter(name: "head" | "body"): (this: Document) => HTMLElement {
  const get = Object.getOwnPropertyDescriptor(Document.prototype, name)?.get;
  if (get === undefined) throw new Error(`Document.prototype.${name} has no getter`);
  return get as (this: Document) => HTMLElement;
}
const headOf = getter("head");
const bodyOf = getter("body");
const querySelector = Document.prototype.querySelector;

/** How htmx hands over a partial answer; it takes this template's content. */
const WRAPPER = '<body><template class="internal-htmx-wrapper">';

function removeAll(nodes: ChildNode[], removed: string[]): void {
  for (const node of nodes) {
    removed.push(node instanceof Element ? `<${node.localName}>` : node.nodeName);
    node.remove();
  }
}

/**
 * Parse a server answer and clean it. htmx hands over a partial answer
 * wrapped as `<body><template class="internal-htmx-wrapper">…</template></body>`
 * and takes that template's content, so in an answer that starts so, that
 * template alone is kept, its content cleaned and the rest of the body
 * removed; one whose parsed shape is not that is refused whole. Anything
 * else is a whole document, whose body is cleaned.
 */
export function parseAnswer(html: string): Document {
  const parse = (text: string) => parseFromString.call(new DOMParser(), admit(text), "text/html");
  const doc = parse(html);
  const removed: string[] = [];
  const body = bodyOf.call(doc);
  removeAll(Array.from(headOf.call(doc).childNodes), removed);
  if (!html.startsWith(WRAPPER)) {
    clean(body, removed);
  } else {
    const wrapper = body.firstChild;
    if (
      wrapper instanceof HTMLTemplateElement &&
      wrapper.attributes.length === 1 &&
      wrapper.getAttribute("class") === "internal-htmx-wrapper"
    ) {
      removeAll(
        Array.from(body.childNodes).filter((node) => node !== wrapper),
        removed,
      );
      clean(wrapper.content, removed);
    }
    if (body.childNodes.length !== 1 || querySelector.call(doc, "template") !== wrapper) {
      report(["the whole answer"]);
      return parse(`${WRAPPER}</template></body>`);
    }
  }
  report(removed.filter((item) => item !== "#text" && item !== "#comment"));
  return doc;
}

/** A server answer as nodes ready to insert, cleaned: the editor's preview. */
export function answerNodes(html: string): Node[] {
  return Array.from(bodyOf.call(parseAnswer(html)).childNodes);
}
