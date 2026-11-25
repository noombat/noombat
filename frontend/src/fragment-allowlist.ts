// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * What a server answer may put into a page: the elements, attributes and
 * attribute values the honest answers use, and nothing else. `fragment.ts`
 * removes everything outside it from every answer htmx swaps in and from
 * the editor's preview.
 *
 * Two sources make the honest answers, and the list covers both. The
 * templates and handlers that answer htmx requests (the feed page, the
 * skill, link, alias, domain and announcement items, the privacy preview,
 * the TOTP and report notices, the status region); and members' own
 * content, which noombat-markup's ammonia profile has already cleaned:
 * its tags, MathML for formulas and checkboxes for task lists.
 *
 * Changed and reviewed like code. A template that starts to send another
 * element, attribute or `hx-target` adds it here in the same commit, or
 * the page loses it. `fragment.ts` reports on the console anything it
 * removes, and `tests/e2e/htmx-fragments.spec.ts` checks that the main
 * honest answers lose nothing.
 */

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

/** The item `id`s an answer may give an element, and so the only ones it can reach. */
const ID = new RegExp(`^(?:skill|link|alias)-${UUID}$`);

/** The items an answer's `hx-target` may name. */
const HX_TARGET_ID = new RegExp(`^#(?:skill|link|alias)-${UUID}$`);

/** URL schemes ammonia lets members link to; anything else is dropped. */
const LINK_SCHEMES = new Set(
  (
    "bitcoin ftp ftps geo http https im irc ircs magnet mailto mms mx news nntp " +
    "openpgp4fpr sip sms smsto ssh tel url webcal wtai xmpp"
  ).split(" "),
);

type Rule = (value: string, element: Element) => boolean;

const any: Rule = () => true;
const oneOf =
  (...values: string[]): Rule =>
  (value) =>
    values.includes(value);

/** A path on this origin, as `hx-get` and `hx-delete` name them. */
const samePath: Rule = (value) => {
  if (!/^\/(?![/\\])/.test(value)) return false;
  try {
    return new URL(value, location.href).origin === location.origin;
  } catch {
    return false;
  }
};

/** The scheme a URL has once the browser has read it as it will, or none. */
function schemeOf(value: string): string | null {
  try {
    return new URL(value, location.href).protocol.slice(0, -1);
  } catch {
    return null;
  }
}

/** A link: relative, or to one of the schemes members may use. */
const link: Rule = (value) => LINK_SCHEMES.has(schemeOf(value) ?? "");

/** An image: over HTTP, or an inline raster image. */
const image: Rule = (value) =>
  ["http", "https"].includes(schemeOf(value) ?? "") ||
  (schemeOf(value) === "data" && /^\s*data:image\/(?:png|jpeg|gif|webp|avif);/i.test(value));

/**
 * An `hx-target`: an item the answer carries, or the row or box the element
 * sits in within the answer itself, never one around it in the page.
 */
const hxTarget: Rule = (value, element) => {
  const closest = /^closest (div|tr)$/.exec(value)?.[1];
  if (closest === undefined) return HX_TARGET_ID.test(value);
  return (element.parentElement?.closest(closest) ?? null) !== null;
};

/** Attributes any HTML element may carry. */
export const GLOBAL: Record<string, Rule> = {
  "aria-label": any,
  class: any,
  // The status region only as the out-of-band update the feed sends.
  id: (value, element) =>
    value === "a11y-status"
      ? element.localName === "span" && element.getAttribute("hx-swap-oob") === "innerHTML"
      : ID.test(value),
  lang: any,
  title: any,
};

/** HTML elements, each with the attributes of its own it may carry. */
export const HTML: Record<string, Record<string, Rule>> = {
  a: {
    href: link,
    hreflang: any,
    "data-doi": any,
    rel: oneOf("noopener noreferrer"),
    target: oneOf("_blank"),
  },
  abbr: {},
  acronym: {},
  area: { href: link, alt: any, coords: any, shape: any },
  article: {},
  aside: {},
  b: {},
  bdi: {},
  bdo: { dir: oneOf("ltr", "rtl") },
  blockquote: { cite: any },
  br: {},
  button: {
    type: oneOf("button"),
    "hx-delete": samePath,
    "hx-target": hxTarget,
    "hx-swap": oneOf("outerHTML"),
    "hx-confirm": any,
  },
  caption: {},
  center: {},
  cite: {},
  code: {},
  col: { align: any, char: any, charoff: any, span: any },
  colgroup: { align: any, char: any, charoff: any, span: any },
  data: {},
  dd: {},
  del: { cite: any, datetime: any },
  details: {},
  dfn: {},
  div: {
    role: oneOf("status"),
    "hx-get": samePath,
    "hx-trigger": oneOf("revealed"),
    "hx-swap": oneOf("outerHTML"),
  },
  dl: {},
  dt: {},
  em: {},
  figcaption: {},
  figure: {},
  footer: {},
  h1: {},
  h2: {},
  h3: {},
  h4: {},
  h5: {},
  h6: {},
  header: {},
  hgroup: {},
  hr: { align: any, size: any, width: any },
  i: {},
  img: { src: image, alt: any, width: any, height: any, align: any, loading: oneOf("lazy") },
  input: { type: (value) => /^checkbox$/i.test(value), disabled: any, checked: any },
  ins: { cite: any, datetime: any },
  kbd: {},
  li: {},
  map: {},
  mark: {},
  nav: {},
  ol: { start: any },
  p: {},
  pre: {},
  q: { cite: any },
  rp: {},
  rt: {},
  rtc: {},
  ruby: {},
  s: {},
  samp: {},
  small: {},
  span: {
    "aria-hidden": any,
    "hx-swap-oob": (value, element) =>
      value === "innerHTML" && element.getAttribute("id") === "a11y-status",
  },
  strike: {},
  strong: {},
  sub: {},
  summary: {},
  sup: {},
  table: { align: any, char: any, charoff: any, summary: any },
  tbody: { align: any, char: any, charoff: any },
  td: { align: any, char: any, charoff: any, colspan: any, headers: any, rowspan: any },
  th: { align: any, char: any, charoff: any, colspan: any, headers: any, rowspan: any, scope: any },
  thead: { align: any, char: any, charoff: any },
  time: { datetime: any },
  tr: { align: any, char: any, charoff: any },
  tt: {},
  u: {},
  ul: {},
  var: {},
  wbr: {},
};

const mathVariant = { mathvariant: any };
const accent = { accent: any, accentunder: any };

/** MathML elements, each with its attributes, as formulas render. */
export const MATHML: Record<string, Record<string, Rule>> = {
  math: { xmlns: oneOf("http://www.w3.org/1998/Math/MathML"), display: any },
  semantics: {},
  annotation: { encoding: any },
  "annotation-xml": { encoding: any },
  mrow: {},
  mi: mathVariant,
  mn: mathVariant,
  ms: mathVariant,
  mtext: mathVariant,
  msqrt: mathVariant,
  mroot: mathVariant,
  mo: {
    fence: any,
    stretchy: any,
    separator: any,
    form: any,
    largeop: any,
    movablelimits: any,
    symmetric: any,
    lspace: any,
    rspace: any,
    minsize: any,
    maxsize: any,
  },
  mspace: { width: any, height: any, depth: any },
  mpadded: { width: any, height: any, depth: any, lspace: any, voffset: any },
  mfrac: { linethickness: any },
  msub: {},
  msup: {},
  msubsup: {},
  mover: accent,
  munder: accent,
  munderover: accent,
  menclose: { notation: any },
  mphantom: {},
  mtable: {
    columnalign: any,
    rowspacing: any,
    columnspacing: any,
    displaystyle: any,
    scriptlevel: any,
  },
  mtr: { columnalign: any, rowalign: any },
  mtd: { columnalign: any, rowalign: any, columnspan: any, rowspan: any },
};

/** The attributes MathML elements share with HTML ones. */
export const MATHML_GLOBAL: Record<string, Rule> = { lang: any, title: any };
