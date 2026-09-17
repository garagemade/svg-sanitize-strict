/**
 * svg-sanitize-strict — DOMPurify's svg profile plus the rule it leaves out:
 * nothing in the output may make the browser fetch a resource.
 */

import type { WindowLike } from "dompurify";
import { sanitizeStyleAttr, sanitizeStyleSheet, type RefPolicy } from "./css";
import { getPurifier, withPolicy, type HookPolicy } from "./purifier";

const SVG_NS = "http://www.w3.org/2000/svg";

export interface SanitizeSvgOptions {
  /**
   * Keep `<style>` elements. Their CSS is scrubbed of `@import` and external
   * `url()` but otherwise left byte-for-byte, because Illustrator and Figma
   * exports routinely rely on `<style>.cls-1{fill:…}</style>` plus `class`.
   * `style=""` attributes are kept (and scrubbed) regardless of this flag.
   * @default true
   */
  allowStyleElement?: boolean;
  /**
   * Keep `<use>` elements. Only same-document `#fragment` references survive
   * on `<use>` either way; a `<use>` that pointed elsewhere loses its `href`.
   * @default true
   */
  allowUse?: boolean;
  /**
   * Keep `data:image/*` URLs in `<image>` and in CSS `url()`. An SVG loaded
   * through `<image>` is a non-scripted, non-fetching context, so these are
   * safe; set to `false` if you want the output to reference nothing at all.
   * @default true
   */
  allowDataImages?: boolean;
  /**
   * The window whose DOM implementation to use. Defaults to the global
   * `window`. In Node, pass a jsdom window.
   */
  window?: WindowLike;
}

export type SvgSanitizeErrorCode =
  /** No DOM available (server, worker), or DOMPurify reports the engine unsupported. */
  | "unsupported"
  /** The string is not well-formed XML (this includes empty input). */
  | "malformed"
  /** Parsed fine, but the root is not an `<svg>` in the SVG namespace. */
  | "not-svg";

export class SvgSanitizeError extends Error {
  readonly code: SvgSanitizeErrorCode;
  constructor(code: SvgSanitizeErrorCode, message: string) {
    super(message);
    this.name = "SvgSanitizeError";
    this.code = code;
  }
}

/**
 * Sanitize an SVG so that rendering it cannot run script or make a request.
 *
 * - Given a **string**, it is parsed as `image/svg+xml` into an inert document,
 *   cleaned there, and the root `<svg>` is returned. Nothing has had a chance
 *   to fetch or execute before the clean copy exists. Append it to your
 *   document (`container.appendChild(clean)` adopts it) or serialise it with
 *   `new XMLSerializer().serializeToString(clean)`.
 * - Given an **element**, it is cleaned in place and returned. Use this form
 *   only for nodes you parsed yourself into an inert document; an untrusted
 *   tree that is already live in the page has already had its chance to run.
 *
 * @throws {SvgSanitizeError} `unsupported` when there is no DOM, `malformed`
 *   for input that is not well-formed XML, `not-svg` when the root is not an
 *   `<svg xmlns="http://www.w3.org/2000/svg">`.
 */
export function sanitizeSvg(
  input: string | SVGSVGElement,
  options: SanitizeSvgOptions = {},
): SVGSVGElement {
  const win =
    options.window ?? (typeof window !== "undefined" ? (window as unknown as WindowLike) : undefined);
  if (!win) {
    throw new SvgSanitizeError(
      "unsupported",
      "sanitizeSvg needs a DOM: run it in a browser, or pass { window } (for example from jsdom).",
    );
  }
  const purifier = getPurifier(win);
  if (!purifier) {
    throw new SvgSanitizeError("unsupported", "DOMPurify reports this environment as unsupported.");
  }

  const root = typeof input === "string" ? parseSvg(input, win) : assertSvgRoot(input);

  const allowData = options.allowDataImages !== false;
  const allowUse = options.allowUse !== false;
  const allowStyle = options.allowStyleElement !== false;

  const isSafeRef: RefPolicy = (value) => {
    const v = value.trim();
    return v.startsWith("#") || (allowData && /^data:image\//i.test(v));
  };
  const policy: HookPolicy = {
    // <use> pulls in and re-renders another subtree, so it is held to a stricter
    // rule than <image>: same-document fragments only — never a data: payload.
    acceptRef: (value, el) =>
      el.localName === "use" ? value.trim().startsWith("#") : isSafeRef(value),
    sanitizeStyleAttr: (css) => sanitizeStyleAttr(css, isSafeRef),
    sanitizeStyleSheet: (css) => sanitizeStyleSheet(css, isSafeRef),
  };

  flattenCdata(root);
  withPolicy(policy, () =>
    purifier.sanitize(root, {
      IN_PLACE: true,
      USE_PROFILES: { svg: true, svgFilters: true },
      // <script> is already outside the profile; naming it is belt-and-braces.
      // <foreignObject> is an HTML island whose <img onerror> executes.
      FORBID_TAGS: allowStyle ? ["script", "foreignObject"] : ["script", "foreignObject", "style"],
      // DOMPurify's svg profile omits <use> (historically an XSS/SSRF vector via
      // external documents). Adding it back is safe only because the hook
      // restricts it to same-document #fragments, which cannot reach out.
      ADD_TAGS: allowUse ? ["use"] : [],
      // Inert attributes the profile happens to lack: `role` (accessibility)
      // and the SMIL value attributes of <animateTransform>/<animateMotion>,
      // without which a plain loading spinner silently stops turning.
      ADD_ATTR: ["role", "from", "to", "calcMode"],
      // DOMPurify's DOM-clobbering guard drops any id that collides with a
      // property of document or <form> — `blur`, `title`, `focus`, `hidden`,
      // `animate` — which silently breaks `filter="url(#blur)"`. Clobbering is
      // an HTML-element phenomenon (named access on window/document only ever
      // exposes HTML elements); this output is SVG-only, so the guard buys
      // nothing here and is switched off.
      SANITIZE_DOM: false,
      NAMESPACE: SVG_NS,
    }),
  );
  return root as SVGSVGElement;
}

/** Parse a source string into an `<svg>` root in an inert XML document. */
function parseSvg(source: string, win: WindowLike): Element {
  const text = source.trim();
  if (!text) throw new SvgSanitizeError("malformed", "Input is empty.");

  const doc = new win.DOMParser().parseFromString(text, "image/svg+xml");
  const root = doc.documentElement;
  // Browsers report XML errors with a <parsererror> element — as the root, or
  // inserted into a partial tree. Either way the file is refused whole.
  if (!root || doc.getElementsByTagName("parsererror").length > 0) {
    throw new SvgSanitizeError("malformed", "Input is not well-formed XML.");
  }
  return assertSvgRoot(root);
}

function assertSvgRoot(el: Element): Element {
  if (!el || el.nodeType !== 1 || el.localName !== "svg") {
    throw new SvgSanitizeError("not-svg", "Root element is not <svg>.");
  }
  if (el.namespaceURI !== SVG_NS) {
    throw new SvgSanitizeError(
      "not-svg",
      'Root <svg> is not in the SVG namespace; it needs xmlns="http://www.w3.org/2000/svg".',
    );
  }
  return el;
}

/**
 * Turn CDATA sections into plain text nodes. XML parsing keeps
 * `<style><![CDATA[ … ]]></style>` (what Illustrator writes) as a CDATASection,
 * and DOMPurify only allows `#text` nodes — without this pass the CSS would be
 * dropped, and the artwork with it. The content is identical either way.
 */
function flattenCdata(root: Element): void {
  const doc = root.ownerDocument;
  const walker = doc.createNodeIterator(root, 0x8 /* NodeFilter.SHOW_CDATA_SECTION */);
  const sections: Node[] = [];
  for (let node = walker.nextNode(); node; node = walker.nextNode()) sections.push(node);
  for (const node of sections) {
    node.parentNode?.replaceChild(doc.createTextNode(node.nodeValue ?? ""), node);
  }
}
