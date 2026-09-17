/**
 * One DOMPurify instance per window, with the strict hooks attached.
 *
 * DOMPurify's svg profile already removes `<script>`, every `on*` handler
 * and `javascript:` URIs. The hooks close the hole it intentionally leaves
 * open: references that make the browser *fetch* something when the SVG
 * is rendered. Policy (what counts as a safe reference, how to scrub CSS)
 * is supplied per call, so the cached instance carries no options.
 */

import createDOMPurify, { type DOMPurify, type WindowLike } from "dompurify";

const XLINK_NS = "http://www.w3.org/1999/xlink";

/** Attributes that can pull in a resource. `xlink:href` is namespaced and handled separately. */
const REF_ATTRS: readonly string[] = ["href", "src"];

export interface HookPolicy {
  /** May this reference stay on this element? */
  acceptRef(value: string, element: Element): boolean;
  /** Clean a `style=""` attribute or a presentation attribute that may hold `url()`. */
  sanitizeStyleAttr(css: string): string;
  /** Clean a `<style>` element's text. */
  sanitizeStyleSheet(css: string): string;
}

const instances = new WeakMap<object, DOMPurify>();

/** The policy for the sanitize() call in progress. DOMPurify is synchronous, so a
 *  module-level slot is safe; `withPolicy` restores it even if sanitize throws. */
let active: HookPolicy | null = null;

export function withPolicy<T>(policy: HookPolicy, run: () => T): T {
  const previous = active;
  active = policy;
  try {
    return run();
  } finally {
    active = previous;
  }
}

function isElement(node: Node): node is Element {
  return node.nodeType === 1;
}

/** A value can only reach off-document through `url(` … `)` or an escape sequence. */
const MAY_HOLD_URL = /[(\\]/;

function scrubAttributes(el: Element, policy: HookPolicy): void {
  for (const name of REF_ATTRS) {
    const value = el.getAttribute(name);
    if (value !== null && !policy.acceptRef(value, el)) el.removeAttribute(name);
  }
  const xlink = el.getAttributeNS(XLINK_NS, "href");
  if (xlink !== null && !policy.acceptRef(xlink, el)) el.removeAttributeNS(XLINK_NS, "href");

  // `style=""` and presentation attributes (`fill`, `filter`, `mask`,
  // `clip-path`, `marker-*`, …) are CSS values and can carry `url(https://…)`.
  // Every attribute is checked; a clean value comes back byte-for-byte.
  for (const attr of Array.from(el.attributes)) {
    if (!MAY_HOLD_URL.test(attr.value)) continue;
    if (attr.namespaceURI === XLINK_NS) continue;
    if (attr.namespaceURI === null && REF_ATTRS.includes(attr.name)) continue;
    const cleaned = policy.sanitizeStyleAttr(attr.value);
    if (cleaned === attr.value) continue;
    if (cleaned.trim()) el.setAttribute(attr.name, cleaned);
    else el.removeAttribute(attr.name);
  }
}

/** Lazily build the DOMPurify instance for `win`, hooks attached, and cache it. */
export function getPurifier(win: WindowLike): DOMPurify | null {
  const cached = instances.get(win);
  if (cached) return cached;

  const instance = createDOMPurify(win);
  if (!instance.isSupported) return null;

  // Runs after DOMPurify has finished with an element's attributes, so
  // javascript: URIs and on* handlers are already gone.
  instance.addHook("afterSanitizeAttributes", (node) => {
    if (active && isElement(node)) scrubAttributes(node, active);
  });

  // <style> bodies: strip @import and external url() while keeping the rules
  // that actually paint the artwork.
  instance.addHook("afterSanitizeElements", (node) => {
    if (!active || !isElement(node) || node.localName !== "style") return;
    const css = node.textContent ?? "";
    if (!css) return;
    const cleaned = active.sanitizeStyleSheet(css);
    if (cleaned !== css) node.textContent = cleaned;
  });

  instances.set(win, instance);
  return instance;
}
