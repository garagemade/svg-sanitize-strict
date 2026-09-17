/**
 * The inverse claim: legitimate SVGs come out the way they went in.
 *
 * The nine `samples/` are the artwork bundled with svg.garagemade.app —
 * gradients with stops, <defs>, transforms, viewBox, even-odd paths, dashed
 * strokes. They must serialise byte-for-byte identically after sanitising.
 * The `legit/` fixtures cover exporter idioms: Illustrator's CDATA <style>,
 * Figma's <style> + class + clip-path, Inkscape's style="" attributes,
 * <use href="#…">, gradient inheritance, markers, masks, patterns, textPath,
 * data: images, and an accessible SMIL spinner.
 */

import { describe, expect, it } from "vitest";
import { sanitizeSvg } from "../src";
import { fixture, fixtures, liveSurface, parseInert, serialize } from "./helpers";

const XLINK = "http://www.w3.org/1999/xlink";

describe("bundled samples survive byte-for-byte", () => {
  it.each(fixtures("samples"))("$name", ({ source }) => {
    const clean = sanitizeSvg(source);
    expect(serialize(clean)).toBe(serialize(parseInert(source)));
    expect(liveSurface(clean)).toEqual([]);
  });
});

describe("exporter idioms survive", () => {
  it.each(["figma-style-class-clip", "use-symbol-fragment", "defs-references", "data-image", "inkscape-style-attrs"])(
    "%s is byte-for-byte identical",
    (name) => {
      const source = fixture("legit", name);
      expect(serialize(sanitizeSvg(source))).toBe(serialize(parseInert(source)));
    },
  );

  it("Illustrator: <style><![CDATA[…]]></style> keeps its CSS, verbatim", () => {
    const clean = sanitizeSvg(fixture("legit", "illustrator-cdata-style"));
    const css = clean.querySelector("style")!.textContent!;
    expect(css).toContain(".st0{fill:#2849FF;}");
    expect(css).toContain(".st1{fill:none;stroke:#101A6B;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10;}");
    expect(css).toContain(".st2{fill:url(#SVGID_1_);}");
    expect(clean.querySelector("style")?.getAttribute("type")).toBe("text/css");
    expect(clean.querySelector("path.st0")).not.toBeNull();
    expect(clean.querySelector("rect.st2")).not.toBeNull();
    expect(clean.querySelector("stop")?.getAttribute("style")).toBe("stop-color:#4F7CFF");
    expect(clean.getAttribute("style")).toBe("enable-background:new 0 0 64 64;");
    expect(clean.getAttributeNS("http://www.w3.org/XML/1998/namespace", "space")).toBe("preserve");
    expect(clean.getAttribute("xmlns:xlink")).toBe(XLINK);
  });

  it("Figma: <style> rules, class and clip-path=url(#id) are untouched", () => {
    const clean = sanitizeSvg(fixture("legit", "figma-style-class-clip"));
    expect(clean.querySelector("style")!.textContent).toContain(".cls-1 { fill: #2849FF; }");
    expect(clean.querySelector("g")?.getAttribute("clip-path")).toBe("url(#clip0_12_34)");
    expect(clean.querySelector("clipPath#clip0_12_34 > rect")).not.toBeNull();
    expect(clean.querySelector("circle")?.getAttribute("class")).toBe("cls-2");
    expect(clean.getAttribute("fill")).toBe("none");
  });

  it("<use> keeps same-document references in both href forms", () => {
    const clean = sanitizeSvg(fixture("legit", "use-symbol-fragment"));
    const uses = Array.from(clean.querySelectorAll("use"));
    expect(uses).toHaveLength(3);
    expect(uses[0]!.getAttribute("href")).toBe("#dot");
    expect(uses[1]!.getAttributeNS(XLINK, "href")).toBe("#dot");
    expect(uses[2]!.getAttribute("href")).toBe("#bar");
    expect(clean.querySelector("symbol#dot")).not.toBeNull();
  });

  it("paint servers, filters, masks, markers and textPath keep their #refs", () => {
    const clean = sanitizeSvg(fixture("legit", "defs-references"));
    expect(clean.querySelector("#inherits")?.getAttribute("href")).toBe("#base");
    expect(clean.querySelector("#inheritsXlink")?.getAttributeNS(XLINK, "href")).toBe("#base");
    expect(clean.querySelector("feImage")?.getAttribute("href")).toBe("#swatch");
    expect(clean.querySelector("textPath")?.getAttribute("href")).toBe("#curve");
    expect(clean.querySelector("a")?.getAttribute("href")).toBe("#swatch");
    const rects = Array.from(clean.querySelectorAll("svg > rect"));
    expect(rects[0]!.getAttribute("fill")).toBe("url(#inherits)");
    expect(rects[1]!.getAttribute("mask")).toBe("url(#fade)");
    expect(rects[2]!.getAttribute("filter")).toBe("url(#blur)");
    expect(rects[2]!.getAttribute("style")).toBe("filter:url(#tex)");
    expect(clean.querySelector("path[marker-end]")?.getAttribute("marker-end")).toBe("url(#arrow)");
  });

  it("data:image/* survives in <image>, xlink:href and CSS url()", () => {
    const clean = sanitizeSvg(fixture("legit", "data-image"));
    const images = Array.from(clean.querySelectorAll("image"));
    expect(images[0]!.getAttribute("href")).toMatch(/^data:image\/png;base64,/);
    expect(images[1]!.getAttributeNS(XLINK, "href")).toMatch(/^data:image\/svg\+xml;utf8,/);
    expect(clean.querySelector("style")!.textContent).toContain("url(data:image/png;base64,iVBORw0KGgo=)");
  });

  it("Inkscape: style=\"\" declaration lists and transforms are untouched", () => {
    const clean = sanitizeSvg(fixture("legit", "inkscape-style-attrs"));
    expect(clean.querySelector("g")?.getAttribute("transform")).toBe("translate(-40.5,-120.2)");
    expect(clean.querySelector("rect")?.getAttribute("style")).toBe("fill:#2849ff;fill-opacity:1;stroke:none;stroke-width:0.264583");
    expect(clean.querySelector("circle")?.getAttribute("style")).toBe("fill:url(#g);stroke:#101a6b");
  });

  it("ids that happen to match document/form properties are kept (SVG cannot clobber)", () => {
    const ids = ["blur", "title", "focus", "hidden", "animate", "body", "name", "remove"];
    const svg = `<svg xmlns="http://www.w3.org/2000/svg"><defs>${ids
      .map((id) => `<filter id="${id}"><feGaussianBlur stdDeviation="1"/></filter>`)
      .join("")}</defs><rect filter="url(#blur)" width="8" height="8"/></svg>`;
    const clean = sanitizeSvg(svg);
    expect(Array.from(clean.querySelectorAll("filter"), (f) => f.getAttribute("id"))).toEqual(ids);
  });

  it("accessible text and a SMIL spinner keep role, aria-*, title/desc and from/to", () => {
    const clean = sanitizeSvg(fixture("legit", "text-and-smil-transform"));
    expect(clean.getAttribute("role")).toBe("img");
    expect(clean.getAttribute("aria-labelledby")).toBe("t d");
    expect(clean.querySelector("title")?.textContent).toBe("Spinner");
    expect(clean.querySelector("desc")?.textContent).toBe("A rotating arc with a label.");
    expect(clean.querySelector("tspan")?.textContent).toBe("…");
    const spin = clean.querySelector("animateTransform")!;
    expect(spin.getAttribute("from")).toBe("0 32 32");
    expect(spin.getAttribute("to")).toBe("360 32 32");
    expect(spin.getAttribute("repeatCount")).toBe("indefinite");
  });
});
