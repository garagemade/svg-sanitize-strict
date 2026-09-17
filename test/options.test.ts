import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import { sanitizeSvg, SvgSanitizeError } from "../src";
import { fixture, parseInert, serialize } from "./helpers";

const XLINK = "http://www.w3.org/1999/xlink";

describe("options", () => {
  it("allowStyleElement: false drops <style> but keeps style=\"\" attributes", () => {
    const figma = sanitizeSvg(fixture("legit", "figma-style-class-clip"), { allowStyleElement: false });
    expect(figma.querySelector("style")).toBeNull();
    expect(figma.querySelector("circle")?.getAttribute("class")).toBe("cls-2"); // class itself is harmless

    const inkscape = sanitizeSvg(fixture("legit", "inkscape-style-attrs"), { allowStyleElement: false });
    expect(inkscape.querySelector("rect")?.getAttribute("style")).toBe("fill:#2849ff;fill-opacity:1;stroke:none;stroke-width:0.264583");
  });

  it("allowUse: false drops <use> elements and leaves the <symbol> definitions", () => {
    const clean = sanitizeSvg(fixture("legit", "use-symbol-fragment"), { allowUse: false });
    expect(clean.querySelector("use")).toBeNull();
    expect(clean.querySelector("symbol#dot")).not.toBeNull();
  });

  it("allowDataImages: false strips data: URLs from <image> and CSS", () => {
    const clean = sanitizeSvg(fixture("legit", "data-image"), { allowDataImages: false });
    for (const img of Array.from(clean.querySelectorAll("image"))) {
      expect(img.hasAttribute("href")).toBe(false);
      expect(img.hasAttributeNS(XLINK, "href")).toBe(false);
    }
    expect(clean.querySelector("style")!.textContent).toBe(".tile { fill: none; }");
  });

  it("allowDataImages never loosens <use>: data: on <use> is stripped regardless", () => {
    const clean = sanitizeSvg(fixture("attacks", "17-use-href-data"), { allowDataImages: true });
    for (const use of Array.from(clean.querySelectorAll("use"))) {
      expect(use.hasAttribute("href")).toBe(false);
      expect(use.hasAttributeNS(XLINK, "href")).toBe(false);
    }
  });

  it("window: uses the given DOM implementation (a second jsdom realm here)", () => {
    const other = new JSDOM("");
    const clean = sanitizeSvg(fixture("samples", "logo"), { window: other.window });
    expect(clean instanceof other.window.SVGSVGElement).toBe(true);
    expect(clean instanceof SVGSVGElement).toBe(false);
    expect(new other.window.XMLSerializer().serializeToString(clean)).toBe(serialize(parseInert(fixture("samples", "logo"))));
  });
});

describe("input handling", () => {
  it("returns an SVGSVGElement from an inert document that can be adopted", () => {
    const clean = sanitizeSvg(fixture("samples", "house"));
    expect(clean).toBeInstanceOf(SVGSVGElement);
    expect(clean.ownerDocument).not.toBe(document);
    document.body.appendChild(clean);
    expect(clean.ownerDocument).toBe(document);
    expect(document.querySelector("svg")).toBe(clean);
    clean.remove();
  });

  it("accepts an already-parsed element and sanitises it in place", () => {
    const el = parseInert(fixture("attacks", "10-image-href-external"));
    const out = sanitizeSvg(el);
    expect(out).toBe(el);
    for (const img of Array.from(el.querySelectorAll("image"))) expect(img.hasAttribute("href")).toBe(false);
  });

  it("tolerates a BOM, leading whitespace and an XML declaration", () => {
    const source = "﻿\n  <?xml version=\"1.0\"?>" + fixture("samples", "badge").trimStart().replace(/^<\?xml[^>]*\?>/, "");
    expect(sanitizeSvg(source).querySelectorAll("path").length).toBeGreaterThan(0);
  });

  it.each([
    ["", "malformed"],
    ["   ", "malformed"],
    ["<svg xmlns=\"http://www.w3.org/2000/svg\"><rect></svg>", "malformed"],
    ["not xml at all", "malformed"],
    ["<html xmlns=\"http://www.w3.org/1999/xhtml\"><body/></html>", "not-svg"],
    ["<svg><rect/></svg>", "not-svg"], // no xmlns: not an SVG element to the XML parser
    ["<div xmlns=\"http://www.w3.org/2000/svg\"/>", "not-svg"],
  ])("rejects %j with code %s", (source, code) => {
    let caught: unknown;
    try {
      sanitizeSvg(source);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(SvgSanitizeError);
    expect((caught as SvgSanitizeError).code).toBe(code);
  });

  it("explains the missing namespace", () => {
    expect(() => sanitizeSvg("<svg/>")).toThrow(/xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  });

  it("rejects a non-<svg> element", () => {
    const div = document.createElement("div") as unknown as SVGSVGElement;
    expect(() => sanitizeSvg(div)).toThrow(SvgSanitizeError);
  });

  it("reports an unusable window as unsupported", () => {
    let caught: unknown;
    try {
      sanitizeSvg("<svg xmlns=\"http://www.w3.org/2000/svg\"/>", { window: {} as never });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(SvgSanitizeError);
    expect((caught as SvgSanitizeError).code).toBe("unsupported");
  });
});
