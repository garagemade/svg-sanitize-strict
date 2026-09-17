/**
 * Attack fixtures. Fixtures 01–16 are the sixteen from the svg.garagemade.app
 * security audit — each one was observed executing or beaconing in a browser
 * before the sanitiser existed. 17–28 are extra cases the library also
 * closes. Every fixture is checked three ways:
 *
 *   1. `liveSurface()` — an independent walker that lists anything in the
 *      output which could still run or fetch — must come back empty.
 *   2. Neither canary string may survive serialisation.
 *   3. A fixture-specific expectation says exactly what happened to it.
 *
 * Every fixture file must have an entry in `expectations`, so adding a fixture
 * without describing it fails the suite.
 */

import { describe, expect, it } from "vitest";
import { sanitizeSvg, SvgSanitizeError } from "../src";
import { CANARIES, fixtures, liveSurface, serialize } from "./helpers";

type Check = (clean: SVGSVGElement, out: string) => void;

const none = (clean: Element, selector: string) => expect(clean.querySelector(selector)).toBeNull();
const noHref = (el: Element | null) => {
  expect(el).not.toBeNull();
  expect(el!.hasAttribute("href")).toBe(false);
  expect(el!.hasAttributeNS("http://www.w3.org/1999/xlink", "href")).toBe(false);
};
const noHandlers = (clean: Element) => {
  for (const el of [clean, ...Array.from(clean.querySelectorAll("*"))]) {
    for (const attr of Array.from(el.attributes)) expect(attr.name).not.toMatch(/^on/i);
  }
};

const expectations: Record<string, Check> = {
  // ── The audit's sixteen ────────────────────────────────────────────────
  "01-script-inline": (clean) => {
    none(clean, "script");
    expect(clean.querySelector("rect")).not.toBeNull(); // artwork kept
  },
  "02-onload-root": (clean) => {
    expect(clean.hasAttribute("onload")).toBe(false);
    noHandlers(clean);
    expect(clean.querySelector("g > rect")).not.toBeNull();
  },
  "03-image-onerror": (clean) => {
    noHandlers(clean);
    for (const img of Array.from(clean.querySelectorAll("image"))) {
      // "missing.png" is a relative fetch → stripped; "#nothing" is a fragment → kept
      expect(img.getAttribute("href") ?? "#").toMatch(/^#/);
    }
  },
  "04-onmouseover": (clean) => {
    noHandlers(clean);
    expect(clean.querySelector("rect")?.getAttribute("fill")).toBe("#2849ff");
    expect(clean.querySelector("circle")?.getAttribute("tabindex")).toBe("0");
  },
  "05-animate-onbegin": (clean) => {
    noHandlers(clean);
    none(clean, "animate"); // DOMPurify's svg profile drops <animate> entirely
    expect(clean.querySelector("a")?.getAttribute("href")).toBe("#safe");
  },
  "06-set-onbegin": (clean) => {
    noHandlers(clean);
    none(clean, "set");
  },
  "07-foreignobject-img-onerror": (clean, out) => {
    none(clean, "foreignObject");
    expect(out).not.toMatch(/<(img|iframe|div)\b/);
    expect(clean.querySelector("rect")).not.toBeNull();
  },
  "08-a-href-javascript": (clean, out) => {
    expect(clean.querySelectorAll("a")).toHaveLength(4);
    for (const a of Array.from(clean.querySelectorAll("a"))) noHref(a);
    expect(out).not.toMatch(/javascript/i);
  },
  "09-image-xlink-href-javascript": (clean) => {
    for (const img of Array.from(clean.querySelectorAll("image"))) noHref(img);
  },
  "10-image-href-external": (clean) => {
    expect(clean.querySelectorAll("image")).toHaveLength(2);
    for (const img of Array.from(clean.querySelectorAll("image"))) noHref(img);
  },
  "11-use-href-external": (clean) => {
    expect(clean.querySelectorAll("use")).toHaveLength(2);
    for (const use of Array.from(clean.querySelectorAll("use"))) noHref(use);
  },
  "12-feimage-href-external": (clean) => {
    expect(clean.querySelectorAll("feImage")).toHaveLength(2);
    for (const fe of Array.from(clean.querySelectorAll("feImage"))) noHref(fe);
    expect(clean.querySelector("rect")?.getAttribute("filter")).toBe("url(#f1)"); // same-doc ref kept
  },
  "13-style-import": (clean) => {
    const css = clean.querySelector("style")!.textContent!;
    expect(css).not.toMatch(/@import/i);
    expect(css).toContain(".a { fill: #2849ff; }"); // the rule that paints survives, verbatim
  },
  "14-style-url-exfil": (clean) => {
    const css = clean.querySelector("style")!.textContent!;
    expect(css).toContain("url(#g)");
    expect(css).toContain("url(data:image/png;base64,iVBORw0KGgo=)");
    expect(css).toMatch(/rect \{ fill: none; \}/);
    expect(css).toMatch(/cursor: none, pointer;/);
  },
  "15-style-attr-url-exfil": (clean) => {
    expect(clean.querySelector("rect")?.getAttribute("style")).toBe("fill:none;stroke:#000");
    expect(clean.querySelector("circle")?.getAttribute("style")).toBe("fill:url(#ok);stroke:none;stroke-width:2");
  },
  "16-style-import-escaped": (clean) => {
    const css = clean.querySelector("style")!.textContent!;
    expect(css).not.toMatch(/mport/i);
    expect(css).toContain(".a { fill: #2849ff; }");
  },

  // ── Beyond the sixteen ────────────────────────────────────────────────
  "17-use-href-data": (clean, out) => {
    for (const use of Array.from(clean.querySelectorAll("use"))) noHref(use);
    expect(out).not.toContain("data:");
  },
  "18-image-xlink-href-external": (clean) => {
    for (const img of Array.from(clean.querySelectorAll("image"))) noHref(img);
  },
  "19-presentation-attr-url-exfil": (clean) => {
    const rect = clean.querySelector("rect")!;
    for (const name of ["fill", "stroke", "filter", "mask", "clip-path", "marker-end"]) {
      expect(rect.getAttribute(name), name).toBe("none");
    }
    expect(clean.querySelector("circle")?.getAttribute("fill")).toBe("url(#ok)");
  },
  "20-style-attr-escaped-url": (clean, out) => {
    expect(out).not.toMatch(/\\/); // no escape sequences left to hide behind
    expect(clean.querySelector("rect")?.getAttribute("style")).toContain("stroke:#000");
    expect(clean.querySelector("circle")?.getAttribute("fill")).toBe("none");
    expect(clean.querySelector("ellipse")?.getAttribute("style")).toBe("fill:none");
  },
  "21-image-set-string-exfil": (clean) => {
    const css = clean.querySelector("style")!.textContent!;
    expect(css).toContain(".a { background-image: none; }"); // bare-string form: whole call goes
    expect(css).toContain(".b { background-image: -webkit-image-set(none 1x); }"); // url() form: argument goes
    expect(css).toContain(".c { fill: #2849ff; }");
    expect(clean.querySelector("rect")?.getAttribute("style")).toBe("background-image:none");
  },
  "22-xml-stylesheet-pi": (clean, out) => {
    expect(out).not.toContain("<?");
    expect(clean.querySelector("rect")).not.toBeNull();
  },
  "23-a-xlink-href-javascript": (clean) => {
    noHref(clean.querySelector("a"));
  },
  "24-handlers-on-allowed-smil-and-case": (clean) => {
    noHandlers(clean);
    // The animations themselves are legitimate and survive with their values.
    expect(clean.querySelector("animateTransform")?.getAttribute("to")).toBe("360 32 32");
    expect(clean.querySelector("animateMotion")?.getAttribute("path")).toBe("M0 0L10 10");
  },
  "25-xxe-external-entity": (clean, out) => {
    // If the parser accepted the DOCTYPE, the entity must not have resolved.
    expect(out).not.toContain("<!ENTITY");
    expect(clean.querySelector("text")?.textContent ?? "").not.toContain("attacker");
  },
  "26-image-href-data-non-image": (clean) => {
    const images = Array.from(clean.querySelectorAll("image"));
    expect(images).toHaveLength(3);
    noHref(images[0]!);
    noHref(images[1]!);
    expect(images[2]!.getAttribute("href")).toBe("data:image/png;base64,iVBORw0KGgo="); // real image data survives
  },
  "27-use-href-relative": (clean) => {
    // Even same-origin relative URLs are a fetch; only #fragments stay.
    for (const el of Array.from(clean.querySelectorAll("use, image"))) noHref(el);
  },
  "28-font-face-external": (clean) => {
    const css = clean.querySelector("style")!.textContent!;
    expect(css).not.toContain("attacker");
    expect(css).toMatch(/src: none format\("woff2"\)/);
    expect(css).toContain('font-family: "Tracker", sans-serif; fill: #2849ff;');
  },
};

/** Fixtures the XML parser itself may refuse (a rejection is also a safe outcome). */
const MAY_REJECT = new Set(["25-xxe-external-entity"]);

const all = fixtures("attacks");

describe("attack fixtures", () => {
  it("every fixture file has an expectation", () => {
    expect(all.map((f) => f.name)).toEqual(Object.keys(expectations).sort());
  });

  const run = (name: string, source: string): SVGSVGElement | null => {
    try {
      return sanitizeSvg(source);
    } catch (error) {
      expect(MAY_REJECT.has(name), `unexpected rejection: ${(error as Error).message}`).toBe(true);
      expect(error).toBeInstanceOf(SvgSanitizeError);
      expect((error as SvgSanitizeError).code).toBe("malformed");
      return null;
    }
  };

  describe.each(all)("$name", ({ name, source }) => {
    it("is neutralised", () => {
      const clean = run(name, source);
      if (!clean) return; // refused outright by the XML parser — also safe
      const out = serialize(clean);
      expect(liveSurface(clean)).toEqual([]);
      for (const canary of CANARIES) expect(out).not.toContain(canary);
      expectations[name]!(clean, out);
    });

    it("is stable: sanitising the output again changes nothing", () => {
      const clean = run(name, source);
      if (!clean) return;
      const once = serialize(clean);
      expect(serialize(sanitizeSvg(once))).toBe(once);
    });
  });
});
