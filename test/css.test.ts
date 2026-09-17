/**
 * The CSS scrubber on its own. Under jsdom there are no constructable
 * stylesheets, so these exercise the textual fallback path — the one that
 * runs in Node and in older browsers, and the one most worth proving.
 */

import { describe, expect, it } from "vitest";
import { decodeCssEscapes, hasExternalCss, sanitizeStyleAttr, sanitizeStyleSheet, scrubUrls } from "../src/css";

const strict = (v: string) => v.trim().startsWith("#") || /^data:image\//i.test(v.trim());

describe("decodeCssEscapes", () => {
  it.each([
    ["@\\69 mport", "@import"],
    ["@\\49\\4d\\50\\4f\\52\\54", "@IMPORT"],
    ["@\\i\\m\\p\\o\\r\\t", "@import"],
    ["u\\72 l(", "url("],
    ["u\\72l(", "url("],
    ["\\000075rl(", "url("],
    ["@\\69\r\nmport", "@import"], // CRLF after a hex escape counts as one whitespace
    ["a\\\nb", "ab"], // backslash-newline is a line continuation
    [".sm\\:flex", ".sm:flex"],
  ])("%j → %j", (input, expected) => {
    expect(decodeCssEscapes(input)).toBe(expected);
  });
});

describe("scrubUrls", () => {
  it("replaces external url()/src() with none and keeps #refs and data:image", () => {
    expect(scrubUrls("fill:url(https://x.invalid/a.svg#g)", strict)).toBe("fill:none");
    expect(scrubUrls("fill:url('https://x.invalid/a.svg#g')", strict)).toBe("fill:none");
    expect(scrubUrls('fill:URL( "https://x.invalid/a.svg#g" )', strict)).toBe("fill:none");
    expect(scrubUrls("src:src(https://x.invalid/f.woff2)", strict)).toBe("src:none");
    expect(scrubUrls("fill:url(#g)", strict)).toBe("fill:url(#g)");
    expect(scrubUrls("fill:url( '#g' )", strict)).toBe("fill:url( '#g' )");
    expect(scrubUrls("fill:url(data:image/png;base64,AAAA)", strict)).toBe("fill:url(data:image/png;base64,AAAA)");
    expect(scrubUrls("fill:url(data:text/html,x)", strict)).toBe("fill:none");
  });

  it("treats bare strings in image-set()/image() as URLs", () => {
    expect(scrubUrls('background:image-set("https://x.invalid/a.png" 1x)', strict)).toBe("background:none");
    expect(scrubUrls("background:-webkit-image-set('https://x.invalid/a.png' 1x, url(#b) 2x)", strict)).toBe("background:none");
    expect(scrubUrls("background:image-set(url(https://x.invalid/a.png) 1x)", strict)).toBe("background:image-set(none 1x)");
    expect(scrubUrls("background:image('https://x.invalid/a.png')", strict)).toBe("background:none");
    expect(scrubUrls("background:image-set(url(#a) 1x)", strict)).toBe("background:image-set(url(#a) 1x)");
    expect(scrubUrls('background:image-set("data:image/png;base64,AA" 1x)', strict)).toBe('background:image-set("data:image/png;base64,AA" 1x)');
  });

  it("fails closed on an unterminated call", () => {
    expect(scrubUrls('background:image-set("https://x.invalid/a.png" 1x', strict)).toBe("background:none");
  });
});

describe("hasExternalCss", () => {
  it.each([
    ["@import url(x.css);", true],
    ["@\\69 mport url(x.css);", true],
    ["fill:u\\72 l(https://x.invalid)", true],
    ["fill:url(https://x.invalid)", true],
    ["fill:url(#g);stroke:none", false],
    [".a{color:red}", false],
    ["content:'@import'", true], // looks external → will be normalised; that is a fidelity cost, not a safety one
  ])("%j → %s", (css, expected) => {
    expect(hasExternalCss(css, strict)).toBe(expected);
  });
});

describe("sanitizeStyleSheet (textual fallback)", () => {
  it("returns clean CSS byte-for-byte — no reformatting, ever", () => {
    const css = "  .a{fill:#2849FF;}\n\t.b { stroke : url( #g ) ; }  /* comment */\n";
    expect(sanitizeStyleSheet(css, strict)).toBe(css);
  });

  it("strips @import, including escaped spellings, and keeps the other rules", () => {
    const css = '@import url("https://x.invalid/a.css");\n@\\69 mport "b.css" screen;\n.a{fill:#2849ff}';
    const out = sanitizeStyleSheet(css, strict);
    expect(out).not.toMatch(/import/i);
    expect(out).toContain(".a{fill:#2849ff}");
  });

  it("scrubs escaped url() that only shows after unescaping", () => {
    const out = sanitizeStyleSheet(".a{fill:u\\72 l(https://x.invalid/p.svg#g)}.b{fill:#000}", strict);
    expect(out).toBe(".a{fill:none}.b{fill:#000}");
  });

  it("survives nested escaping without leaving anything behind", () => {
    const out = sanitizeStyleSheet("@\\5c 69 mport url(https://x.invalid/a.css); .a{fill:red}", strict);
    expect(hasExternalCss(out, strict)).toBe(false);
    expect(out).toContain(".a{fill:red}");
  });
});

describe("sanitizeStyleAttr", () => {
  it("returns clean declarations byte-for-byte", () => {
    const css = "fill:#2849ff;fill-opacity:1;stroke:none;stroke-width:0.264583";
    expect(sanitizeStyleAttr(css, strict)).toBe(css);
  });

  it("scrubs only the offending declaration value", () => {
    expect(sanitizeStyleAttr("fill:url(https://x.invalid/p.svg#g);stroke:#000", strict)).toBe("fill:none;stroke:#000");
    expect(sanitizeStyleAttr("fill:u\\72 l(https://x.invalid/p.svg#g);stroke:#000", strict)).toBe("fill:none;stroke:#000");
  });

  it("honours the ref policy for data: images", () => {
    const noData = (v: string) => v.trim().startsWith("#");
    expect(sanitizeStyleAttr("fill:url(data:image/png;base64,AA)", strict)).toBe("fill:url(data:image/png;base64,AA)");
    expect(sanitizeStyleAttr("fill:url(data:image/png;base64,AA)", noData)).toBe("fill:none");
  });
});
