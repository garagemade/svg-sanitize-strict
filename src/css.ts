/**
 * CSS scrubbing — the part of the job DOMPurify does not do.
 *
 * DOMPurify validates URLs in attributes (`href`, `src`, `xlink:href`) but
 * treats CSS as opaque text. A `<style>` body or a `style=""` attribute can
 * therefore carry `@import` or `url(https://…)` through an otherwise sanitised
 * SVG, and the browser fetches it the moment the SVG is rendered.
 *
 * Two rules keep this module honest about fidelity:
 *
 * 1. CSS that reaches nowhere is returned byte-for-byte. Re-serialising every
 *    stylesheet through the CSSOM would rewrite the author's CSS on load
 *    (`#2849ff` becomes `rgb(40, 73, 255)`, shorthands expand). Only a sheet
 *    that actually reaches off-document is normalised.
 * 2. Checks run on the *unescaped* text. CSS lets `@\69 mport` and `u\72 l(`
 *    spell `@import` and `url(`, so anything that only looks at the raw
 *    characters can be walked around.
 */

/** Decides whether a URL may stay: `#fragment`, or `data:image/*` when allowed. */
export type RefPolicy = (value: string) => boolean;

/** `url(...)` or `src(...)`, quoted or bare. Over-matching is fine — it fails closed. */
const URL_FN_RE = /(url|src)\(\s*(['"]?)([^'")]*)\2\s*\)/gi;

/** Functions whose *bare string* arguments are URLs (CSS Images 4). */
const IMAGE_FN_RE = /(?:-webkit-)?image-set\(|image\(/gi;

/** Quoted CSS strings, with escapes. */
const STRING_RE = /(['"])(?:\\[\s\S]|(?!\1)[^\\])*\1/g;

/**
 * Resolve CSS escape sequences: `\<hex>{1,6}` plus one optional whitespace
 * (CRLF counts as one), a backslash-newline (line continuation, removed), or a
 * backslash before any other single character.
 *
 * This is a detector, not a re-serialiser: it may decode a little more
 * eagerly than a real CSS tokenizer (`\\69` decodes here but not in CSS),
 * which can only produce a false positive — and a false positive only costs
 * that one sheet its byte-for-byte fidelity.
 */
export function decodeCssEscapes(css: string): string {
  return css
    .replace(/\\([0-9a-fA-F]{1,6})(?:\r\n|[ \t\n\r\f])?/g, (_, hex: string) => {
      const code = parseInt(hex, 16);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
    })
    .replace(/\\(?:\r\n|[\n\r\f])/g, "")
    .replace(/\\(.)/g, "$1");
}

/** Index just past the `)` that closes the `(` at `open`, honouring quotes. */
function closeParen(css: string, open: number): number {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < css.length; i++) {
    const ch = css[i];
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "(") {
      depth++;
    } else if (ch === ")" && --depth === 0) {
      return i + 1;
    }
  }
  return css.length; // unterminated: the rest of the text is the argument
}

/** Replace `image-set()` / `image()` calls that carry an unsafe bare string. */
function scrubImageFunctions(css: string, isSafe: RefPolicy): string {
  let out = "";
  let last = 0;
  IMAGE_FN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IMAGE_FN_RE.exec(css))) {
    const open = m.index + m[0].length - 1;
    const end = closeParen(css, open);
    const body = css.slice(open + 1, end - 1);
    const strings = body.match(STRING_RE) ?? [];
    if (strings.some((s) => !isSafe(s.slice(1, -1)))) {
      out += css.slice(last, m.index) + "none";
      last = end;
    }
    IMAGE_FN_RE.lastIndex = end;
  }
  return out + css.slice(last);
}

/** Replace every external `url()`/`src()`/`image-set()` with `none`. */
export function scrubUrls(css: string, isSafe: RefPolicy): string {
  const urls = css.replace(URL_FN_RE, (match, _fn, _quote, value: string) =>
    isSafe(value) ? match : "none",
  );
  return scrubImageFunctions(urls, isSafe);
}

/** Textual `@import` strip, escape-aware in the at-rule name. */
function stripImports(css: string): string {
  return css.replace(
    /@((?:\\[0-9a-fA-F]{1,6}(?:\r\n|[ \t\n\r\f])?|\\.|[a-zA-Z-])+)[^;]*;?/g,
    (match, name: string) =>
      decodeCssEscapes(name).toLowerCase() === "import" ? "" : match,
  );
}

/** Does this CSS try to reach off-document? Checked after unescaping. */
export function hasExternalCss(css: string, isSafe: RefPolicy): boolean {
  const decoded = decodeCssEscapes(css);
  if (/@import/i.test(decoded)) return true;
  return scrubUrls(decoded, isSafe) !== decoded;
}

/**
 * Normalise a stylesheet through the browser's own CSS parser. `replaceSync`
 * drops `@import` per spec and resolves escape sequences, so the `url()`
 * scrub that follows sees exactly what the browser would. Returns null where
 * constructable stylesheets are unavailable (Node, jsdom, older engines).
 */
function normalizeSheet(css: string): string | null {
  try {
    const Sheet = (globalThis as { CSSStyleSheet?: typeof CSSStyleSheet }).CSSStyleSheet;
    if (typeof Sheet === "function" && "replaceSync" in Sheet.prototype) {
      const sheet = new Sheet();
      sheet.replaceSync(css);
      return Array.from(sheet.cssRules, (rule) => rule.cssText).join("\n");
    }
  } catch {
    /* Malformed CSS, or an engine that still throws on @import — use the textual path. */
  }
  return null;
}

/**
 * Textual scrub for engines without constructable stylesheets. Strips what is
 * visible, then — if escape sequences still hide something — unescapes the
 * whole text and strips again. Gives up (returns "") rather than return CSS
 * it cannot vouch for.
 */
function scrubTextually(css: string, isSafe: RefPolicy): string {
  let out = scrubUrls(stripImports(css), isSafe);
  for (let pass = 0; pass < 3; pass++) {
    if (!hasExternalCss(out, isSafe)) return out;
    out = scrubUrls(stripImports(decodeCssEscapes(out)), isSafe);
  }
  return hasExternalCss(out, isSafe) ? "" : out;
}

/** Clean a full stylesheet (a `<style>` element's text). */
export function sanitizeStyleSheet(css: string, isSafe: RefPolicy): string {
  if (!hasExternalCss(css, isSafe)) return css;
  const normalized = normalizeSheet(css);
  if (normalized !== null) return scrubUrls(normalized, isSafe);
  return scrubTextually(css, isSafe);
}

/** Clean a declaration list (a `style=""` attribute or a presentation attribute). */
export function sanitizeStyleAttr(css: string, isSafe: RefPolicy): string {
  if (!hasExternalCss(css, isSafe)) return css;
  return scrubTextually(css, isSafe);
}
