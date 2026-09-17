import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

export type FixtureGroup = "attacks" | "legit" | "samples";

export function fixture(group: FixtureGroup, name: string): string {
  return readFileSync(join(FIXTURES, group, `${name}.svg`), "utf8");
}

export function fixtures(group: FixtureGroup): Array<{ name: string; source: string }> {
  return readdirSync(join(FIXTURES, group))
    .filter((f) => f.endsWith(".svg"))
    .sort()
    .map((f) => ({ name: f.replace(/\.svg$/, ""), source: fixture(group, f.replace(/\.svg$/, "")) }));
}

/**
 * Strings that must never appear in sanitised output. Every attack fixture
 * carries them: `attacker.invalid` on anything that would fetch (RFC 2606
 * reserved TLD, never resolves), `EXEC_CANARY` on anything that would run.
 */
export const CANARIES = ["attacker.invalid", "EXEC_CANARY"] as const;

export function serialize(node: Node): string {
  return new XMLSerializer().serializeToString(node);
}

/** Parse as the library does, without sanitising — for before/after comparisons. */
export function parseInert(source: string): SVGSVGElement {
  const doc = new DOMParser().parseFromString(source.trim(), "image/svg+xml");
  return doc.documentElement as unknown as SVGSVGElement;
}

const isSafeRef = (value: string): boolean => {
  const v = value.trim();
  return v.startsWith("#") || /^data:image\//i.test(v);
};

/** A deliberately naive, independent CSS unescape (not the library's own). */
const unescapeCss = (css: string): string =>
  css
    .replace(/\\([0-9a-fA-F]{1,6})(?:\r\n|[ \t\n\r\f])?/g, (_, hex: string) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\(.)/g, "$1");

/** Anything in this CSS text that would make a browser fetch. */
function cssReaches(css: string): string[] {
  const out: string[] = [];
  const text = unescapeCss(css);
  if (/@import/i.test(text)) out.push("@import");
  for (const m of text.matchAll(/(?:url|src)\(\s*(['"]?)(.*?)\1\s*\)/gi)) {
    if (!isSafeRef(m[2] ?? "")) out.push(`url(${m[2]})`);
  }
  for (const m of text.matchAll(/(?:image-set|image)\(([^)]*)\)/gi)) {
    for (const s of (m[1] ?? "").matchAll(/(['"])(.*?)\1/g)) {
      if (!isSafeRef(s[2] ?? "")) out.push(`image-set(${s[2]})`);
    }
  }
  return out;
}

/**
 * Everything in `root` that could still run or fetch. An empty list means the
 * tree is inert. This walker is independent of the library's own checks: it
 * knows nothing about DOMPurify, and only asks "could this line reach out?".
 */
export function liveSurface(root: Element): string[] {
  const findings: string[] = [];
  const walk = (node: Node): void => {
    if (node.nodeType === 7 /* PROCESSING_INSTRUCTION */) {
      findings.push(`<?${(node as ProcessingInstruction).target}?>`);
      return;
    }
    if (node.nodeType !== 1) return;
    const el = node as Element;
    const tag = el.localName;
    const lc = tag.toLowerCase();
    if (lc === "script" || lc === "foreignobject") findings.push(`<${tag}>`);

    for (const attr of Array.from(el.attributes)) {
      const where = `<${tag} ${attr.name}>`;
      const value = attr.value;
      if (/^on/i.test(attr.localName)) findings.push(`${where} handler`);
      const uri = value.replace(/[\s\x00-\x1f]/g, "");
      if (/^(javascript|vbscript|data:text\/html)/i.test(uri)) findings.push(`${where} = ${value}`);
      if (attr.localName === "href" || attr.localName === "src") {
        if (!isSafeRef(value)) findings.push(`${where} = ${value}`);
      } else {
        for (const reach of cssReaches(value)) findings.push(`${where} ${reach}`);
      }
    }
    if (lc === "style") {
      for (const reach of cssReaches(el.textContent ?? "")) findings.push(`<style> ${reach}`);
    }
    for (const child of Array.from(el.childNodes)) walk(child);
  };
  walk(root);
  return findings;
}
