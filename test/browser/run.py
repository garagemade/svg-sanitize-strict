"""Optional: run the fixtures in real Chromium (jsdom cannot fetch or execute).

    pip install playwright && playwright install chromium
    npm run build && python test/browser/run.py

Two passes over the same fixtures:

  raw        mounts the attack fixtures untouched, as a control: counts the
             network requests Chromium makes off-origin and how many times the
             EXEC_CANARY payload runs. This proves the fixtures are live.
  sanitized  mounts sanitizeSvg(fixture) and expects zero of both; also checks
             the samples/ and legit/ fixtures serialise byte-for-byte.

Exit code 0 means PASS. Nothing is written inside the repository.
"""
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
PKG = HERE.parent.parent
DIST = PKG / "dist" / "index.js"
if not DIST.exists():
    sys.exit("dist/index.js missing — run `npm run build` first")

# Stage everything the page needs in one temp directory (same origin).
stage = Path(tempfile.mkdtemp(prefix="svg-sanitize-strict-"))
shutil.copy(HERE / "harness.html", stage / "harness.html")
shutil.copy(DIST, stage / "index.js")
shutil.copy(PKG / "node_modules" / "dompurify" / "dist" / "purify.es.mjs", stage / "purify.es.mjs")
fixtures = {}
for group in ("attacks", "samples", "legit"):
    d = PKG / "test" / "fixtures" / group
    fixtures[group] = {p.stem: p.read_text(encoding="utf8") for p in sorted(d.glob("*.svg"))}
(stage / "fixtures.json").write_text(json.dumps(fixtures), encoding="utf8")


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def end_headers(self):
        if self.path.endswith((".mjs", ".js")):
            self.send_header("Content-Type", "text/javascript")
        super().end_headers()


os.chdir(stage)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

# Fixtures that must not serialise identically for a known, benign reason.
EXPECTED_CHANGES = {
    "illustrator-cdata-style": "CDATA section becomes a text node; the generator comment is dropped",
}


def run(mode):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        requests = []
        page.on("request", lambda r: requests.append(r.url))
        page.on("pageerror", lambda e: print(f"  [pageerror] {e}"))
        # Answer attacker.invalid instantly (404) instead of hanging on DNS.
        page.route(
            "**/*",
            lambda route: route.fulfill(status=404, body="")
            if "attacker.invalid" in route.request.url
            else route.continue_(),
        )
        page.goto(f"http://127.0.0.1:{port}/harness.html?mode={mode}")
        page.wait_for_function("document.title === 'done'", timeout=30000)
        page.wait_for_timeout(1500)  # let deferred fetches / handlers fire
        results = page.evaluate("window.__results")
        executed = page.evaluate("window.__executed.length")
        version = browser.version
        browser.close()
    external = [u for u in requests if f"127.0.0.1:{port}" not in u]
    return results, external, executed, version


raw, raw_ext, raw_exec, version = run("raw")
san, san_ext, san_exec, _ = run("sanitized")
shutil.rmtree(stage, ignore_errors=True)

print(f"Chromium {version} — constructable stylesheets (CSSOM path): {san['cssom']}")
print()
print("== RAW (control) ==")
print(f"  attack fixtures mounted: {sum(1 for v in raw['attacks'].values() if v == 'mounted')}/{len(raw['attacks'])}")
print(f"  requests off-origin:     {len(raw_ext)}")
for u in sorted(set(raw_ext)):
    print(f"    - {u}")
print(f"  EXEC_CANARY calls:       {raw_exec}")
print()
print("== SANITISED ==")
bad = 0
for name, r in san["attacks"].items():
    if "rejected" in r:
        print(f"  ok  {name}: rejected by the parser ({r['rejected']})")
        continue
    ok = not r["live"] and not r["canary"] and r["stable"]
    bad += 0 if ok else 1
    print(f"  {'ok ' if ok else 'BAD'} {name}" + ("" if ok else f"  live={r['live']} canary={r['canary']} stable={r['stable']}"))
for group in ("samples", "legit"):
    for name, r in san[group].items():
        if r.get("live"):
            bad += 1
            print(f"  BAD {group}/{name}: live={r['live']}")
        elif r.get("identical"):
            print(f"  ok  {group}/{name}: byte-identical")
        elif name in EXPECTED_CHANGES:
            print(f"  ok  {group}/{name}: changed as expected ({EXPECTED_CHANGES[name]})")
        else:
            bad += 1
            print(f"  BAD {group}/{name}: serialisation changed")
print(f"  requests off-origin:     {len(san_ext)}")
for u in sorted(set(san_ext)):
    print(f"    - {u}")
print(f"  EXEC_CANARY calls:       {san_exec}")
print()
print("== <style> of 13-style-import after CSSOM normalisation ==")
print(san["cssomSample"].strip())
print()
verdict = bad == 0 and not san_ext and san_exec == 0 and len(raw_ext) > 0
print("VERDICT:", "PASS" if verdict else "FAIL")
sys.exit(0 if verdict else 1)
