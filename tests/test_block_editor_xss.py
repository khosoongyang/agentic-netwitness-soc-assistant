"""tests/test_block_editor_xss.py -- audit T-01 regression (P0).

frontend/js/components/blockEditor.js interpolated block text into
innerHTML unescaped, so attacker-controlled incident text in a Triage
Ticket / report block executed when the analyst clicked Edit. This test
loads the REAL module in headless Chrome (skipped if Chrome or Node is not
installed) and checks that no element is created from block text and that
the text round-trips exactly through the editor (textContent).
"""
from __future__ import annotations

import http.server
import json
import shutil
import socketserver
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chromium-browser"),
]
CHROME = next((c for c in CHROME_CANDIDATES
               if c and Path(c).is_file() and str(c).lower().endswith((".exe", "chrome", "chromium", "chromium-browser"))),
              None)
pytestmark = pytest.mark.skipif(not (NODE and CHROME), reason="needs Node.js and Chrome/Edge")

PAYLOAD = '<img src=x onerror="window.__fired=(window.__fired||0)+1">'
BLOCKS = [
    {"type": "heading", "level": 2, "text": "H " + PAYLOAD},
    {"type": "paragraph", "text": "P " + PAYLOAD},
    {"type": "bullet_list", "items": [{"text": "L " + PAYLOAD, "level": 0}]},
    {"type": "table", "columns": ["C " + PAYLOAD, "Value"], "rows": [["R " + PAYLOAD, "v"]]},
    {"type": "weird<script>x</script>"},
]

PAGE = """<!doctype html><html><body><div id="m"></div><script type="module">
import { createBlockEditor } from "/frontend/js/components/blockEditor.js";
const ed = createBlockEditor(__BLOCKS__);
document.querySelector("#m").appendChild(ed.element);
setTimeout(() => {
  const texts = [...document.querySelectorAll(".editor-text")].map(e => e.textContent);
  document.title = JSON.stringify({fired: window.__fired || 0,
    imgs: document.querySelectorAll("#m img").length,
    scripts: document.querySelectorAll("#m script").length, texts});
}, 600);
</script></body></html>"""

DRIVER = r"""
import { spawn } from "node:child_process";
const [chrome, url, port] = process.argv.slice(2);
const p = spawn(chrome, ["--headless=new", `--remote-debugging-port=${port}`, "--no-first-run",
  `--user-data-dir=${process.env.PROFILE}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ws_url;
for (let i = 0; i < 60 && !ws_url; i++) {
  try { ws_url = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find(t => t.type === "page")?.webSocketDebuggerUrl; } catch {}
  await sleep(250);
}
const ws = new WebSocket(ws_url); await new Promise(r => ws.addEventListener("open", r));
let id = 0; const pend = new Map(); const errors = [];
ws.addEventListener("message", e => { const m = JSON.parse(e.data); if (pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); }
  if (m.method === "Runtime.exceptionThrown") errors.push(JSON.stringify(m.params.exceptionDetails).slice(0, 300)); });
const send = (method, params = {}) => { const i = ++id; ws.send(JSON.stringify({ id: i, method, params })); return new Promise(r => pend.set(i, r)); };
await send("Runtime.enable");
await send("Page.enable"); await send("Page.navigate", { url });
let title = "";
for (let i = 0; i < 60 && !title.startsWith("{"); i++) {
  await sleep(250);
  const r = await send("Runtime.evaluate", { expression: "document.title", returnByValue: true });
  title = String(r.result?.result?.value || "");
}
console.log(title || JSON.stringify({ error: errors.join(" | ") || "no result" }));
ws.close(); p.kill(); process.exit(0);
"""


class _Handler(http.server.SimpleHTTPRequestHandler):
    page = b""

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/probe"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self.page)
            return
        super().do_GET()

    def guess_type(self, path):
        return "text/javascript" if str(path).endswith(".js") else super().guess_type(path)

    def log_message(self, *a):
        pass


def test_block_editor_never_renders_block_text_as_html(tmp_path):
    # \u003c keeps "</script>" in the fixture from closing the page's own tag.
    _Handler.page = PAGE.replace("__BLOCKS__", json.dumps(BLOCKS).replace("<", "\\u003c")).encode("utf-8")
    with socketserver.TCPServer(("127.0.0.1", 0), _Handler) as httpd:
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        driver = tmp_path / "driver.mjs"
        driver.write_text(DRIVER, encoding="utf-8")
        out = subprocess.run(
            [NODE, str(driver), CHROME, f"http://127.0.0.1:{port}/probe", str(port + 1 if port < 65000 else 9335)],
            capture_output=True, text=True, timeout=90,
            env={**__import__("os").environ, "PROFILE": str(tmp_path / "profile")})
        httpd.shutdown()
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert "error" not in result, result
    assert result["fired"] == 0 and result["imgs"] == 0 and result["scripts"] == 0, result
    # Text round-trips exactly (what the analyst sees is what gets saved).
    assert "P " + PAYLOAD in result["texts"]
    assert "C " + PAYLOAD in result["texts"] and "R " + PAYLOAD in result["texts"]
