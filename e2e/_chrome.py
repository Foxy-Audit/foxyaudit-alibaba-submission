"""Screenshot the live dashboard from headless Chrome, over the DevTools Protocol.

Launched by run_e2e.py inside the isolated venv (it needs `websockets`).

CDP rather than plain `--screenshot=` because the dashboard SPA has NO URL route
for its pages — `go('ledger')` is a JS call and nothing restores it from the
location — so a command-line screenshot can only ever capture the overview.

  python _chrome.py <spec.json> <result.json>

⚠ Chrome is launched as a CHILD PROCESS and terminated by handle. Never by image
name: that would close the developer's own browser along with it.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import time
import traceback
import urllib.request


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _http_json(url: str, timeout: float = 2.0):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class CDP:
    """The smallest useful DevTools client: send a command, wait for its id."""

    def __init__(self, ws_url: str):
        from websockets.sync.client import connect
        # Screenshots arrive as one base64 message and blow past the 1 MiB default.
        self.ws = connect(ws_url, max_size=None, open_timeout=20)
        self._id = 0

    def send(self, method: str, params: dict | None = None, timeout: float = 30.0):
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv(timeout=max(0.1, deadline - time.time())))
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method} failed: {msg['error']}")
                return msg.get("result", {})
        raise TimeoutError(f"{method} did not answer within {timeout}s")

    def eval(self, expression: str, timeout: float = 30.0):
        res = self.send("Runtime.evaluate",
                        {"expression": expression, "returnByValue": True,
                         "awaitPromise": True}, timeout=timeout)
        if res.get("exceptionDetails"):
            raise RuntimeError(f"JS threw: {res['exceptionDetails'].get('text')} "
                               f"({expression[:80]})")
        return res.get("result", {}).get("value")

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def _wait(cdp: CDP, expression: str, deadline: float, label: str):
    """Poll a JS predicate until true, or fail saying what it last returned."""
    last = None
    while time.time() < deadline:
        try:
            last = cdp.eval(expression)
        except Exception as exc:              # a mid-navigation evaluate can throw
            last = f"<{type(exc).__name__}: {exc}>"
        if last is True or (isinstance(last, (int, float)) and last > 0):
            return last
        time.sleep(0.5)
    raise TimeoutError(f"{label}: predicate never became true (last value {last!r})")


def run(spec: dict, result: dict) -> None:
    port = _free_port()
    profile = spec["profile_dir"]
    os.makedirs(profile, exist_ok=True)
    argv = [
        spec["chrome"],
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--hide-scrollbars",
        "--force-prefers-reduced-motion",
        f"--window-size={spec['width']},{spec['height']}",
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={port}",
        "about:blank",
    ]
    result["argv"] = argv
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cdp = None
    try:
        deadline = time.time() + float(spec.get("timeout", 90))
        targets = None
        while time.time() < deadline:
            try:
                _http_json(f"http://127.0.0.1:{port}/json/version")
                targets = [t for t in _http_json(f"http://127.0.0.1:{port}/json")
                           if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
                if targets:
                    break
            except Exception:
                time.sleep(0.3)
        if not targets:
            raise RuntimeError(f"Chrome never exposed a debuggable page on :{port}")

        cdp = CDP(targets[0]["webSocketDebuggerUrl"])
        cdp.send("Page.enable")
        cdp.send("Runtime.enable")
        cdp.send("Page.navigate", {"url": spec["url"]}, timeout=60)

        # The handoff token is redeemed by the SPA during boot, so ledger rows can
        # only appear once that session actually exists. That makes "rows > 0" the
        # honest readiness signal — not a sleep, and not merely "the page loaded".
        _wait(cdp, "typeof go === 'function'", deadline, "SPA never booted")
        rows = _wait(cdp,
                     "document.querySelectorAll('#ledgerBody tr.ldg-row').length",
                     deadline, "ledger never rendered a row")
        result["ledger_rows_rendered"] = rows

        cdp.eval("go('ledger', null)")
        _wait(cdp, "document.getElementById('page-ledger').classList.contains('active')",
              deadline, "ledger page never became active")
        # One frame for the (motion-reduced, therefore instant) scroll to settle.
        cdp.eval("new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")

        result["title"] = cdp.eval("document.title")
        result["ledger_count_text"] = cdp.eval(
            "(document.getElementById('ledgerCount')||{}).textContent || ''")

        shot = cdp.send("Page.captureScreenshot",
                        {"format": "png", "captureBeyondViewport": True}, timeout=60)
        with open(spec["png_path"], "wb") as fh:
            fh.write(base64.b64decode(shot["data"]))
        result["png_bytes"] = os.path.getsize(spec["png_path"])

        # The rendered DOM is what the content-blindness sweep can actually search;
        # a PNG cannot be grepped. Recorded as a separate artifact and swept there.
        dom = cdp.eval("document.documentElement.outerHTML")
        with open(spec["dom_path"], "w", encoding="utf-8") as fh:
            fh.write(dom or "")
        result["dom_bytes"] = len(dom or "")
    finally:
        if cdp is not None:
            cdp.close()
        proc.kill()                      # by HANDLE — never taskkill by name
        try:
            proc.wait(timeout=15)
        except Exception:
            pass


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as fh:
        spec = json.load(fh)
    result: dict = {"ok": False, "error": None}
    try:
        run(spec, result)
        result["ok"] = True
    except Exception:
        result["error"] = traceback.format_exc()
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
