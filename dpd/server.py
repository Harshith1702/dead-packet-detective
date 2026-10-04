"""Local HTTP front end. Diagnostics run in worker threads so the UI never blocks."""
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dpd.case import new_case, run_case
from dpd.report import render_markdown

HOST, PORT = "127.0.0.1", 8765
INDEX = Path(__file__).parent / "static" / "index.html"
CASES = {}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", extra=None):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        if self.path == "/":
            return self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
        case = CASES.get(parts[2]) if len(parts) >= 3 and parts[:2] == ["api", "cases"] else None
        if case is None:
            return self._send(404, {"error": "Not found."})
        if len(parts) == 4 and parts[3] == "report.md":
            return self._send(200, render_markdown(case).encode(), "text/markdown; charset=utf-8",
                              {"Content-Disposition": f'attachment; filename="case-{case["id"]}.md"'})
        self._send(200, case)

    def do_POST(self):
        if self.path != "/api/cases":
            return self._send(404, {"error": "Not found."})
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 4096:
                raise ValueError("Request too large.")
            body = json.loads(self.rfile.read(length) or b"{}")
            case = new_case(body.get("target"), body.get("ports"))
        except (ValueError, TypeError, AttributeError) as exc:
            return self._send(400, {"error": str(exc)})
        CASES[case["id"]] = case
        threading.Thread(target=run_case, args=(case,), daemon=True).start()
        self._send(202, {"id": case["id"]})

    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"Dead Packet Detective listening on {url} (Ctrl+C to stop)")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
