"""Serve a live view of a process log for the CI ZDR canary."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _LogHandler(BaseHTTPRequestHandler):
    log_path: Path

    def do_GET(self) -> None:
        if self.path not in {"/", "/logs", "/health"}:
            self.send_error(404)
            return
        try:
            body = self.log_path.read_bytes()
        except OSError:
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    handler = type("LogHandler", (_LogHandler,), {"log_path": args.file})
    with ThreadingHTTPServer((args.host, args.port), handler) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
