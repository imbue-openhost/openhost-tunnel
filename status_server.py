#!/usr/bin/env python3
"""status_server.py — Status page + tunnel proxy for the OpenHost tunnel app.

Listens on 127.0.0.1:3000. For each request, checks if the tunnel port
(default 3001) is responding. If yes, proxies the request there (the
user's local app). If no, serves a status page with connection instructions.
"""

import http.client
import os
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3000
TUNNEL_PORT = int(os.environ.get("TUNNEL_PORT", "3001"))
TUNNEL_URL = os.environ.get("TUNNEL_URL", "https://tunnel.localhost")
AUTH_CREDS = os.environ.get("AUTH_CREDS", "tunnel:changeme")


def _tunnel_alive():
    """Check if something is listening on the tunnel port."""
    try:
        with socket.create_connection(("127.0.0.1", TUNNEL_PORT), timeout=0.5):
            return True
    except (ConnectionRefusedError, OSError):
        return False


STATUS_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenHost Tunnel</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 640px;
         margin: 40px auto; padding: 0 20px; color: #333; line-height: 1.6; }}
  h1 {{ color: #111; }}
  code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
  pre {{ background: #f4f4f4; padding: 16px; border-radius: 6px; overflow-x: auto; }}
  .status {{ padding: 12px 16px; border-radius: 6px; margin: 20px 0; }}
  .waiting {{ background: #fff3cd; border: 1px solid #ffc107; }}
</style>
</head>
<body>
<h1>OpenHost Tunnel</h1>
<div class="status waiting">No tunnel client connected.</div>

<h2>Quick Start</h2>
<p>1. Install chisel on your local machine:</p>
<pre>
# macOS
brew install chisel

# Linux
curl -sL https://i.jpillora.com/chisel! | bash

# Or with Go
go install github.com/jpillora/chisel@latest
</pre>

<p>2. Run the chisel client (replace <code>3000</code> with your local app's port):</p>
<pre>chisel client --auth {auth_creds} {tunnel_url} R:3001:localhost:3000</pre>

<p>3. Your local app is now accessible at: <a href="{tunnel_url}">{tunnel_url}</a></p>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _serve_status(self):
        body = STATUS_HTML.format(
            tunnel_url=TUNNEL_URL, auth_creds=AUTH_CREDS,
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy_to_tunnel(self, body=None):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", TUNNEL_PORT, timeout=30)
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "connection", "transfer-encoding")}
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            self.send_response_only(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp_body)
            conn.close()
        except Exception:
            self._serve_status()

    def _handle(self):
        if self.path == "/healthz":
            connected = _tunnel_alive()
            body = f'{{"status":"ok","tunnel_connected":{str(connected).lower()}}}'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if _tunnel_alive():
            body = None
            if self.command in ("POST", "PUT", "PATCH"):
                cl = self.headers.get("Content-Length")
                if cl:
                    body = self.rfile.read(int(cl))
            self._proxy_to_tunnel(body)
        else:
            self._serve_status()

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_OPTIONS(self): self._handle()


if __name__ == "__main__":
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[status] Listening on {LISTEN_HOST}:{LISTEN_PORT}, tunnel port {TUNNEL_PORT}", flush=True)
    server.serve_forever()
