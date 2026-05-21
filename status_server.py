#!/usr/bin/env python3
"""status_server.py — Lightweight status/instructions page for the tunnel app.

Listens on 127.0.0.1:3000. When no chisel client has connected a reverse
tunnel, this serves the status page with connection instructions. When a
client connects and tunnels their local port to 3000, chisel replaces this
server's traffic with the tunneled app.

Note: chisel's reverse tunnel binding *replaces* the backend for the
tunneled port. So when a client does `R:3000:localhost:8080`, chisel
stops forwarding port 3000 to this status server and instead forwards
it to the client's local port 8080. When the client disconnects, chisel
resumes forwarding to this status server.
"""

import os
from http.server import HTTPServer, BaseHTTPRequestHandler

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3000

TUNNEL_URL = os.environ.get("TUNNEL_URL", "https://tunnel.localhost")
AUTH_CREDS = os.environ.get("AUTH_CREDS", "tunnel:changeme")


HTML_TEMPLATE = """<!DOCTYPE html>
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
<div class="status waiting">
  No tunnel client connected. Follow the instructions below to expose your local app.
</div>

<h2>Quick Start</h2>
<p>1. Install chisel on your local machine:</p>
<pre>
# macOS
brew install chisel

# Linux (download binary)
curl -sL https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz | gunzip > chisel
chmod +x chisel
sudo mv chisel /usr/local/bin/

# Or with Go
go install github.com/jpillora/chisel@latest
</pre>

<p>2. Run the chisel client to tunnel your local app (e.g. running on port 3000):</p>
<pre>chisel client --auth {auth_creds} {tunnel_url} R:3000:localhost:3000</pre>

<p>Replace the second <code>3000</code> with whatever port your local app listens on.</p>

<p>3. Your local app is now accessible at:</p>
<pre>{tunnel_url}</pre>

<h2>How It Works</h2>
<p>The chisel client on your machine opens an outbound WebSocket connection to this
server (NAT/firewall friendly). Your local HTTP traffic is then forwarded through
this tunnel and served at the OpenHost URL above.</p>

<h2>Notes</h2>
<ul>
  <li>The tunnel URL is protected by OpenHost zone auth by default.
      Public access can be configured via <code>public_paths</code>.</li>
  <li>The connection is encrypted (SSH over WebSocket).</li>
  <li>Keep the chisel client running to maintain the tunnel.</li>
</ul>
</body>
</html>
"""


class StatusHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        body = HTML_TEMPLATE.format(
            tunnel_url=TUNNEL_URL,
            auth_creds=AUTH_CREDS,
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


if __name__ == "__main__":
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), StatusHandler)
    print(f"[status] Listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()
