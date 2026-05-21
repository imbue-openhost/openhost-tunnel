#!/usr/bin/env python3
"""status_server.py — Status page + tunnel proxy + optional OAuth access control.

Listens on 127.0.0.1:3000. For each request:
  1. If auth is enabled (allowed-users.txt exists), check session cookie
  2. If tunnel port (3001) is responding, proxy to it
  3. Otherwise show status page with connection instructions

Auth flow (when enabled):
  - Visitor hits any page → no session cookie → redirect to /_tunnel/login
  - /_tunnel/login → call OpenHost OAuth service for a Google token
  - OAuth service returns 401 with authorize_url → redirect user there
  - User authenticates with Google → redirected back to /_tunnel/callback
  - We fetch user's email from Google userinfo API
  - Check email against allowed-users.txt
  - If allowed, set signed session cookie → redirect to original URL
  - If not allowed, show "access denied"
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import ssl
import time
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3000
TUNNEL_PORT = int(os.environ.get("TUNNEL_PORT", "3001"))
TUNNEL_URL = os.environ.get("TUNNEL_URL", "https://tunnel.localhost")
AUTH_CREDS = os.environ.get("AUTH_CREDS", "tunnel:changeme")

# OpenHost service integration
ROUTER_URL = os.environ.get("OPENHOST_ROUTER_URL", "")
APP_TOKEN = os.environ.get("OPENHOST_APP_TOKEN", "")
ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "")
APP_NAME = os.environ.get("OPENHOST_APP_NAME", "tunnel")
APP_DATA_DIR = os.environ.get("OPENHOST_APP_DATA_DIR", "/data/app_data/tunnel")

ALLOWED_USERS_FILE = os.path.join(APP_DATA_DIR, "allowed-users.txt")
SESSION_COOKIE = "tunnel_session"
SESSION_MAX_AGE = 7 * 24 * 3600  # 1 week

# Signing key for session cookies (generated once at startup)
_COOKIE_SECRET = os.environ.get("COOKIE_SECRET", "")


def _get_cookie_secret() -> str:
    global _COOKIE_SECRET
    if not _COOKIE_SECRET:
        secret_path = os.path.join(APP_DATA_DIR, ".cookie-secret")
        if os.path.exists(secret_path):
            with open(secret_path) as f:
                _COOKIE_SECRET = f.read().strip()
        else:
            _COOKIE_SECRET = secrets.token_hex(32)
            with open(secret_path, "w") as f:
                f.write(_COOKIE_SECRET)
            os.chmod(secret_path, 0o600)
    return _COOKIE_SECRET


def _auth_enabled() -> bool:
    """Auth is enabled when allowed-users.txt exists and is non-empty."""
    if not os.path.exists(ALLOWED_USERS_FILE):
        return False
    with open(ALLOWED_USERS_FILE) as f:
        lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    return len(lines) > 0


def _load_allowed_users() -> set[str]:
    if not os.path.exists(ALLOWED_USERS_FILE):
        return set()
    with open(ALLOWED_USERS_FILE) as f:
        return {l.strip().lower() for l in f if l.strip() and not l.strip().startswith("#")}


def _save_allowed_users(users: set[str]) -> None:
    with open(ALLOWED_USERS_FILE, "w") as f:
        for u in sorted(users):
            f.write(u + "\n")


def _add_allowed_user(identity: str) -> None:
    users = _load_allowed_users()
    users.add(identity.strip().lower())
    _save_allowed_users(users)


def _remove_allowed_user(identity: str) -> None:
    users = _load_allowed_users()
    users.discard(identity.strip().lower())
    if users:
        _save_allowed_users(users)
    elif os.path.exists(ALLOWED_USERS_FILE):
        os.remove(ALLOWED_USERS_FILE)


def _is_owner(headers) -> bool:
    return headers.get("X-OpenHost-Is-Owner", "").lower() == "true"


def _sign_session(email: str) -> str:
    """Create a signed session value: email|expiry|signature."""
    expiry = str(int(time.time()) + SESSION_MAX_AGE)
    payload = f"{email}|{expiry}"
    sig = hmac.new(_get_cookie_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def _verify_session(cookie: str) -> str | None:
    """Verify a session cookie. Returns email if valid, None otherwise."""
    parts = cookie.split("|")
    if len(parts) != 3:
        return None
    email, expiry, sig = parts
    payload = f"{email}|{expiry}"
    expected = hmac.new(_get_cookie_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    if int(expiry) < int(time.time()):
        return None
    return email


def _tunnel_alive() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", TUNNEL_PORT), timeout=0.5):
            return True
    except (ConnectionRefusedError, OSError):
        return False


def _parse_cookies(header: str) -> dict[str, str]:
    cookies = {}
    if not header:
        return cookies
    for part in header.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def _oauth_service_call(endpoint: str, payload: dict) -> tuple[int, dict]:
    """Call the OpenHost OAuth service via the router."""
    url = f"{ROUTER_URL}/api/services/v2/call/oauth/{endpoint}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {APP_TOKEN}")
    req.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _fetch_google_email(access_token: str) -> str | None:
    """Fetch the user's email from Google's userinfo endpoint."""
    req = urllib.request.Request("https://www.googleapis.com/oauth2/v2/userinfo")
    req.add_header("Authorization", f"Bearer {access_token}")
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            return data.get("email")
    except Exception:
        return None


def _fetch_github_username(access_token: str) -> str | None:
    """Fetch the user's login from GitHub's user endpoint."""
    req = urllib.request.Request("https://api.github.com/user")
    req.add_header("Authorization", f"Bearer {access_token}")
    req.add_header("User-Agent", "openhost-tunnel")
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            return data.get("login")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

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
  .info {{ background: #d1ecf1; border: 1px solid #0dcaf0; }}
</style>
</head>
<body>
<h1>OpenHost Tunnel</h1>
<div class="status waiting">No tunnel client connected.</div>
{auth_notice}
<h2>Quick Start</h2>
<p>1. Install chisel on your local machine:</p>
<pre>
# macOS
brew install chisel

# Linux
curl -sL https://i.jpillora.com/chisel! | bash
</pre>
<p>2. Run the chisel client (replace <code>3000</code> with your local app's port):</p>
<pre>chisel client --auth {auth_creds} {tunnel_url} R:3001:localhost:3000</pre>
<p>3. Your local app is now accessible at: <a href="{tunnel_url}">{tunnel_url}</a></p>
</body>
</html>
"""

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"><title>OpenHost Tunnel - Login</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 400px;
         margin: 80px auto; padding: 0 20px; text-align: center; }}
  a.btn {{ display: inline-block; padding: 12px 24px; margin: 10px;
           background: #4285f4; color: white; text-decoration: none;
           border-radius: 6px; font-size: 1.1em; }}
  a.btn.github {{ background: #333; }}
</style>
</head>
<body>
<h2>Sign in to access the tunnel</h2>
<p>Choose a provider:</p>
<a class="btn" href="/_tunnel/auth/google">Sign in with Google</a>
<br>
<a class="btn github" href="/_tunnel/auth/github">Sign in with GitHub</a>
</body>
</html>
"""

ACCESS_DENIED_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"><title>Access Denied</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 400px;
         margin: 80px auto; padding: 0 20px; text-align: center; }}
  .denied {{ background: #f8d7da; border: 1px solid #f5c6cb; padding: 16px;
             border-radius: 6px; margin: 20px 0; }}
</style>
</head>
<body>
<h2>Access Denied</h2>
<div class="denied">
  <p><strong>{identity}</strong> is not in the allowed users list.</p>
  <p>Contact the tunnel owner to request access.</p>
</div>
</body>
</html>
"""


ADMIN_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenHost Tunnel - Access Control</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 640px;
         margin: 40px auto; padding: 0 20px; color: #333; line-height: 1.6; }}
  h1 {{ color: #111; }}
  .status {{ padding: 12px 16px; border-radius: 6px; margin: 20px 0; }}
  .enabled {{ background: #d4edda; border: 1px solid #28a745; }}
  .disabled {{ background: #f8f9fa; border: 1px solid #dee2e6; }}
  .user-list {{ list-style: none; padding: 0; }}
  .user-list li {{ display: flex; justify-content: space-between; align-items: center;
                   padding: 8px 12px; border: 1px solid #dee2e6; margin: 4px 0;
                   border-radius: 4px; background: #fff; }}
  .user-list li form {{ margin: 0; }}
  .add-form {{ display: flex; gap: 8px; margin: 16px 0; }}
  .add-form input {{ flex: 1; padding: 8px 12px; border: 1px solid #ccc; border-radius: 4px; }}
  button {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
  .btn-add {{ background: #28a745; color: white; }}
  .btn-remove {{ background: #dc3545; color: white; font-size: 0.85em; padding: 4px 12px; }}
  .btn-back {{ background: #6c757d; color: white; text-decoration: none;
               display: inline-block; margin-top: 16px; }}
  .empty {{ color: #888; font-style: italic; }}
</style>
</head>
<body>
<h1>Tunnel Access Control</h1>

<div class="status {status_class}">
  Auth is <strong>{auth_status}</strong>.
  {status_detail}
</div>

<h2>Allowed Users</h2>
<p>Add Google emails or GitHub usernames. Auth activates when at least one user is listed.</p>

<form class="add-form" method="POST" action="/_tunnel/admin/add">
  <input type="text" name="identity" placeholder="email@example.com or github-username" required>
  <button type="submit" class="btn-add">Add</button>
</form>

{user_list_html}

<a href="/" class="btn-back" style="padding: 8px 16px; border-radius: 4px;">Back to tunnel</a>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _read_body(self) -> bytes | None:
        cl = self.headers.get("Content-Length")
        if cl:
            try:
                return self.rfile.read(int(cl))
            except (ValueError, OSError):
                return None
        return None

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code: int, html: str):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, url: str, cookie: str | None = None):
        self.send_response(302)
        self.send_header("Location", url)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _require_owner(self) -> bool:
        """Check X-OpenHost-Is-Owner. If not owner, redirect to zone login or return 401.

        Returns True if the request should be blocked (caller should return early).
        """
        if _is_owner(self.headers):
            return False
        accept = self.headers.get("Accept", "")
        if "text/html" in accept:
            zone = self.headers.get("X-Forwarded-Host", "")
            if zone:
                bare = zone.split(".", 1)[1] if "." in zone else zone
                self._redirect(f"https://{bare}/login")
                return True
        self._send_json(401, {"error": "owner session required"})
        return True

    def _serve_status(self):
        """Serve the status/instructions page. Owner-only (shows credentials)."""
        if self._require_owner():
            return
        auth_notice = ""
        if _auth_enabled():
            auth_notice = '<div class="status info">Access control is enabled. Users must sign in with Google or GitHub.</div>'
        auth_notice += '<p><a href="/_tunnel/admin">Manage access control</a></p>'
        html = STATUS_HTML.format(
            tunnel_url=TUNNEL_URL, auth_creds=AUTH_CREDS, auth_notice=auth_notice,
        )
        self._send_html(200, html)

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

    def _check_auth(self) -> bool:
        """Check if the request is authenticated. Returns True if ok to proceed."""
        if not _auth_enabled():
            return True
        cookies = _parse_cookies(self.headers.get("Cookie", ""))
        session = cookies.get(SESSION_COOKIE, "")
        email = _verify_session(session)
        if email and email.lower() in _load_allowed_users():
            return True
        return False

    def _handle_tunnel_auth(self, provider: str):
        """Start OAuth flow for the given provider."""
        return_to = f"//{APP_NAME}.{ZONE_DOMAIN}/_tunnel/callback?provider={provider}"
        scopes = ["openid", "email"] if provider == "google" else []
        status, data = _oauth_service_call("token", {
            "provider": provider,
            "scopes": scopes,
            "account": "NEW",
            "return_to": return_to,
        })
        if status == 401 and "authorize_url" in data:
            self._redirect(data["authorize_url"])
        elif status == 403 and "required_grant" in data:
            grant_url = data["required_grant"].get("grant_url", "")
            if grant_url:
                self._redirect(grant_url)
            else:
                self._send_html(500, "<h1>OAuth permission not granted</h1>")
        elif status == 503:
            self._send_html(503, "<h1>OAuth provider not configured</h1><p>The zone owner needs to configure OAuth credentials.</p>")
        else:
            self._send_html(500, f"<h1>OAuth error</h1><pre>{json.dumps(data, indent=2)}</pre>")

    def _handle_admin(self):
        """Render the access control admin page (owner-only)."""
        if self._require_owner():
            return
        users = sorted(_load_allowed_users())
        if users:
            items = "".join(
                f'<li>{u} <form method="POST" action="/_tunnel/admin/remove">'
                f'<input type="hidden" name="identity" value="{u}">'
                f'<button type="submit" class="btn-remove">Remove</button></form></li>'
                for u in users
            )
            user_list_html = f'<ul class="user-list">{items}</ul>'
        else:
            user_list_html = '<p class="empty">No users added. Auth is disabled.</p>'

        enabled = _auth_enabled()
        html = ADMIN_HTML.format(
            status_class="enabled" if enabled else "disabled",
            auth_status="enabled" if enabled else "disabled",
            status_detail="Visitors must sign in." if enabled else "Add users below to enable.",
            user_list_html=user_list_html,
        )
        self._send_html(200, html)

    def _handle_admin_add(self):
        """Add a user to the allowed list (owner-only)."""
        if self._require_owner():
            return
        body = self._read_body()
        if not body:
            self._redirect("/_tunnel/admin")
            return
        params = urllib.parse.parse_qs(body.decode())
        identity = params.get("identity", [""])[0].strip()
        if identity:
            _add_allowed_user(identity)
        self._redirect("/_tunnel/admin")

    def _handle_admin_remove(self):
        """Remove a user from the allowed list (owner-only)."""
        if self._require_owner():
            return
        body = self._read_body()
        if not body:
            self._redirect("/_tunnel/admin")
            return
        params = urllib.parse.parse_qs(body.decode())
        identity = params.get("identity", [""])[0].strip()
        if identity:
            _remove_allowed_user(identity)
        self._redirect("/_tunnel/admin")

    def _handle_api_users(self):
        """JSON API for managing allowed users (owner-only)."""
        if self._require_owner():
            return
        if self.command == "GET":
            self._send_json(200, {"users": sorted(_load_allowed_users()), "auth_enabled": _auth_enabled()})
        elif self.command == "POST":
            body = self._read_body()
            if not body:
                self._send_json(400, {"error": "missing body"})
                return
            data = json.loads(body)
            identity = data.get("identity", "").strip()
            if not identity:
                self._send_json(400, {"error": "identity required"})
                return
            _add_allowed_user(identity)
            self._send_json(200, {"ok": True, "users": sorted(_load_allowed_users())})
        elif self.command == "DELETE":
            body = self._read_body()
            if not body:
                self._send_json(400, {"error": "missing body"})
                return
            data = json.loads(body)
            identity = data.get("identity", "").strip()
            if not identity:
                self._send_json(400, {"error": "identity required"})
                return
            _remove_allowed_user(identity)
            self._send_json(200, {"ok": True, "users": sorted(_load_allowed_users())})

    def _handle_callback(self):
        """Handle OAuth callback — fetch token, get user identity, set session."""
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        provider = params.get("provider", ["google"])[0]

        scopes = ["openid", "email"] if provider == "google" else []
        status, data = _oauth_service_call("token", {
            "provider": provider,
            "scopes": scopes,
            "account": "default",
        })
        if status != 200 or "access_token" not in data:
            self._send_html(500, f"<h1>Failed to get token</h1><pre>{json.dumps(data, indent=2)}</pre>")
            return

        token = data["access_token"]
        if provider == "google":
            identity = _fetch_google_email(token)
        else:
            identity = _fetch_github_username(token)

        if not identity:
            self._send_html(500, "<h1>Failed to fetch user identity</h1>")
            return

        allowed = _load_allowed_users()
        if identity.lower() not in allowed:
            self._send_html(403, ACCESS_DENIED_HTML.format(identity=identity))
            return

        session_value = _sign_session(identity.lower())
        cookie = f"{SESSION_COOKIE}={session_value}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age={SESSION_MAX_AGE}"
        self._redirect("/", cookie)

    def _handle(self):
        path = self.path.split("?")[0]

        if path == "/healthz":
            connected = _tunnel_alive()
            body = f'{{"status":"ok","tunnel_connected":{str(connected).lower()}}}'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Admin endpoints (owner-only, gated by X-OpenHost-Is-Owner)
        if path == "/_tunnel/admin":
            self._handle_admin()
            return
        if path == "/_tunnel/admin/add":
            self._handle_admin_add()
            return
        if path == "/_tunnel/admin/remove":
            self._handle_admin_remove()
            return
        if path == "/_tunnel/api/users":
            self._handle_api_users()
            return

        # Auth endpoints (always accessible)
        if path == "/_tunnel/login":
            self._send_html(200, LOGIN_HTML)
            return
        if path == "/_tunnel/auth/google":
            self._handle_tunnel_auth("google")
            return
        if path == "/_tunnel/auth/github":
            self._handle_tunnel_auth("github")
            return
        if path == "/_tunnel/callback":
            self._handle_callback()
            return

        # Access control for tunneled content:
        # - Owner always has access (X-OpenHost-Is-Owner)
        # - When OAuth auth enabled: allowed users with valid session get access
        # - When no auth: only owner
        if not _is_owner(self.headers):
            if _auth_enabled():
                if not self._check_auth():
                    self._redirect("/_tunnel/login")
                    return
            else:
                if self._require_owner():
                    return

        # Proxy or status page
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
    _get_cookie_secret()  # Initialize on startup
    auth_status = "enabled" if _auth_enabled() else "disabled (no allowed-users.txt)"
    print(f"[status] Listening on {LISTEN_HOST}:{LISTEN_PORT}, tunnel port {TUNNEL_PORT}", flush=True)
    print(f"[status] Auth: {auth_status}", flush=True)
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.serve_forever()
