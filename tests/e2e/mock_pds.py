"""Minimal mock PDS OAuth server for E2E testing.

Implements just enough of the ATProto OAuth flow to test robot.wtf's
login → callback → cookie flow without a real Bluesky PDS.

Endpoints:
- GET  /xrpc/_health
- POST /xrpc/com.atproto.server.createAccount
- POST /xrpc/com.atproto.server.createSession
- GET  /.well-known/oauth-authorization-server
- GET  /.well-known/oauth-protected-resource
- POST /oauth/par
- GET  /oauth/authorize (login + consent page)
- POST /oauth/authorize (submit login/consent)
- POST /oauth/token
- GET  /oauth/jwks
"""

import hashlib
import json
import os
import secrets
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs

# In-memory state
_accounts = {}  # handle -> {did, email, password}
_auth_requests = {}  # request_uri -> {client_id, redirect_uri, state, code_challenge, scope, login_hint}
_auth_codes = {}  # code -> {client_id, redirect_uri, did, code_challenge}
_jwks = {"keys": []}  # Empty JWKS — we don't actually verify DPoP in the mock


class MockPDSHandler(BaseHTTPRequestHandler):
    """Handle ATProto PDS OAuth requests."""

    def do_GET(self):
        path = self.path.split("?")[0]
        qs = parse_qs(urlparse(self.path).query)

        if path == "/xrpc/_health":
            self._json(200, {"version": "mock-0.1"})

        elif path == "/.well-known/oauth-authorization-server":
            base = f"http://127.0.0.1:{self.server.server_address[1]}"
            self._json(200, {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "pushed_authorization_request_endpoint": f"{base}/oauth/par",
                "require_pushed_authorization_requests": True,
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                "scopes_supported": ["atproto", "transition:generic"],
                "authorization_response_iss_parameter_supported": True,
                "dpop_signing_alg_values_supported": ["ES256"],
                "client_id_metadata_document_supported": True,
                "subject_types_supported": ["public"],
                "request_parameter_supported": True,
                "request_uri_parameter_supported": True,
                "require_request_uri_registration": True,
            })

        elif path == "/.well-known/oauth-protected-resource":
            base = f"http://127.0.0.1:{self.server.server_address[1]}"
            self._json(200, {
                "resource": base,
                "authorization_servers": [base],
            })

        elif path == "/oauth/authorize":
            request_uri = qs.get("request_uri", [None])[0]
            if not request_uri or request_uri not in _auth_requests:
                self._json(400, {"error": "invalid_request", "error_description": "Unknown request_uri"})
                return
            req = _auth_requests[request_uri]
            login_hint = req.get("login_hint", "")
            # Serve a simple HTML login+consent form
            self._html(200, f"""<!doctype html>
<html>
<head><title>Mock PDS Login</title></head>
<body>
<h1>Mock PDS Authorization</h1>
<form method="POST" action="/oauth/authorize">
  <input type="hidden" name="request_uri" value="{request_uri}" />
  <label>Handle: <input type="text" name="identifier" value="{login_hint}" /></label><br/>
  <label>Password: <input type="password" name="password" /></label><br/>
  <button type="submit" name="action" value="approve">Sign in and Authorize</button>
  <button type="submit" name="action" value="deny">Deny</button>
</form>
</body>
</html>""")

        elif path == "/oauth/jwks":
            self._json(200, _jwks)

        elif path.startswith("/did:plc:"):
            # Serve DID documents (acts as PLC directory for mock accounts)
            did = path[1:]  # strip leading /
            for acct in _accounts.values():
                if acct["did"] == did:
                    self._json(200, _make_did_doc(
                        did, acct["handle"], self.server.server_address[1]
                    ))
                    return
            self._json(404, {"error": "not_found"})

        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode()
        path = self.path.split("?")[0]
        content_type = self.headers.get("Content-Type", "")

        if path == "/xrpc/com.atproto.server.createAccount":
            data = json.loads(raw_body)
            handle = data.get("handle", "")
            email = data.get("email", "")
            password = data.get("password", "")
            if handle in _accounts:
                self._json(400, {"error": "HandleNotAvailable", "message": "Handle already taken"})
                return
            did = f"did:plc:{secrets.token_hex(16)}"
            _accounts[handle] = {"did": did, "email": email, "password": password, "handle": handle}
            self._json(200, {
                "handle": handle,
                "did": did,
                "didDoc": _make_did_doc(did, handle, self.server.server_address[1]),
                "accessJwt": f"mock-access-{secrets.token_hex(8)}",
                "refreshJwt": f"mock-refresh-{secrets.token_hex(8)}",
            })

        elif path == "/xrpc/com.atproto.server.createSession":
            data = json.loads(raw_body)
            identifier = data.get("identifier", "")
            password = data.get("password", "")
            account = _accounts.get(identifier)
            if not account or account["password"] != password:
                self._json(401, {"error": "AuthenticationRequired", "message": "Invalid credentials"})
                return
            self._json(200, {
                "handle": account["handle"],
                "did": account["did"],
                "accessJwt": f"mock-access-{secrets.token_hex(8)}",
                "refreshJwt": f"mock-refresh-{secrets.token_hex(8)}",
            })

        elif path == "/oauth/par":
            # Use urllib.parse.parse_qs for robust form body parsing
            params_multi = parse_qs(raw_body, keep_blank_values=True)
            params = {k: v[0] for k, v in params_multi.items()}

            client_id = params.get("client_id", "")
            redirect_uri = params.get("redirect_uri", "")
            state = params.get("state", "")
            code_challenge = params.get("code_challenge", "")
            scope = params.get("scope", "atproto")
            login_hint = params.get("login_hint", "")

            request_uri = f"urn:ietf:params:oauth:request_uri:{secrets.token_hex(16)}"
            _auth_requests[request_uri] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
                "scope": scope,
                "login_hint": login_hint,
            }
            # Return DPoP nonce in header (mock)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("DPoP-Nonce", f"mock-nonce-{secrets.token_hex(8)}")
            self.end_headers()
            self.wfile.write(json.dumps({
                "request_uri": request_uri,
                "expires_in": 300,
            }).encode())

        elif path == "/oauth/authorize":
            # Use urllib.parse.parse_qs for robust form body parsing
            params_multi = parse_qs(raw_body, keep_blank_values=True)
            params = {k: v[0] for k, v in params_multi.items()}

            request_uri = params.get("request_uri", "")
            action = params.get("action", "")
            identifier = params.get("identifier", "")
            password = params.get("password", "")

            if request_uri not in _auth_requests:
                self._json(400, {"error": "invalid_request"})
                return

            req = _auth_requests.pop(request_uri)

            if action == "deny":
                redirect_uri = req["redirect_uri"]
                sep = "&" if "?" in redirect_uri else "?"
                self._redirect(f"{redirect_uri}{sep}error=access_denied&state={req['state']}")
                return

            # Validate credentials
            account = None
            for acct in _accounts.values():
                if acct["handle"] == identifier or acct["did"] == identifier:
                    if acct["password"] == password:
                        account = acct
                        break

            if not account:
                # Re-show form with error (simplified: just reject)
                self._json(401, {"error": "invalid_credentials"})
                return

            # Generate authorization code
            code = secrets.token_hex(32)
            _auth_codes[code] = {
                "client_id": req["client_id"],
                "redirect_uri": req["redirect_uri"],
                "did": account["did"],
                "code_challenge": req["code_challenge"],
                "scope": req["scope"],
            }

            base = f"http://127.0.0.1:{self.server.server_address[1]}"
            redirect_uri = req["redirect_uri"]
            sep = "&" if "?" in redirect_uri else "?"
            self._redirect(
                f"{redirect_uri}{sep}{urlencode({'code': code, 'state': req['state'], 'iss': base})}"
            )

        elif path == "/oauth/token":
            # Use urllib.parse.parse_qs for robust form body parsing
            params_multi = parse_qs(raw_body, keep_blank_values=True)
            params = {k: v[0] for k, v in params_multi.items()}

            code = params.get("code", "")
            if code not in _auth_codes:
                self._json(400, {"error": "invalid_grant"})
                return

            auth_code = _auth_codes.pop(code)
            # Skip PKCE verification in the mock — just issue tokens
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("DPoP-Nonce", f"mock-nonce-{secrets.token_hex(8)}")
            self.end_headers()
            self.wfile.write(json.dumps({
                "access_token": f"mock-at-{secrets.token_hex(16)}",
                "token_type": "DPoP",
                "scope": auth_code["scope"],
                "sub": auth_code["did"],
                "expires_in": 3600,
                "refresh_token": f"mock-rt-{secrets.token_hex(16)}",
            }).encode())

        elif path == "/oauth/revoke":
            self._json(200, {})

        else:
            self._json(404, {"error": "not_found"})

    def _json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _html(self, status, html):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def _redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress request logging


def _make_did_doc(did, handle, port):
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": [f"at://{handle}"],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": f"http://127.0.0.1:{port}",
        }],
    }


def start_mock_pds(port=0):
    """Start mock PDS in a background thread on 127.0.0.1.

    If port=0, an available port is chosen automatically.
    Returns (base_url, server).
    """
    server = HTTPServer(("127.0.0.1", port), MockPDSHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{actual_port}", server
