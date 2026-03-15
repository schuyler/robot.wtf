# VS-1: ATProto OAuth Spike

Throwaway spike to validate ATProto OAuth against real PDS servers (bsky.social).
Adapted from the [Bluesky cookbook Flask demo](https://github.com/bluesky-social/cookbook/tree/main/python-oauth-web-app) (CC-0).

## What this does

- Implements ATProto OAuth confidential client flow with identity-only scope (`"atproto"`)
- Resolves Bluesky handles to DIDs via DNS TXT + HTTP well-known
- Performs PAR with PKCE + DPoP, redirects to PDS Authorization Server
- Exchanges authorization code for tokens, verifies DID ownership
- Displays authenticated user's DID, handle, and display name

## Prerequisites

- VPS at 192.168.77.107 with Python 3.11+, venv at `/srv/app/venv`
- Client JWK at `/srv/data/client_jwk.json` (ES256, generated via `authlib.jose.JsonWebKey.generate_key("EC", "P-256")`)
- Caddy reverse proxy routing `robot.wtf/auth/*` to `192.168.77.107:8003`
- DNS for `robot.wtf` pointing at the Caddy host

## Deploy to VPS

```bash
# Copy spike code to VPS
scp -r spike/atproto-oauth/ user@192.168.77.107:/srv/app/atproto-spike/

# SSH to VPS
ssh user@192.168.77.107

# Install dependencies
source /srv/app/venv/bin/activate
pip install -r /srv/app/atproto-spike/requirements.txt

# Set Flask secret key (generate a random one)
export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Optionally override JWK path and DB path
# export CLIENT_JWK_PATH=/srv/data/client_jwk.json
# export FLASK_DATABASE_URL=/srv/data/atproto_spike.sqlite

# Run the app
cd /srv/app/atproto-spike
flask --app app run --host 127.0.0.1 --port 8003
```

## Test

1. Open https://robot.wtf/auth/client-metadata.json — verify JSON with correct client_id, scope, redirect_uri
2. Open https://robot.wtf/auth/login
3. Enter a Bluesky handle (e.g., `sderle.bsky.social`)
4. Complete the OAuth flow on bsky.social
5. Verify redirect back to https://robot.wtf/auth/profile showing DID, handle, display name

## Architecture

```
Browser → Caddy (robot.wtf) → Flask :8003
                                  ↓
                            resolve handle → DID → PDS → Auth Server
                                  ↓
                            PAR (PKCE + DPoP) → redirect to Auth Server
                                  ↓
                            callback → token exchange → profile display
```

## Key files

| File | Description |
|------|-------------|
| `app.py` | Flask routes: login, callback, client-metadata, profile, logout |
| `atproto_oauth.py` | OAuth flow: PAR, DPoP proof, token exchange, refresh, revoke |
| `atproto_identity.py` | Handle validation, DID resolution, PDS discovery |
| `atproto_security.py` | SSRF mitigations, hardened HTTP client |
| `schema.sql` | SQLite tables for auth requests and sessions |

## Notes

- This is a SPIKE — not production code. No error recovery, no rate limiting, no graceful degradation.
- The `client_id` URL (`https://robot.wtf/auth/client-metadata.json`) must be publicly accessible for the PDS to fetch it during PAR.
- Scope is `"atproto"` (identity-only) — no PDS write access requested.
- DPoP nonce handling follows the cookbook pattern: retry once on `use_dpop_nonce` error.
- Session data stored in SQLite at `/srv/data/atproto_spike.sqlite`.
- Flask session cookie requires `FLASK_SECRET_KEY` env var.
