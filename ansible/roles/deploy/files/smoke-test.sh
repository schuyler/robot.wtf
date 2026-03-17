#!/bin/bash
# robot.wtf post-deploy smoke test.
# Validates all services are healthy after a deploy.
# Accumulates failures; exits with failure count (0 = success).

set -uo pipefail

FAILURES=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }

# Wait for a service to become active and its HTTP endpoint to respond.
# Usage: wait_for_service <svc> <port>
# Returns 0 if healthy within 30s, 1 otherwise.
wait_for_service() {
    local svc="$1"
    local port="$2"
    local deadline=$((SECONDS + 30))

    while [ $SECONDS -lt $deadline ]; do
        if systemctl is-active --quiet "$svc" && \
           curl -sf --max-time 5 "http://localhost:${port}/" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# A. Service liveness
# ---------------------------------------------------------------------------

# Service name -> port mappings (ordered for readability)
declare -A SERVICES=(
    [robot-otterwiki]=8000
    [robot-mcp]=8001
    [robot-api]=8002
    [robot-auth]=8003
)

for svc in robot-otterwiki robot-mcp robot-api robot-auth; do
    port="${SERVICES[$svc]}"

    # systemctl check
    if ! systemctl is-active --quiet "$svc"; then
        fail "${svc}: systemd unit not active (waited up to 30s)"
        # No point curling if the unit isn't running
        continue
    fi

    # HTTP reachability with retry loop
    deadline=$((SECONDS + 30))
    http_ok=false
    while [ $SECONDS -lt $deadline ]; do
        if curl -sf --max-time 5 "http://localhost:${port}/" >/dev/null 2>&1; then
            http_ok=true
            break
        fi
        sleep 2
    done

    if [ "$http_ok" = true ]; then
        pass "${svc} (port ${port}): active and responding"
    else
        fail "${svc} (port ${port}): not responding after 30s"
    fi
done

# robot-api: expect 200 with "robot.wtf" in body
api_body="$(curl -s --max-time 5 http://localhost:8002/ 2>/dev/null || true)"
if echo "$api_body" | grep -q "robot.wtf"; then
    pass "robot-api body contains 'robot.wtf'"
else
    fail "robot-api body does not contain 'robot.wtf' (got: ${api_body:0:80})"
fi

# robot-auth: expect 200 with login form content
auth_body="$(curl -s --max-time 5 http://localhost:8003/auth/login 2>/dev/null || true)"
if echo "$auth_body" | grep -qi "login\|<form"; then
    pass "robot-auth /auth/login contains login form"
else
    fail "robot-auth /auth/login missing expected content (got: ${auth_body:0:80})"
fi

# ---------------------------------------------------------------------------
# B. Auth well-known endpoints (port 8003)
# ---------------------------------------------------------------------------

# OAuth authorization server metadata
as_meta="$(curl -s --max-time 5 http://localhost:8003/.well-known/oauth-authorization-server 2>/dev/null || true)"
as_status="$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8003/.well-known/oauth-authorization-server 2>/dev/null || true)"
if [ "$as_status" = "200" ] && echo "$as_meta" | grep -q '"issuer"'; then
    pass "robot-auth /.well-known/oauth-authorization-server: 200 with issuer"
else
    fail "robot-auth /.well-known/oauth-authorization-server: status=${as_status}, missing issuer"
fi

# JWKS
jwks_body="$(curl -s --max-time 5 http://localhost:8003/.well-known/jwks.json 2>/dev/null || true)"
jwks_status="$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8003/.well-known/jwks.json 2>/dev/null || true)"
if [ "$jwks_status" = "200" ] && echo "$jwks_body" | grep -q '"keys"'; then
    pass "robot-auth /.well-known/jwks.json: 200 with keys"
else
    fail "robot-auth /.well-known/jwks.json: status=${jwks_status}, missing keys"
fi

# ---------------------------------------------------------------------------
# C. MCP OAuth metadata (port 8001)
# ---------------------------------------------------------------------------

mcp_meta="$(curl -s --max-time 5 http://localhost:8001/.well-known/oauth-protected-resource 2>/dev/null || true)"
mcp_status="$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8001/.well-known/oauth-protected-resource 2>/dev/null || true)"
if [ "$mcp_status" = "200" ] && echo "$mcp_meta" | grep -q '"authorization_servers"'; then
    pass "robot-mcp /.well-known/oauth-protected-resource: 200 with authorization_servers"
else
    fail "robot-mcp /.well-known/oauth-protected-resource: status=${mcp_status}, missing authorization_servers"
fi

# ---------------------------------------------------------------------------
# D. Dynamic wiki checks
# ---------------------------------------------------------------------------

ROBOT_ENV="/srv/data/robot.env"
if [ ! -f "$ROBOT_ENV" ]; then
    fail "Cannot find $ROBOT_ENV — skipping wiki checks"
else
    ROBOT_DB_PATH="$(grep -m1 '^ROBOT_DB_PATH=' "$ROBOT_ENV" | cut -d= -f2-)"
    if [ -z "$ROBOT_DB_PATH" ]; then
        fail "ROBOT_DB_PATH not set in $ROBOT_ENV — skipping wiki checks"
    elif [ ! -f "$ROBOT_DB_PATH" ]; then
        fail "DB not found at ${ROBOT_DB_PATH} — skipping wiki checks"
    else
        # Read slugs from DB
        slugs="$(sqlite3 "$ROBOT_DB_PATH" 'SELECT slug FROM wikis;' 2>/dev/null || true)"
        if [ -z "$slugs" ]; then
            fail "No wikis found in DB or sqlite3 error"
        else
            while IFS= read -r slug; do
                [ -z "$slug" ] && continue

                # Validate slug format before using in curl
                if [[ ! "$slug" =~ ^[a-z0-9-]+$ ]]; then
                    fail "Wiki slug has invalid format, skipping: '${slug}'"
                    continue
                fi

                http_code="$(curl -s -o /dev/null -w "%{http_code}" \
                    --max-time 5 \
                    -H "Host: ${slug}.robot.wtf" \
                    http://localhost:8000/ 2>/dev/null || echo "000")"

                # Accept 2xx, 3xx, 4xx — only 5xx or connection failure = fail
                if [[ "$http_code" =~ ^[5] ]] || [ "$http_code" = "000" ]; then
                    fail "Wiki ${slug}.robot.wtf: HTTP ${http_code}"
                else
                    pass "Wiki ${slug}.robot.wtf: HTTP ${http_code}"
                fi
            done <<< "$slugs"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "Smoke test PASSED (all checks OK)"
else
    echo "Smoke test FAILED (${FAILURES} check(s) failed)"
fi

exit "$FAILURES"
