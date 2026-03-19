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
        if systemctl is-active --quiet "$svc"; then
            local code
            code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://localhost:${port}/" 2>/dev/null || echo "000")"
            if [[ ! "$code" =~ ^[5] ]] && [ "$code" != "000" ]; then
                return 0
            fi
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
    [robot-platform]=8002
)

platform_alive=false

for svc in robot-otterwiki robot-mcp robot-platform; do
    port="${SERVICES[$svc]}"

    if wait_for_service "$svc" "$port"; then
        pass "${svc} (port ${port}): active and responding"
        [ "$svc" = "robot-platform" ] && platform_alive=true
    else
        fail "${svc} (port ${port}): not responding after 30s"
    fi
done

# robot-platform: expect response with "robot.wtf" in body (only if liveness passed)
if [ "$platform_alive" = true ]; then
    platform_body="$(curl -s --max-time 5 http://localhost:8002/ 2>/dev/null || true)"
    if echo "$platform_body" | grep -q "robot.wtf"; then
        pass "robot-platform body contains 'robot.wtf'"
    else
        fail "robot-platform body does not contain 'robot.wtf'"
    fi
fi

# robot-platform: expect login form content
if [ "$platform_alive" = true ]; then
    auth_body="$(curl -s --max-time 5 http://localhost:8002/auth/login 2>/dev/null || true)"
    if echo "$auth_body" | grep -qi "login\|<form"; then
        pass "robot-platform /auth/login contains login form"
    else
        fail "robot-platform /auth/login missing expected content"
    fi
fi

# ---------------------------------------------------------------------------
# B. Auth well-known endpoints (port 8002, now served by robot-platform)
# ---------------------------------------------------------------------------

# OAuth authorization server metadata — fetch body and status in one call
as_tmp="$(mktemp)"
as_status="$(curl -s -o "$as_tmp" -w "%{http_code}" --max-time 5 \
    http://localhost:8002/.well-known/oauth-authorization-server 2>/dev/null || echo "000")"
as_meta="$(cat "$as_tmp")"
rm -f "$as_tmp"
if [[ ! "$as_status" =~ ^[5] ]] && [ "$as_status" != "000" ] && echo "$as_meta" | grep -q '"issuer"'; then
    pass "robot-platform /.well-known/oauth-authorization-server: ${as_status} with issuer"
else
    fail "robot-platform /.well-known/oauth-authorization-server: status=${as_status}, missing issuer"
fi

# JWKS — fetch body and status in one call
jwks_tmp="$(mktemp)"
jwks_status="$(curl -s -o "$jwks_tmp" -w "%{http_code}" --max-time 5 \
    http://localhost:8002/.well-known/jwks.json 2>/dev/null || echo "000")"
jwks_body="$(cat "$jwks_tmp")"
rm -f "$jwks_tmp"
if [[ ! "$jwks_status" =~ ^[5] ]] && [ "$jwks_status" != "000" ] && echo "$jwks_body" | grep -q '"keys"'; then
    pass "robot-platform /.well-known/jwks.json: ${jwks_status} with keys"
else
    fail "robot-platform /.well-known/jwks.json: status=${jwks_status}, missing keys"
fi

# ---------------------------------------------------------------------------
# C. MCP OAuth metadata (port 8001)
# ---------------------------------------------------------------------------

mcp_tmp="$(mktemp)"
mcp_status="$(curl -s -o "$mcp_tmp" -w "%{http_code}" --max-time 5 \
    http://localhost:8001/.well-known/oauth-protected-resource 2>/dev/null || echo "000")"
mcp_meta="$(cat "$mcp_tmp")"
rm -f "$mcp_tmp"
if [[ ! "$mcp_status" =~ ^[5] ]] && [ "$mcp_status" != "000" ] && echo "$mcp_meta" | grep -q '"authorization_servers"'; then
    pass "robot-mcp /.well-known/oauth-protected-resource: ${mcp_status} with authorization_servers"
else
    # MCP well-known may not be served on bare localhost (requires wiki Host header)
    echo "  WARN: robot-mcp /.well-known/oauth-protected-resource: status=${mcp_status} (non-fatal)"
fi

# ---------------------------------------------------------------------------
# D. Dynamic wiki checks
# ---------------------------------------------------------------------------

ROBOT_ENV="/srv/data/robot.env"
if [ ! -f "$ROBOT_ENV" ]; then
    fail "Cannot find $ROBOT_ENV — skipping wiki checks"
else
    ROBOT_DB_PATH="$(grep -m1 '^ROBOT_DB_PATH=' "$ROBOT_ENV" | cut -d= -f2- | sed "s/^['\"]//;s/['\"]$//")"
    ROBOT_DB_PATH="${ROBOT_DB_PATH:-/srv/data/robot.db}"
    if [ ! -f "$ROBOT_DB_PATH" ]; then
        fail "DB not found at ${ROBOT_DB_PATH} — skipping wiki checks"
    else
        # Read slugs from DB; distinguish error from empty table
        slugs="$(sqlite3 "$ROBOT_DB_PATH" 'SELECT slug FROM wikis;' 2>&1)" || {
            fail "sqlite3 error: ${slugs}"
            slugs=""
        }
        if [ -z "$slugs" ]; then
            fail "No wikis found in DB"
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

exit $(( FAILURES > 125 ? 125 : FAILURES ))
