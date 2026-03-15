#!/bin/bash
# robot.wtf service health check with email alerts via msmtp.
# Checks systemd unit status and HTTP reachability for each service.

set -uo pipefail

ALERT_EMAIL="${ALERT_EMAIL:-root}"
HOSTNAME="$(hostname -f)"
FAILURES=""

# Service name -> port mappings
declare -A SERVICES=(
    [robot-chromadb]=8004
    [robot-otterwiki]=8000
    [robot-api]=8002
    [robot-auth]=8003
    [robot-mcp]=8001
)

for svc in "${!SERVICES[@]}"; do
    port="${SERVICES[$svc]}"

    # Check systemd unit is active
    if ! systemctl is-active --quiet "$svc"; then
        FAILURES="${FAILURES}FAIL: ${svc} systemd unit is not active\n"
        continue
    fi

    # Check HTTP endpoint responds
    if ! curl -sf --max-time 5 "http://localhost:${port}/" >/dev/null 2>&1; then
        FAILURES="${FAILURES}FAIL: ${svc} not responding on port ${port}\n"
    fi
done

if [ -n "$FAILURES" ]; then
    printf "Subject: [robot.wtf] Health check FAILED on %s\n\n%b" \
        "$HOSTNAME" "$FAILURES" | msmtp "$ALERT_EMAIL"
fi
