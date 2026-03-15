#!/bin/bash
# robot.wtf service health check with email alerts via msmtp.
# Alerts once per incident, then on recovery. No mailbombing.

set -uo pipefail

ALERT_EMAIL="${ALERT_EMAIL:-root}"
HOSTNAME="$(hostname -f)"
STATE_DIR="/var/run/robot-healthcheck"
mkdir -p "$STATE_DIR"

FAILURES=""

# Service name -> port mappings
declare -A SERVICES=(
    [robot-otterwiki]=8000
    [robot-api]=8002
    [robot-auth]=8003
    [robot-mcp]=8001
)

for svc in "${!SERVICES[@]}"; do
    port="${SERVICES[$svc]}"
    state_file="$STATE_DIR/$svc"

    # Check systemd unit is active + HTTP responds
    ok=true
    if ! systemctl is-active --quiet "$svc"; then
        ok=false
        reason="systemd unit not active"
    elif ! curl -sf --max-time 5 "http://localhost:${port}/" >/dev/null 2>&1; then
        ok=false
        reason="not responding on port ${port}"
    fi

    if [ "$ok" = false ]; then
        FAILURES="${FAILURES}FAIL: ${svc} — ${reason}\n"
        if [ ! -f "$state_file" ]; then
            # First failure — create state file, alert will be sent below
            touch "$state_file"
        fi
    else
        if [ -f "$state_file" ]; then
            # Was failing, now recovered — send recovery alert
            printf "Subject: [robot.wtf] RECOVERED: %s on %s\n\nService %s is back up." \
                "$svc" "$HOSTNAME" "$svc" | msmtp "$ALERT_EMAIL"
            rm -f "$state_file"
        fi
    fi
done

# Only send failure alert if there are NEW failures (state file just created)
if [ -n "$FAILURES" ]; then
    # Check if any state files were created THIS run (modified in last 60 seconds)
    new_failures=false
    for svc in "${!SERVICES[@]}"; do
        state_file="$STATE_DIR/$svc"
        if [ -f "$state_file" ] && [ "$(find "$state_file" -mmin -1 2>/dev/null)" ]; then
            new_failures=true
            break
        fi
    done

    if [ "$new_failures" = true ]; then
        printf "Subject: [robot.wtf] Health check FAILED on %s\n\n%b" \
            "$HOSTNAME" "$FAILURES" | msmtp "$ALERT_EMAIL"
    fi
fi
