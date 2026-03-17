#!/bin/bash
# robot.wtf SQLite backup script
# Runs as root via cron, uses sudo -u robot for correct file ownership.
# Proxmox handles VM-level snapshots; this handles point-in-time DB recovery.

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/srv/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
DEST="${BACKUP_DIR}/${TIMESTAMP}"

mkdir -p "${DEST}"
chown robot:robot "${DEST}"

# Backup main database
if [ -f /srv/data/robot.db ]; then
    sudo -u robot sqlite3 /srv/data/robot.db ".backup '${DEST}/robot.db'"
fi

# Backup MCP OAuth database (if exists)
if [ -f /srv/data/mcp_oauth.db ]; then
    sudo -u robot sqlite3 /srv/data/mcp_oauth.db ".backup '${DEST}/mcp_oauth.db'"
fi

# Backup per-wiki databases
for db_file in /srv/data/wikis/*/wiki.db; do
    [ -f "$db_file" ] || continue
    slug=$(basename "$(dirname "$db_file")")
    mkdir -p "${DEST}/wikis/${slug}"
    chown robot:robot "${DEST}/wikis/${slug}"
    sudo -u robot sqlite3 "$db_file" ".backup '${DEST}/wikis/${slug}/wiki.db'"
done

# Prune backups older than retention period
find "${BACKUP_DIR}" -mindepth 1 -maxdepth 1 -type d -mtime "+${RETENTION_DAYS}" -exec rm -rf {} +
