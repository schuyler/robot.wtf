"""Shared platform constants for robot.wtf.

These values are used by the resolver (per-request quota enforcement),
the management middleware (tier limits), and the quota cron script.
"""

# Per-wiki page limit (free tier)
MAX_PAGES_PER_WIKI = 500

# Per-wiki disk quota in bytes (50 MB)
QUOTA_BYTES = 50 * 1024 * 1024
