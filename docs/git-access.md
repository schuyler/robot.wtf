# Git-over-HTTPS Access

Each wiki can optionally be cloned and pushed over HTTPS at
`https://{slug}.robot.wtf/.git`. It's off by default. The owner enables it
per wiki.

## Enabling

```sh
# Enable
curl -X POST -H "Authorization: Bearer $PLATFORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}' \
  https://robot.wtf/api/wikis/{slug}/git

# Disable
curl -X POST -H "Authorization: Bearer $PLATFORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}' \
  https://robot.wtf/api/wikis/{slug}/git
```

`GET /api/wikis/{slug}` now includes `git_access_enabled` in the response so
you can check current state without hitting the toggle endpoint.

Owner-only. Returns 403 for anyone else.

## Cloning and pushing

Use your MCP bearer token as the HTTP Basic password. The username is ignored.

```sh
git clone https://x-token:$MCP_TOKEN@{slug}.robot.wtf/.git my-wiki
git push https://x-token:$MCP_TOKEN@{slug}.robot.wtf/.git
```

Tokens are wiki-scoped: a token for wiki A gets a 403 against wiki B. If the
feature is disabled for a wiki, `/.git/*` returns 404 — no auth prompt.

## Behavior

**Rate limiting and quotas.** Pushes count as writes. They're subject to the
same 5/minute write rate limit and the 50 MB disk quota. An over-quota wiki
rejects pushes. After a successful push, disk usage and page count are
recomputed immediately (rather than waiting for the 15-minute quota cron).

**Semantic search.** A push fires otterwiki's `repository_changed` hook, which
triggers incremental reindexing of the changed `.md` files (adds/updates and
deletes). Limitation: only the files listed in the last commit's diff are
reindexed, so a force-push or a push that includes multiple commits can leave
earlier commits' pages stale until a manual `/api/v1/reindex` or the next full
reindex cycle.

## Deploy / infra notes

The `GIT_WEB_SERVER` flag lives in each wiki's `wiki.db` preferences table.
No `settings.cfg` or Ansible change is needed to ship this code.

Before relying on this in production, confirm two things:

1. **Caddy on proxy-1** passes `/.git/*` through to wiki-1 unmodified. The
   Caddyfile for `{slug}.robot.wtf` is not in this repo — check it manually.
2. **`git` is on PATH on wiki-1.** The otterwiki process calls git directly
   for smart-HTTP; if git isn't there, pushes will 500.
