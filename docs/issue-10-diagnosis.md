# Issue #10: spaced wikilinks and the 302

Issue #10 isn't a robot.wtf bug. The wiki engine lives in three other repos, so
this repo only needs to track the fix. Both bugs below are confirmed by reading
the code; bug 1 is also reproduced against the real `WikiLinkIndex`. Nothing
has been run against the live wiki or the fork's test suite.

Status: diagnosed, not filed. The session that did this had no write access to
the other repos, so the next step is whoever has it.

## What to do

1. File bug 1 in `schuyler/otterwiki-api` and bug 2 in `schuyler/otterwiki`
   (the `wikibot-io` branch). The text for each is below.
2. Comment on #10 with links to both, then close it as not planned.
3. Fix them, then redeploy. `deploy.sh` reinstalls all three from git, and the
   link index is in-memory and rebuilt at startup, so there's no data
   migration.

## Bug 1: spaced links never match their page

With `TREAT_UNDERSCORE_AS_SPACE_FOR_TITLES = True` (it is, see
`ansible/roles/deploy/templates/settings.cfg.j2`), a page linked as
`[[Design Notes]]` shows no inbound links, and `find_orphaned_notes` reports it
as an orphan.

`normalize_target()` in `otterwiki_api/wikilinks.py` strips, drops a leading
`/` and `#anchor`, and lowercases unless `RETAIN_PAGE_NAME_CASE` is set. It
never turns spaces into underscores. `WikiLinkIndex.build()` then files
sources under the on-disk name (`Design_Notes`) and targets under the raw text
(`Design Notes`), and the two never meet. Core's
`otterwiki.helper.get_filename()` does the space→underscore step; the index
doesn't use it.

Repro, with `RETAIN_PAGE_NAME_CASE` and `TREAT_UNDERSCORE_AS_SPACE_FOR_TITLES`
both on, and pages `Home.md` = `[[Design Notes]] [[Moderation]]`,
`Design_Notes.md`, `Moderation.md`:

```
incoming keys: ['Design Notes', 'Moderation']
get_links_for_page("Design_Notes") -> incoming: []          # bug
get_links_for_page("Moderation")   -> incoming: ['Home']    # fine
get_links_for_page("Home")         -> outgoing: ['Design Notes', 'Moderation']
```

`get_links` echoes `Browse Flow` with a space for the same reason, and
`find_orphaned_notes` (`otterwiki_mcp/server.py`) treats an empty `linked_from`
as an orphan, so the orphan list is this bug seen from the other side.
Single-token links only work because the raw text happens to equal the slug.

Fix:

- Make `normalize_target()` produce the same key as `get_filename()`, ideally
  by calling it so they can't drift.
- Normalise the lookup side the same way (`/links/<path>` and `get_page` in
  `routes.py`).
- `rewrite_links()` shares the function, so renames start rewriting
  `[[Design Notes]]` links too.
- Test that `[[Design Notes]]` and `[[Design_Notes]]` are the same edge.

Unconfirmed: the original report shows both `Questions_For_Schuyler` and
`Questions_for_Schuyler`. With case retained, links are case-sensitive, so
that may be a real case mismatch in the wiki rather than a typo. Check the
filename in the wiki's git repo.

## Bug 2: the 302 on spaced API paths

`read_note("Deploy Setup Checklist")` fails with
`Wiki API error (302): Redirecting...`; the underscored name works.

The redirect comes from `_normalize_spaces_to_underscores` in
`otterwiki/views.py`, a global `before_request` hook on the fork that 302s any
GET with a space in the path. It's meant for browser URLs but also catches
`/api/v1/*`. otterwiki-mcp's `WikiClient` builds its `httpx.AsyncClient`
without `follow_redirects`, so the 302 surfaces as an error. The API doesn't
need the redirect, since `resolve_filename()` already handles spaces.

The issue suggests answering with 307/308 instead. That wouldn't help: the
client follows no redirects at all, and the hook only fires for GET anyway.

Fix, in order of preference:

1. Skip the hook for `/api/` paths in the fork.
2. Set `follow_redirects=True` in otterwiki-mcp's `WikiClient`, as a backstop.
3. Test that `GET /api/v1/pages/Some Page` returns 200 with the config on.
