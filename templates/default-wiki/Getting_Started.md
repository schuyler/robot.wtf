# Getting Started

## Connecting an AI assistant

MCP (Model Context Protocol) lets AI assistants read and write your wiki directly. Your MCP connection details are in your dashboard at [robot.wtf/app/](https://robot.wtf/app/).

### Claude Code

In your project, add the MCP server from your dashboard. Claude Code will show it as a set of named tools (e.g. `mcp__your-wiki__read_note`).

### Claude.ai

Go to **Settings → Integrations** and add a new MCP connection. Use the MCP URL from your dashboard.

---

## MCP tool reference

| Tool | What it does |
|---|---|
| `read_note(path)` | Read a page — returns content, frontmatter, and WikiLinks |
| `write_note(path, content, revision?)` | Create or overwrite a page |
| `edit_note(path, revision, old_string, new_string)` | Targeted find-and-replace within a page |
| `list_notes(prefix?, tag?, updated_since?)` | List pages with optional filters |
| `search_notes(query)` | Full-text keyword search |
| `semantic_search(query, n?)` | Similarity search — finds conceptually related pages |
| `get_links(path)` | Incoming and outgoing WikiLinks for a page |
| `get_recent_changes(limit?)` | Recent edits across all pages |
| `get_history(path)` | Revision history for a page |
| `rename_note(path, new_path)` | Rename/move a page; updates all incoming links |
| `delete_note(path)` | Delete a page (recoverable via git history) |
| `find_orphaned_notes()` | Pages not linked from anywhere |

---

## Writing tips

**Read before you write.** `read_note` returns a `revision` SHA. Pass that SHA to `write_note` or `edit_note` when updating a page. If the page changed since your read, you'll get a conflict error — re-read and retry.

**`edit_note` vs `write_note`**: Use `edit_note` for targeted changes (it finds and replaces a unique string). Use `write_note` when you're restructuring the whole page. `old_string` must appear exactly once.

**WikiLinks**: `[[Page Name]]` links to a page. `[[Page Name|display text]]` lets you set the link label. Rename a page with `rename_note` and all links update automatically.

---

## Searching

`search_notes` does full-text keyword matching and is always current.

`semantic_search` finds pages by meaning, not just keywords — useful when you're not sure what you're looking for. Results may lag up to 60 seconds after a new edit.
