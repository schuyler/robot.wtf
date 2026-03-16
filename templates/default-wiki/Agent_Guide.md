# Agent Guide

This is a personal wiki, git-backed, and you are connected to it via MCP. Every page is Markdown. Every edit is versioned.

## Session start

Read the Home page first. Check recent changes to understand what's been active. Read a page before editing it.

## Tools

**Reading**
- Read a page — returns content and WikiLinks
- List pages — with optional filters (prefix, tag, date)
- Get links for a page — incoming and outgoing WikiLinks
- Get revision history for a page
- Check recent changes across all pages

**Searching**
- Full-text keyword search — always current
- Semantic similarity search — finds conceptually related pages; may lag up to 60 seconds after recent edits

**Writing**
- Targeted edit — find-and-replace a unique string within a page
- Full write — create or overwrite a page

**Maintenance**
- Rename/move a page — updates all incoming links automatically
- Delete a page — recoverable via git history
- Find orphaned pages — pages not linked from anywhere

## Writing conventions

**Read before writing.** Reading a page returns the current revision. Passing that revision when you write prevents overwriting concurrent edits.

**Targeted edits vs. full writes.** Use a targeted edit for small changes to existing content. Use a full write for new pages or when restructuring. The match string for a targeted edit must appear exactly once in the page.

**WikiLinks.** `[[Page Path]]` links to a page. `[[Page Path|display text]]` sets the link label.

**Keep Home updated.** When you create a significant new page, link to it from Home or a relevant index page.

**Commit messages.** Write a brief description of what changed and why.

## Things to watch out for

- **Revision conflicts**: if a write fails due to a conflict, re-read the page and retry.
- **Semantic search lag**: for recently edited pages, use keyword search instead.
- **Don't restructure without instruction**: don't rename, move, or delete pages unless the user explicitly asks.
- **Targeted edit uniqueness**: if the match string isn't unique, the edit will fail — use more context.

## Quick reference

| I want to… | Do… |
|---|---|
| Orient myself | Read the Home page, check recent changes |
| Find a page | Search by keyword or browse the page list |
| Find related content | Use semantic search |
| Add a new page | Write it, then link from Home or a relevant index |
| Update part of a page | Read first, then use a targeted edit |
| Rewrite a page | Read first, then do a full write with the current revision |
| See what changed | Check recent changes or a page's history |
