# Agent Guide

This wiki is shared memory between you and your user. Treat it as persistent working notes — things you learn, things you write, things you want to remember across sessions. It's git-backed Markdown, and you're connected via MCP.

Your MCP tools are self-describing — you can see what they do from their descriptions. This page covers conventions and pitfalls that aren't obvious from the tool descriptions alone.

**Read this page at the start of every session with this wiki.** Conventions evolve. A quick re-read keeps you current.

## Session start

**First visit?** Read the Home page to understand what the wiki is for and how it's organized. Explore a few pages to get oriented.

**Returning?** Check recent changes to see what happened since your last session, then read any pages relevant to the current task.

**Always:** Read a page before editing it — you'll need the current revision to write back.

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

Your tool descriptions have the details on parameters and usage.

## Writing conventions

**Read before writing.** Reading a page returns the current revision. Passing that revision when you write prevents overwriting concurrent edits.

**Targeted edits vs. full writes.** Use a targeted edit for small changes to existing content. Use a full write for new pages or when restructuring. The match string for a targeted edit must appear exactly once in the page.

**WikiLinks.** `[[Page Path]]` links to a page. `[[Page Path|display text]]` sets the link label.

**Keep Home updated.** When you create a significant new page, link to it from Home or a relevant index page.

**Page structure.** Keep pages focused on one topic. Use clear section headings — semantic search is section-aware, so well-structured pages produce better search results. If a page gets long, offer to split it into subpages or use headings to break it up.

**Commit messages.** Write a brief description of what changed and why.

## Things to watch out for

- **Revision conflicts**: if a write fails due to a conflict (409), someone else edited since your last read. Re-read the page to get the current revision, then retry.
- **Semantic search lag**: Use keyword search on recently edited pages.
- **Don't restructure without instruction**: don't rename, move, or delete pages unless the user explicitly asks.
- **Don’t delete information without asking**: this wiki is your shared memory with your user. If you delete anything, even by accident, it means you might forget something important.
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
