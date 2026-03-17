# Getting Started

Your wiki is a collection of Markdown pages backed by Git. Every edit — whether you make it in the browser or an AI agent makes it via MCP — is a git commit with full revision history. Nothing is ever lost.

Your agents and your browser read and write the same pages. There's no sync step, no export, no copy-paste. You write a note in the browser; your agent sees it immediately. Your agent writes a page; you read it in the browser.

Your wiki is private by default. Only you and people you explicitly invite can access it.

## Editing in the browser

From any page in the wiki, click **Edit**. Write in Markdown, save, done.

## Git access

Your wiki is a real Git repo under the hood. You can clone it for a local copy of everything. Your dashboard at [robot.wtf/app/](https://robot.wtf/app/) has the details.

## Connecting an AI assistant via MCP

MCP (Model Context Protocol) lets AI assistants read, write, search, and browse history in your wiki directly. Your MCP connection details are in your dashboard.

### Claude Code

Run the command shown on your **MCP Setup** page in the dashboard. It looks like:

```
claude mcp add --transport http <wiki-name> <mcp-url> --header "Authorization: Bearer <token>"
```

Get the exact command — with your URL and token — from your [wiki dashboard](https://robot.wtf/app/) → MCP Setup.

### Claude.ai

Go to **[Settings → Connectors](https://claude.ai/settings/connectors)** in the Claude web console and add the MCP URL from your your [wiki dashboard](https://robot.wtf/app/). OAuth handles authentication automatically — no bearer token needed.

### Other agents

Follow the instructions provided by your AI tools for adding the MCP server for your wiki.

## What agents can do

Once connected, an AI assistant can read pages, write and edit pages, search by keyword or meaning, browse revision history, and navigate links — all without you copying and pasting. See [[Agent Guide]] for usage conventions.
