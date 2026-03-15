"""MCP sidecar entry point (port 8001).

Placeholder that imports FastMCP if available, otherwise serves a stub.
Real MCP implementation comes in V2 when the dev wikis are migrated.

Runs under uvicorn (async), not gunicorn.
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger(__name__)

PLATFORM_DOMAIN = os.environ.get("PLATFORM_DOMAIN", "robot.wtf")

try:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("robot.wtf MCP Server")

    @mcp.tool()
    def ping() -> str:
        """Health check — returns pong."""
        return "pong"

    # The ASGI app for uvicorn
    app = mcp.sse_app()
    _has_fastmcp = True
except ImportError:
    logger.warning("FastMCP not installed — using stub ASGI app")
    _has_fastmcp = False

    async def app(scope, receive, send):
        """Minimal ASGI stub when FastMCP is not installed."""
        if scope["type"] == "lifespan":
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
            return

        if scope["type"] != "http":
            return

        path = scope.get("path", "")

        if path == "/.well-known/oauth-protected-resource":
            body = json.dumps({
                "resource": f"https://mcp.{PLATFORM_DOMAIN}",
                "authorization_servers": [
                    f"https://auth.{PLATFORM_DOMAIN}"
                ],
                "bearer_methods_supported": ["header"],
            }).encode()

            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        # Default: 501 stub
        body = json.dumps({"error": "MCP server not yet implemented"}).encode()
        await send({
            "type": "http.response.start",
            "status": 501,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("MCP_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
