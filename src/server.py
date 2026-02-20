#!/usr/bin/env python3
"""GCM MCP Server — FastMCP server setup (wiring only).

Registers tools, prompts, and resources from the tools module.
Supports stdio and SSE transports.
"""

import argparse
import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

from src import config
from src.discovery import get_service_names
from src.tools import (
    list_tools, call_tool,
    list_prompts, get_prompt,
    list_resources, read_resource,
)

logger = config.get_logger("gcm-mcp")

# ==================== MCP Server ====================

app = Server("gcm-mcp-server")

# Register handlers from tools module
app.list_tools()(list_tools)
app.call_tool()(call_tool)
app.list_prompts()(list_prompts)
app.get_prompt()(get_prompt)
app.list_resources()(list_resources)
app.read_resource()(read_resource)


# ==================== Transport ====================

async def _async_main_stdio():
    """Run the MCP server over stdio."""
    logger.info("Starting GCM MCP Server (stdio mode)")
    logger.info("Tools: gcm_auth, gcm_api, gcm_discover")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


# ==================== API Key Middleware ====================

class APIKeyMiddleware(BaseHTTPMiddleware):
    """Validates API key in Authorization header for SSE transport.

    If GCM_MCP_API_KEY is not set, all requests are allowed (open mode).
    If set, every request must include: Authorization: Bearer <key>
    The /health endpoint is always accessible without auth.
    """

    async def dispatch(self, request, call_next):
        # Skip auth if no API key configured (open mode)
        if not config.GCM_MCP_API_KEY:
            return await call_next(request)

        # Always allow health checks without auth
        if request.url.path == "/health":
            return await call_next(request)

        # Validate API key
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()

        if token != config.GCM_MCP_API_KEY:
            logger.warning(f"Unauthorized request from {request.client.host} to {request.url.path}")
            return JSONResponse(
                {"error": "Unauthorized", "message": "Invalid or missing API key"},
                status_code=401,
            )

        return await call_next(request)


def _create_sse_app(host: str = "0.0.0.0", port: int = 8002) -> Starlette:
    """Create a Starlette app with SSE transport for the MCP server."""
    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )

    async def health(request):
        return JSONResponse({
            "status": "ok",
            "server": "GCM MCP Server",
            "version": "1.0.0",
            "transport": "sse",
            "auth_required": config.GCM_MCP_API_KEY is not None,
            "services": get_service_names(),
        })

    middleware = []
    if config.GCM_MCP_API_KEY:
        middleware.append(Middleware(APIKeyMiddleware))
        logger.info("API key authentication enabled")
    else:
        logger.warning("No GCM_MCP_API_KEY set — server is open (no client auth)")

    return Starlette(
        debug=False,
        routes=[
            Route("/health", health),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
        middleware=middleware,
    )


# ==================== Main ====================

def main():
    """Entry point for the MCP server. Supports stdio and SSE transports."""
    parser = argparse.ArgumentParser(description="GCM MCP Server")
    parser.add_argument(
        "--transport", choices=["stdio", "sse"], default="stdio",
        help="Transport mode: stdio (default) or sse"
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="Host to bind SSE server (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8002,
        help="Port for SSE server (default: 8002)"
    )
    args = parser.parse_args()

    if args.transport == "sse":
        import uvicorn
        logger.info(f"Starting GCM MCP Server (SSE mode) on {args.host}:{args.port}")
        logger.info(f"Connect via: http://{args.host}:{args.port}/sse")
        logger.info("Tools: gcm_auth, gcm_api, gcm_discover")
        starlette_app = _create_sse_app(args.host, args.port)
        uvicorn.run(starlette_app, host=args.host, port=args.port)
    else:
        asyncio.run(_async_main_stdio())


if __name__ == "__main__":
    main()
