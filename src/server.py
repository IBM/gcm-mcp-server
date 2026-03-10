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
from src import keystore
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
    """Validates API key from the key store in Authorization header.

    Every request must include: Authorization: Bearer <key>
    The /health and /admin/* endpoints are handled separately.
    """

    async def dispatch(self, request, call_next):
        # Always allow health checks without auth
        if request.url.path == "/health":
            return await call_next(request)

        # Admin endpoints use localhost check, not API key
        if request.url.path.startswith("/admin"):
            return await call_next(request)

        # Validate API key against key store
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()

        key_info = keystore.validate_key(token)
        if key_info is None:
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
            "auth_required": True,
            "active_keys": len(keystore.list_keys()),
            "services": get_service_names(),
        })

    # ---- Admin endpoints (localhost only) ----

    # Allowed admin IPs — localhost + Docker bridge (host→container)
    _ADMIN_ALLOWED_IPS = {"127.0.0.1", "::1", "localhost", "172.17.0.1"}

    def _is_localhost(request) -> bool:
        """Check if request originates from localhost or Docker host.

        Allows localhost and Docker bridge IPs so that
        'curl http://localhost:8002/admin/keys' works from the
        Docker host via SSH.
        """
        client_host = request.client.host if request.client else None
        return client_host in _ADMIN_ALLOWED_IPS

    async def admin_create_key(request):
        if not _is_localhost(request):
            return JSONResponse({"error": "Forbidden", "message": "Admin endpoints are localhost only"}, status_code=403)
        try:
            body = await request.json()
            user = body.get("user", "").strip()
        except Exception:
            user = ""
        if not user:
            return JSONResponse({"error": "Bad Request", "message": "'user' field is required"}, status_code=400)
        result = keystore.generate_key(user)
        return JSONResponse(result, status_code=201)

    async def admin_list_keys(request):
        if not _is_localhost(request):
            return JSONResponse({"error": "Forbidden", "message": "Admin endpoints are localhost only"}, status_code=403)
        return JSONResponse(keystore.list_keys())

    async def admin_revoke_key(request):
        if not _is_localhost(request):
            return JSONResponse({"error": "Forbidden", "message": "Admin endpoints are localhost only"}, status_code=403)
        key_prefix = request.path_params["key_prefix"]
        result = keystore.revoke_key(key_prefix)
        if result is None:
            return JSONResponse({"error": "Not Found", "message": f"No key with prefix '{key_prefix}'"}, status_code=404)
        return JSONResponse(result)

    middleware = [Middleware(APIKeyMiddleware)]
    logger.info("API key authentication enforced for all SSE connections")
    logger.info(f"Key store: {keystore.KEY_STORE_PATH}")
    logger.info(f"Active keys: {len(keystore.list_keys())}")

    return Starlette(
        debug=False,
        routes=[
            Route("/health", health),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
            Route("/admin/keys", admin_create_key, methods=["POST"]),
            Route("/admin/keys", admin_list_keys, methods=["GET"]),
            Route("/admin/keys/{key_prefix}", admin_revoke_key, methods=["DELETE"]),
        ],
        middleware=middleware,
    )


# ==================== Main ====================

def main():
    """Entry point for the MCP server. Supports stdio and SSE transports."""
    # Fail fast if required env vars are missing
    config.validate_required_config()

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
