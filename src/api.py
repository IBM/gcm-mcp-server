#!/usr/bin/env python3
"""
GCM MCP Server - REST API

HTTP wrapper around the MCP tools, exposing the same functionality
via REST endpoints. This allows testing and integration without
requiring an MCP-aware client like Claude Desktop.

Usage:
    python -m src.api                    # Start on port 8000
    GCM_API_PORT_HTTP=9000 python -m src.api  # Custom port

Endpoints:
    POST /tools/{tool_name}  - Call any MCP tool (gcm_auth, gcm_api, gcm_discover)
    GET  /tools              - List available tools
    GET  /health             - Health check
    GET  /docs               - Swagger UI (auto-generated)

Examples:
    # Authenticate
    curl -X POST http://localhost:8000/tools/gcm_auth \
         -H "Content-Type: application/json" \
         -d '{"action": "login"}'

    # List services
    curl -X POST http://localhost:8000/tools/gcm_discover \
         -H "Content-Type: application/json" \
         -d '{"category": "services"}'

    # Get system version
    curl -X POST http://localhost:8000/tools/gcm_api \
         -H "Content-Type: application/json" \
         -d '{"service": "usermanagement", "operation": "system.version"}'

    # List users
    curl -X POST http://localhost:8000/tools/gcm_api \
         -H "Content-Type: application/json" \
         -d '{"service": "usermanagement", "operation": "users.list", "params": {"pageSize": 5}}'
"""

import json
import os
import sys
import asyncio
import logging
from typing import Any, Dict, Optional
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse as FastAPIJSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Import MCP server internals
from src.tools import call_tool, list_tools, state
from src.discovery import GCM_API_SCHEMA
from src import config as mcp_config
from src import keystore

# ==================== Configuration ====================

logger = logging.getLogger("gcm-api")

HTTP_PORT = int(os.environ.get("GCM_API_PORT_HTTP", 8000))
HTTP_HOST = os.environ.get("GCM_API_HOST_HTTP", "0.0.0.0")

# ==================== FastAPI App ====================

app = FastAPI(
    title="GCM MCP Server API",
    description=(
        "REST API for IBM Guardium Cryptography Manager (GCM).\n\n"
        "This is an HTTP wrapper around the MCP server tools. "
        "The same tools available to AI assistants via MCP protocol "
        "are exposed here as REST endpoints.\n\n"
        "**Tools:**\n"
        "- `gcm_auth` — Authentication & session management\n"
        "- `gcm_api` — Execute any GCM API operation\n"
        "- `gcm_discover` — Discover available services & endpoints\n"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== API Key Middleware ====================

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Validate API key from key store for REST API.

    Every request must include: Authorization: Bearer <key>
    Only /health, /docs, /redoc, /openapi.json are exempt.
    """
    # Allow health, docs, and openapi schema without auth
    open_paths = {"/health", "/docs", "/redoc", "/openapi.json"}
    if request.url.path in open_paths:
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()

    key_info = keystore.validate_key(token)
    if key_info is None:
        return FastAPIJSONResponse(
            {"error": "Unauthorized", "message": "Invalid or missing API key"},
            status_code=401,
        )

    return await call_next(request)

# ==================== Request/Response Models ====================


class ToolRequest(BaseModel):
    """Request body for tool calls. Fields depend on the tool being called."""

    # gcm_auth fields
    action: Optional[str] = Field(None, description="Auth action: login, logout, status")
    username: Optional[str] = Field(None, description="GCM username (optional if env vars set)")
    password: Optional[str] = Field(None, description="GCM password (optional if env vars set)")

    # gcm_api fields
    service: Optional[str] = Field(None, description="Service name (e.g., usermanagement, tde)")
    operation: Optional[str] = Field(None, description="Operation (e.g., users.list, system.version)")
    params: Optional[Dict[str, Any]] = Field(None, description="Query parameters")
    path_params: Optional[Dict[str, Any]] = Field(None, description="Path parameters")
    body: Optional[Dict[str, Any]] = Field(None, description="Request body for POST/PUT")
    method: Optional[str] = Field(None, description="HTTP method for raw calls")
    endpoint: Optional[str] = Field(None, description="Raw endpoint path")

    # gcm_discover fields
    category: Optional[str] = Field(None, description="Discovery category: services, endpoints, schema, search")
    query: Optional[str] = Field(None, description="Search query")

    model_config = {"extra": "allow"}


class ToolResponse(BaseModel):
    """Response from a tool call."""
    tool: str
    success: bool
    data: Any
    timestamp: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    server: str
    gcm_host: str
    authenticated: bool
    user_id: Optional[str]
    timestamp: str


class ToolInfo(BaseModel):
    """Tool information."""
    name: str
    description: str
    parameters: Dict[str, Any]


# ==================== Endpoints ====================


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Check server health and authentication status."""
    client = state.get_client()
    return HealthResponse(
        status="ok",
        server="GCM MCP Server API",
        gcm_host=f"https://{client.host}:{client.api_port}",
        authenticated=client.authenticated,
        user_id=client.user_id,
        timestamp=datetime.now().isoformat(),
    )


@app.get("/tools", tags=["Tools"])
async def get_tools():
    """List all available MCP tools with their schemas."""
    tools = await list_tools()
    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description.strip(),
                "parameters": t.inputSchema,
            }
            for t in tools
        ],
        "count": len(tools),
    }


@app.post("/tools/{tool_name}", response_model=ToolResponse, tags=["Tools"])
async def execute_tool(tool_name: str, request: ToolRequest = ToolRequest()):
    """
    Execute an MCP tool by name.

    **Available tools:**
    - `gcm_auth` — Login, logout, or check session status
    - `gcm_api` — Call any GCM API endpoint
    - `gcm_discover` — Discover available services and endpoints

    **Examples:**

    Login:
    ```json
    POST /tools/gcm_auth
    {"action": "login"}
    ```

    List users:
    ```json
    POST /tools/gcm_api
    {"service": "usermanagement", "operation": "users.list", "params": {"pageSize": 5}}
    ```

    Discover services:
    ```json
    POST /tools/gcm_discover
    {"category": "services"}
    ```
    """
    # Validate tool name
    valid_tools = ["gcm_auth", "gcm_api", "gcm_discover"]
    if tool_name not in valid_tools:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Unknown tool: {tool_name}",
                "available_tools": valid_tools,
            },
        )

    # Build arguments dict — exclude None values
    arguments = {k: v for k, v in request.model_dump().items() if v is not None}

    try:
        result = await call_tool(tool_name, arguments)
        # Parse the TextContent response
        text = result[0].text
        data = json.loads(text)

        return ToolResponse(
            tool=tool_name,
            success=data.get("success", True) if isinstance(data, dict) else True,
            data=data,
            timestamp=datetime.now().isoformat(),
        )
    except Exception as e:
        logger.exception(f"Error executing tool {tool_name}")
        raise HTTPException(
            status_code=500,
            detail={"error": str(e), "tool": tool_name},
        )


# ── Convenience endpoints (shortcuts for common operations) ──


@app.post("/auth", tags=["Shortcuts"])
async def auth_shortcut(action: str = "login"):
    """Shortcut for gcm_auth. Defaults to login using env vars."""
    return await execute_tool("gcm_auth", ToolRequest(action=action))


@app.get("/services", tags=["Shortcuts"])
async def list_services():
    """Shortcut for gcm_discover → list services."""
    return await execute_tool("gcm_discover", ToolRequest(category="services"))


@app.get("/services/{service_name}/endpoints", tags=["Shortcuts"])
async def list_endpoints(service_name: str):
    """Shortcut for gcm_discover → list endpoints for a service."""
    return await execute_tool(
        "gcm_discover", ToolRequest(category="endpoints", service=service_name)
    )


@app.get("/schema", tags=["Shortcuts"])
async def get_schema():
    """Get the full GCM API schema directly."""
    return GCM_API_SCHEMA


# ==================== Main ====================


def main():
    """Start the HTTP API server."""
    print(f"{'='*60}")
    print(f"  GCM MCP Server — REST API")
    print(f"{'='*60}")
    print(f"  Target GCM: https://{os.getenv('GCM_HOST', 'localhost')}:{os.getenv('GCM_API_PORT', '31443')}")
    print(f"  API Server: http://{HTTP_HOST}:{HTTP_PORT}")
    print(f"  Swagger UI: http://localhost:{HTTP_PORT}/docs")
    print(f"{'='*60}\n")

    uvicorn.run(
        "src.api:app",
        host=HTTP_HOST,
        port=HTTP_PORT,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
