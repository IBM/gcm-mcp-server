#!/usr/bin/env python3
"""GCM MCP Server — All @mcp.tool() definitions.

Contains tool definitions, prompts, resources, server state,
and all handler functions for the MCP server.
"""

import asyncio
import io
import json
import re
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from mcp.types import (
    Tool, TextContent, Prompt, PromptMessage, PromptArgument,
    Resource, TextResourceContents, GetPromptResult,
)

from src import config
from src.client import GCMClient
from src.discovery import (
    GCM_API_SCHEMA,
    get_services,
    get_service_detail,
    get_full_schema,
    search_endpoints,
    get_service_catalog,
    get_total_endpoint_count,
    get_service_names,
)

logger = config.get_logger("gcm-mcp")


# ==================== Server State ====================

class ServerState:
    """Manages server state including client and cache."""

    def __init__(self):
        self.client: Optional[GCMClient] = None
        self.auth_time: Optional[datetime] = None
        self.session_timeout = timedelta(hours=1)

    def get_client(self) -> GCMClient:
        """Get or create GCM client."""
        if self.client is None:
            self.client = GCMClient()
        return self.client

    def is_session_valid(self) -> bool:
        """Check if current session is still valid."""
        if not self.client or not self.client.authenticated:
            return False
        # Client handles token refresh internally
        return self.client._ensure_token()

    def auto_auth(self) -> Tuple[bool, str]:
        """Attempt auto-authentication using environment variables."""
        username = config.GCM_USERNAME
        password = config.GCM_PASSWORD

        if not username or not password:
            return False, "Credentials not found. Set GCM_USERNAME and GCM_PASSWORD environment variables."

        client = self.get_client()
        if client.login(username, password):
            self.auth_time = datetime.now()
            return True, f"Authenticated as {client.user_id}"
        return False, "Authentication failed"


state = ServerState()


# ==================== Tool Definitions ====================

async def list_tools() -> List[Tool]:
    """
    List available GCM tools.

    Design: Only 3 tools to minimize token consumption while preserving full functionality.
    """
    return [
        Tool(
            name="gcm_auth",
            description="""Authenticate to IBM Guardium Cryptographic Manager (GCM).

Required for all API operations. Session persists across calls.
If GCM_USERNAME and GCM_PASSWORD env vars are set, authentication is automatic.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "GCM username (optional if env vars set)"
                    },
                    "password": {
                        "type": "string",
                        "description": "GCM password (optional if env vars set)"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["login", "logout", "status"],
                        "description": "Auth action (default: login)",
                        "default": "login"
                    }
                }
            }
        ),

        Tool(
            name="gcm_api",
            description="""Execute any GCM API operation.

Use gcm_discover first to see available services and endpoints.

Examples:
- Get version: service="usermanagement", operation="system.version"
- List users: service="usermanagement", operation="users.list", params={"pageSize": 10}
- TDE client inventory: service="tde", operation="clients.inventory"
- List certificates: service="assetinventory", operation="assets.list_certificates", body={"columns":["all"],"page_number":1,"page_size":10}
- Violations dashboard: service="policyrisk", operation="violations.dashboard"
- List policies: service="policy", operation="policies.list"
- System config: service="config", operation="config.get_all"
- Create policy: service="policy", operation="policies.create", body={...}

For raw API calls, use: method="GET", endpoint="/ibm/usermanagement/api/v1/users\"""",
            inputSchema={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Service name: usermanagement, tde, assetinventory, discovery, policy, policyrisk, audit, integration, notifications, clm, config"
                    },
                    "operation": {
                        "type": "string",
                        "description": "Operation in format 'resource.action' (e.g., users.list, clients.get)"
                    },
                    "params": {
                        "type": "object",
                        "description": "Query parameters (for GET requests)"
                    },
                    "path_params": {
                        "type": "object",
                        "description": "Path parameters to substitute (e.g., {userId}, {clientId})"
                    },
                    "body": {
                        "type": "object",
                        "description": "Request body (for POST/PUT requests)"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE"],
                        "description": "HTTP method (for raw endpoint calls)"
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "Raw API endpoint path (alternative to service/operation)"
                    }
                }
            }
        ),

        Tool(
            name="gcm_discover",
            description="""Discover GCM API capabilities and schemas.

Returns available services, endpoints, and parameters.
Call once at start of conversation - results can be cached.

Categories:
- services: List all available services
- endpoints: List endpoints for a specific service
- schema: Get full API schema
- search: Search for endpoints by keyword""",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["services", "endpoints", "schema", "search"],
                        "description": "What to discover",
                        "default": "services"
                    },
                    "service": {
                        "type": "string",
                        "description": "Service name (for endpoints category)"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query (for search category)"
                    }
                }
            }
        ),
    ]


# ==================== Tool Router ====================

async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Route tool calls to handlers."""
    try:
        if name == "gcm_auth":
            return await handle_auth(arguments)
        elif name == "gcm_api":
            return await handle_api(arguments)
        elif name == "gcm_discover":
            return await handle_discover(arguments)
        else:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]
    except Exception as e:
        logger.exception(f"Error in {name}")
        return [TextContent(type="text", text=json.dumps({
            "error": str(e),
            "tool": name,
            "hint": "Check gcm_discover for available operations"
        }, indent=2))]


# ==================== Tool Handlers ====================

async def handle_auth(args: Dict[str, Any]) -> List[TextContent]:
    """Handle authentication operations."""
    action = args.get("action", "login")

    if action == "status":
        client = state.get_client()
        return [TextContent(type="text", text=json.dumps({
            "authenticated": client.authenticated,
            "user_id": client.user_id,
            "session_valid": state.is_session_valid(),
            "base_url": client.base_url
        }, indent=2))]

    if action == "logout":
        if state.client:
            state.client.authenticated = False
            state.client.session.cookies.clear()
            state.auth_time = None
        return [TextContent(type="text", text=json.dumps({"status": "logged_out"}))]

    # Login
    username = args.get("username") or config.GCM_USERNAME
    password = args.get("password") or config.GCM_PASSWORD

    if not username or not password:
        return [TextContent(type="text", text=json.dumps({
            "error": "Credentials required",
            "hint": "Provide username/password or set GCM_USERNAME/GCM_PASSWORD env vars"
        }, indent=2))]

    client = state.get_client()

    # Capture login output
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()

    # Run blocking login in thread pool to avoid blocking the event loop
    success = await asyncio.to_thread(client.login, username, password)

    login_output = sys.stdout.getvalue()
    sys.stdout = old_stdout

    if success:
        state.auth_time = datetime.now()
        return [TextContent(type="text", text=json.dumps({
            "status": "authenticated",
            "user_id": client.user_id,
            "message": "Login successful. You can now use gcm_api to call any endpoint."
        }, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({
            "status": "failed",
            "error": "Authentication failed",
            "details": login_output
        }, indent=2))]


async def handle_api(args: Dict[str, Any]) -> List[TextContent]:
    """Handle API operations."""
    # Ensure authenticated
    if not state.is_session_valid():
        success, msg = await asyncio.to_thread(state.auto_auth)
        if not success:
            return [TextContent(type="text", text=json.dumps({
                "error": "Not authenticated",
                "message": msg,
                "action": "Call gcm_auth first"
            }, indent=2))]

    client = state.get_client()

    # Check for raw endpoint call
    if "endpoint" in args:
        return await execute_raw_api(client, args)

    # Service/operation based call
    service_name = args.get("service")
    operation = args.get("operation")

    if not service_name or not operation:
        return [TextContent(type="text", text=json.dumps({
            "error": "Missing required parameters",
            "required": "Either (service + operation) or (method + endpoint)",
            "hint": "Use gcm_discover to see available services and operations"
        }, indent=2))]

    # Parse operation (e.g., "users.list" -> resource="users", action="list")
    parts = operation.split(".")
    if len(parts) != 2:
        return [TextContent(type="text", text=json.dumps({
            "error": f"Invalid operation format: {operation}",
            "expected": "resource.action (e.g., users.list, clients.get)"
        }, indent=2))]

    resource, action = parts

    # Look up in schema
    service = GCM_API_SCHEMA["services"].get(service_name)
    if not service:
        return [TextContent(type="text", text=json.dumps({
            "error": f"Unknown service: {service_name}",
            "available": get_service_names()
        }, indent=2))]

    endpoints = service.get("endpoints", {}).get(resource, {})
    endpoint_def = endpoints.get(action)

    if not endpoint_def:
        return [TextContent(type="text", text=json.dumps({
            "error": f"Unknown operation: {operation}",
            "available_in_service": list(service.get("endpoints", {}).keys()),
            "hint": f"Use gcm_discover with service='{service_name}' to see all endpoints"
        }, indent=2))]

    # Build request
    method = endpoint_def["method"]
    path = service["base"] + endpoint_def["path"]

    # Substitute path parameters
    path_params = args.get("path_params", {})
    for key, value in path_params.items():
        path = path.replace(f"{{{key}}}", str(value))

    # Check for unsubstituted path params
    if "{" in path:
        missing = re.findall(r'\{(\w+)\}', path)
        return [TextContent(type="text", text=json.dumps({
            "error": "Missing path parameters",
            "missing": missing,
            "hint": f"Provide path_params: {{{missing[0]}: 'value'}}"
        }, indent=2))]

    # Execute request
    params = args.get("params", {})
    body = args.get("body")

    return await execute_request(client, method, path, params, body)


async def execute_raw_api(client: GCMClient, args: Dict[str, Any]) -> List[TextContent]:
    """Execute raw API endpoint call."""
    method = args.get("method", "GET").upper()
    endpoint = args["endpoint"]
    params = args.get("params", {})
    body = args.get("body")

    return await execute_request(client, method, endpoint, params, body)


def _sync_request(
    client: GCMClient,
    method: str,
    endpoint: str,
    params: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> Dict:
    """Synchronous HTTP request — runs in thread pool to avoid blocking event loop."""
    if method == "GET":
        response = client.get(endpoint, params=params)
    elif method == "POST":
        response = client.post(endpoint, data=body)
    elif method == "PUT":
        response = client.put(endpoint, data=body)
    elif method == "DELETE":
        response = client.delete(endpoint)
    else:
        return {"error": f"Unsupported method: {method}"}

    # Parse response
    try:
        data = response.json()
    except Exception:
        data = response.text[:2000] if response.text else None

    result = {
        "status": response.status_code,
        "success": 200 <= response.status_code < 300,
        "data": data
    }

    if not result["success"]:
        result["error"] = f"HTTP {response.status_code}"

    return result


async def execute_request(
    client: GCMClient,
    method: str,
    endpoint: str,
    params: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[TextContent]:
    """Execute HTTP request in a thread pool with timeout, never blocking the event loop."""
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_sync_request, client, method, endpoint, params, body),
            timeout=config.GCM_REQUEST_TIMEOUT
        )

        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    except asyncio.TimeoutError:
        return [TextContent(type="text", text=json.dumps({
            "error": f"Request timed out after {config.GCM_REQUEST_TIMEOUT}s",
            "endpoint": endpoint,
            "method": method,
            "hint": "The GCM endpoint did not respond in time. Try again or check GCM service health."
        }, indent=2))]

    except Exception as e:
        return [TextContent(type="text", text=json.dumps({
            "error": str(e),
            "endpoint": endpoint,
            "method": method
        }, indent=2))]


async def handle_discover(args: Dict[str, Any]) -> List[TextContent]:
    """Handle discovery requests."""
    category = args.get("category", "services")

    if category == "services":
        services = get_services()
        return [TextContent(type="text", text=json.dumps({
            "services": services,
            "usage": "Use gcm_api with service='<name>' and operation='<resource>.<action>'"
        }, indent=2))]

    elif category == "endpoints":
        service_name = args.get("service")
        if not service_name:
            return [TextContent(type="text", text=json.dumps({
                "error": "service parameter required",
                "available": get_service_names()
            }, indent=2))]

        detail = get_service_detail(service_name)
        if not detail:
            return [TextContent(type="text", text=json.dumps({
                "error": f"Unknown service: {service_name}",
                "available": get_service_names()
            }, indent=2))]

        return [TextContent(type="text", text=json.dumps(detail, indent=2))]

    elif category == "schema":
        return [TextContent(type="text", text=json.dumps(get_full_schema(), indent=2))]

    elif category == "search":
        query = args.get("query", "").lower()
        if not query:
            return [TextContent(type="text", text=json.dumps({
                "error": "query parameter required",
                "example": "gcm_discover category='search' query='user'"
            }, indent=2))]

        results = search_endpoints(query)
        return [TextContent(type="text", text=json.dumps({
            "query": query,
            "results": results,
            "count": len(results)
        }, indent=2))]

    return [TextContent(type="text", text=json.dumps({"error": f"Unknown category: {category}"}))]


# ==================== MCP Prompts ====================

async def list_prompts() -> List[Prompt]:
    """Pre-defined prompt templates for common GCM operations."""
    return [
        Prompt(
            name="gcm-security-audit",
            description="Run a comprehensive security audit across all GCM services",
            arguments=[
                PromptArgument(
                    name="focus_area",
                    description="Area to focus on: all, encryption, policies, users, certificates",
                    required=False
                )
            ]
        ),
        Prompt(
            name="gcm-crypto-inventory",
            description="Get a summary of all cryptographic assets, keys, and certificates",
            arguments=[]
        ),
        Prompt(
            name="gcm-policy-compliance",
            description="Check policy compliance status and list any violations",
            arguments=[
                PromptArgument(
                    name="severity",
                    description="Filter by severity: all, high, medium, low",
                    required=False
                )
            ]
        ),
        Prompt(
            name="gcm-tde-status",
            description="Check TDE encryption status for all database clients",
            arguments=[]
        ),
        Prompt(
            name="gcm-discovery-scan",
            description="Run or check status of cryptographic asset discovery scans",
            arguments=[
                PromptArgument(
                    name="action",
                    description="What to do: status, list-profiles, run",
                    required=False
                )
            ]
        ),
    ]


async def get_prompt(name: str, arguments: Optional[Dict[str, str]] = None) -> GetPromptResult:
    """Return prompt messages for a given prompt template."""
    if name == "gcm-security-audit":
        focus = (arguments or {}).get("focus_area", "all")
        return GetPromptResult(
            description="Comprehensive GCM security audit",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=f"""Run a comprehensive security audit on the GCM system. Focus area: {focus}.

Please:
1. First authenticate using gcm_auth
2. Check system version and license status
3. List all users and their roles
4. Review TDE encryption key status
5. Check policy compliance and violations
6. List recent audit events
7. Summarize findings with recommendations"""
                    )
                )
            ]
        )
    elif name == "gcm-crypto-inventory":
        return GetPromptResult(
            description="Cryptographic asset inventory summary",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text="""Get a complete inventory of all cryptographic assets in GCM.

Please:
1. Authenticate with gcm_auth
2. List all IT assets with cryptographic objects
3. List all certificates and their expiration dates
4. List all encryption keys and their algorithms
5. Show vulnerable crypto objects count
6. Summarize the crypto posture"""
                    )
                )
            ]
        )
    elif name == "gcm-policy-compliance":
        severity = (arguments or {}).get("severity", "all")
        return GetPromptResult(
            description="Policy compliance check",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=f"""Check GCM policy compliance status. Severity filter: {severity}.

Please:
1. Authenticate with gcm_auth
2. List all policies and their status
3. Check the violations dashboard
4. List policy violation tickets
5. Summarize compliance posture and highlight critical issues"""
                    )
                )
            ]
        )
    elif name == "gcm-tde-status":
        return GetPromptResult(
            description="TDE encryption status",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text="""Check the status of Transparent Data Encryption (TDE) across all database clients.

Please:
1. Authenticate with gcm_auth
2. List all TDE client inventory
3. Check encryption key status
4. Review TDE policy settings
5. List supported database types
6. Summarize TDE coverage and any gaps"""
                    )
                )
            ]
        )
    elif name == "gcm-discovery-scan":
        action = (arguments or {}).get("action", "status")
        return GetPromptResult(
            description="Discovery scan management",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=f"""Manage cryptographic asset discovery scans. Action: {action}.

Please:
1. Authenticate with gcm_auth
2. List all discovery profiles
3. Show import profile configurations
4. Check transformation rules
5. Report on discovery coverage"""
                    )
                )
            ]
        )
    raise ValueError(f"Unknown prompt: {name}")


# ==================== MCP Resources ====================

async def list_resources() -> List[Resource]:
    """Expose GCM service catalog and API schema as MCP resources."""
    return [
        Resource(
            uri="gcm://services",
            name="GCM Service Catalog",
            description="List of all available GCM services with descriptions",
            mimeType="application/json"
        ),
        Resource(
            uri="gcm://schema",
            name="GCM API Schema",
            description="Complete API schema with all endpoints, methods, and parameters",
            mimeType="application/json"
        ),
        Resource(
            uri="gcm://config",
            name="GCM Server Configuration",
            description="Current MCP server configuration (non-sensitive)",
            mimeType="application/json"
        ),
    ]


async def read_resource(uri: str) -> str:
    """Read a GCM resource by URI."""
    uri_str = str(uri)
    if uri_str == "gcm://services":
        return json.dumps(get_service_catalog(), indent=2)
    elif uri_str == "gcm://schema":
        return json.dumps(get_full_schema(), indent=2)
    elif uri_str == "gcm://config":
        server_config = {
            "server": "GCM MCP Server",
            "version": "1.0.0",
            "gcm_host": config.GCM_HOST,
            "api_port": str(config.GCM_API_PORT),
            "keycloak_port": str(config.GCM_KEYCLOAK_PORT),
            "auth_mode": config.GCM_AUTH_MODE,
            "verify_ssl": str(config.GCM_VERIFY_SSL).lower(),
            "services_available": get_service_names(),
            "total_endpoints": get_total_endpoint_count()
        }
        return json.dumps(server_config, indent=2)
    raise ValueError(f"Unknown resource: {uri_str}")
