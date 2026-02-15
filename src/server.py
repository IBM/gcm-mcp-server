#!/usr/bin/env python3
"""
GCM MCP Server - Enterprise Edition

Token-Optimized Model Context Protocol Server for IBM Guardium Cryptographic Manager.

Design Philosophy:
- Minimal tool definitions = Lower token consumption per request
- Generic tools with smart routing = Full functionality preserved
- Cached discovery = Reduced repeated schema transfers
- Production-grade error handling and logging

Tools:
1. gcm_auth     - Authentication & session management
2. gcm_api      - Generic API execution (GET/POST/PUT/DELETE)
3. gcm_discover - Endpoint discovery & schema information
"""

import argparse
import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent, Prompt, PromptMessage, PromptArgument, Resource, TextResourceContents, GetPromptResult
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse

from src.client import GCMClient

# ==================== Configuration ====================

LOG_LEVEL = os.environ.get('GCM_LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("gcm-mcp")

# ==================== API Schema (Cached) ====================

# Pre-defined API schema to avoid repeated discovery calls
# This is transferred once when gcm_discover is called, then cached by the LLM
GCM_API_SCHEMA = {
    "services": {
        "usermanagement": {
            "base": "/ibm/usermanagement/api",
            "description": "User, role, license, and authorization management",
            "endpoints": {
                "users": {
                    "list": {"method": "GET", "path": "/v1/users", "params": ["pageNumber", "pageSize", "search"]},
                    "get": {"method": "GET", "path": "/v1/users/{userId}"},
                    "create": {"method": "POST", "path": "/v1/users", "body": ["email", "displayName", "distinguishedName", "assignRolesList"]},
                    "activate": {"method": "PUT", "path": "/v1/users/{userId}/activate"},
                    "deactivate": {"method": "PUT", "path": "/v1/users/deactivate", "body": ["userIds"]},
                    "update_roles": {"method": "PUT", "path": "/v1/users/{userId}/roles", "body": ["assignRolesList", "revokeRolesList"]},
                },
                "roles": {
                    "list": {"method": "GET", "path": "/v1/roles", "params": ["pageNumber", "pageSize"]},
                    "get": {"method": "GET", "path": "/v1/roles/{role_id}"},
                    "create": {"method": "POST", "path": "/v1/roles", "body": ["name", "description", "permissions"]},
                    "update": {"method": "PUT", "path": "/v1/roles/{role_id}", "body": ["name", "description", "assignedPermissions", "revokedPermissions"]},
                    "delete": {"method": "DELETE", "path": "/v1/roles/{role_id}"},
                },
                "system": {
                    "version": {"method": "GET", "path": "/v1/system/version-info"},
                },
                "license": {
                    "status": {"method": "GET", "path": "/v1/licenses/status"},
                    "apply": {"method": "POST", "path": "/v1/license", "body": ["licenseFor", "licenseFile"]},
                },
                "auth_policy": {
                    "list": {"method": "GET", "path": "/v1/auth-policy"},
                    "permissions": {"method": "GET", "path": "/v1/auth-policy/permissions", "params": ["feature"]},
                    "dashboards": {"method": "GET", "path": "/v1/auth-policy/dashboards", "params": ["feature"]},
                },
            }
        },
        "tde": {
            "base": "/ibm/encryption/db/tde/api",
            "description": "Transparent Data Encryption management for databases",
            "endpoints": {
                "clients": {
                    "inventory": {"method": "GET", "path": "/v1/client-inventory", "params": ["page", "size", "sort", "clientName", "dbType"]},
                    "list": {"method": "POST", "path": "/v1/clients/list", "body": ["page", "size", "sort", "filters"]},
                    "get": {"method": "GET", "path": "/v1/clients/{clientId}"},
                    "create": {"method": "POST", "path": "/v1/clients", "body": ["clientName", "dbType", "description"]},
                    "update": {"method": "PUT", "path": "/v1/clients/{clientId}"},
                    "delete": {"method": "DELETE", "path": "/v1/clients/{clientId}"},
                },
                "keys": {
                    "get": {"method": "GET", "path": "/v1/symmetric-key/{uuid}"},
                },
                "certificates": {
                    "get": {"method": "GET", "path": "/v1/certificates/{hash}"},
                },
                "policy": {
                    "list": {"method": "GET", "path": "/v1/policy"},
                    "update": {"method": "PUT", "path": "/v1/policy"},
                },
                "databases": {
                    "supported_types": {"method": "GET", "path": "/v1/databases/supported/types"},
                },
            }
        },
        "assetinventory": {
            "base": "/ibm/assetinventory/api",
            "description": "Cryptographic asset inventory — IT assets, crypto objects, groups",
            "endpoints": {
                "assets": {
                    "list_it_assets": {"method": "POST", "path": "/v1/assets/it_assets/it_assets", "body": ["columns", "filter", "page_number", "page_size", "search_by", "sort_by"]},
                    "list_certificates": {"method": "POST", "path": "/v1/assets/crypto_objects/certificates", "body": ["columns", "filter", "page_number", "page_size", "search_by", "sort_by"]},
                    "list_keys": {"method": "POST", "path": "/v1/assets/crypto_objects/keys", "body": ["columns", "filter", "page_number", "page_size", "search_by", "sort_by"]},
                    "list_protocols": {"method": "POST", "path": "/v1/assets/crypto_objects/protocols", "body": ["columns", "filter", "page_number", "page_size", "search_by", "sort_by"]},
                    "details_crypto": {"method": "GET", "path": "/v1/assets/details/crypto_objects/{asset_type}", "params": ["crypto_id", "widget", "page_number", "page_size"]},
                    "details_it": {"method": "GET", "path": "/v1/assets/details/{asset_category}", "params": ["asset_id", "widget", "page_number", "page_size"]},
                },
                "filters": {
                    "list": {"method": "GET", "path": "/v1/assets/filters/{asset_category}"},
                    "suggestions": {"method": "GET", "path": "/v1/assets/filters/suggestions/{asset_category}/{filter_category}"},
                },
                "groups": {
                    "list": {"method": "GET", "path": "/v1/assets/groups", "params": ["page_number", "page_size", "sort"]},
                    "create": {"method": "POST", "path": "/v1/assets/groups"},
                    "update": {"method": "PUT", "path": "/v1/assets/groups"},
                    "delete": {"method": "DELETE", "path": "/v1/assets/groups/{group_id}"},
                },
                "metadata": {
                    "list": {"method": "GET", "path": "/v1/assets/metadata/{asset_category}"},
                },
                "dashboards": {
                    "crypto_posture": {"method": "POST", "path": "/v1/assets/dashboards/crypto-posture", "body": ["page_number", "page_size"]},
                    "vulnerable_count": {"method": "GET", "path": "/v1/assets/count/vulnerable_crypto_objects"},
                },
                "presets": {
                    "list": {"method": "GET", "path": "/v1/assets/presets/{asset_category}"},
                },
            }
        },
        "discovery": {
            "base": "/ibm/assetdiscovery/api",
            "description": "Asset discovery profiles, import profiles, and transformations",
            "endpoints": {
                "profiles": {
                    "list": {"method": "GET", "path": "/v1/discovery/profiles", "params": ["page", "size"]},
                    "get": {"method": "GET", "path": "/v1/discovery/profiles/{profileId}"},
                    "create": {"method": "POST", "path": "/v1/discovery/profiles"},
                    "run": {"method": "POST", "path": "/v1/discovery/profiles/{profileId}/run"},
                },
                "import_profiles": {
                    "list": {"method": "GET", "path": "/v1/discovery/import-profiles", "params": ["page", "size"]},
                    "get": {"method": "GET", "path": "/v1/discovery/import-profiles/{importProfileId}"},
                    "create": {"method": "POST", "path": "/v1/discovery/import-profiles"},
                },
                "transformations": {
                    "list": {"method": "GET", "path": "/v1/discovery/transformations", "params": ["page", "size"]},
                    "get": {"method": "GET", "path": "/v1/discovery/transformations/{transformationId}"},
                    "create": {"method": "POST", "path": "/v1/discovery/transformations"},
                    "validate": {"method": "POST", "path": "/v1/discovery/transformations/validate"},
                },
            }
        },
        "policy": {
            "base": "/ibm/gemimcpolicy/api",
            "description": "Cryptographic policy builder and management",
            "endpoints": {
                "policies": {
                    "list": {"method": "GET", "path": "/v1/policies", "params": ["page", "size", "sortBy", "sortDirection"]},
                    "get": {"method": "GET", "path": "/v1/policies/{policyId}"},
                    "create": {"method": "POST", "path": "/v1/policies"},
                    "update": {"method": "PUT", "path": "/v1/policies"},
                    "delete": {"method": "POST", "path": "/v1/policies/delete"},
                },
                "metadata": {
                    "asset_types": {"method": "GET", "path": "/v1/policies/metadata/asset-types"},
                    "compliance_controls": {"method": "GET", "path": "/v1/policies/compliance-controls"},
                },
            }
        },
        "policyrisk": {
            "base": "/ibm/gempolicyengine/api",
            "description": "Risk evaluation, violations, and policy dashboards",
            "endpoints": {
                "violations": {
                    "dashboard": {"method": "GET", "path": "/v1/violations/dashboards/policy-violations"},
                    "list": {"method": "POST", "path": "/v1/violations/policy-violation-tickets", "params": ["page", "size", "sortBy", "sortDirection"]},
                    "get": {"method": "GET", "path": "/v1/violations/{entityId}", "params": ["entityType", "policyName", "policySubType", "sortBy"]},
                    "update_ticket": {"method": "PUT", "path": "/v1/violations", "params": ["action"]},
                    "create_ticket": {"method": "POST", "path": "/v1/violations/ticket"},
                },
            }
        },
        "audit": {
            "base": "/ibm/auditmgmt/api",
            "description": "Audit logs and CSV export",
            "endpoints": {
                "logs": {
                    "list": {"method": "GET", "path": "/v1/audits", "params": ["page", "size", "startDate", "endDate", "action"]},
                    "get": {"method": "GET", "path": "/v1/audits/{auditId}"},
                    "download_csv": {"method": "GET", "path": "/v1/download-csv", "params": ["startDate", "endDate"]},
                },
            }
        },
        "integration": {
            "base": "/ibm/integrationmanager/api",
            "description": "External system integrations and ticket management",
            "endpoints": {
                "integrations": {
                    "list": {"method": "GET", "path": "/v1/integrations"},
                    "get": {"method": "GET", "path": "/v1/integrations/{integrationId}"},
                    "create": {"method": "POST", "path": "/v1/integrations"},
                    "update": {"method": "PUT", "path": "/v1/integrations/{integrationId}"},
                    "delete": {"method": "DELETE", "path": "/v1/integrations/{integrationId}"},
                },
                "tickets": {
                    "list": {"method": "GET", "path": "/v1/ticket-master"},
                    "create": {"method": "POST", "path": "/v1/ticket-master"},
                    "update": {"method": "PUT", "path": "/v1/ticket-master/{integrationId}"},
                },
            }
        },
        "notifications": {
            "base": "/ibm/notificationmgmt/api",
            "description": "Alerts and notification management",
            "endpoints": {
                "notifications": {
                    "list": {"method": "GET", "path": "/v1/notifications", "params": ["pageNumber", "pageSize", "sort"]},
                    "get": {"method": "GET", "path": "/v1/notifications/{notificationId}"},
                },
            }
        },
        "clm": {
            "base": "/ibm/clm/api",
            "description": "Certificate Lifecycle Management — issuance, renewal, revocation",
            "endpoints": {
                "certificates": {
                    "list": {"method": "GET", "path": "/v1/certificate/all"},
                    "issue_selfsigned": {"method": "POST", "path": "/v1/certificate/{provider}/selfSigned"},
                    "revoke": {"method": "POST", "path": "/v1/certificate/{provider}/revoke/{id}"},
                    "delete": {"method": "POST", "path": "/v1/certificate/delete"},
                    "download": {"method": "POST", "path": "/v1/certificate/download/certificate"},
                },
                "vault": {
                    "details": {"method": "GET", "path": "/v1/certificate/vault-details"},
                },
            }
        },
        "config": {
            "base": "/ibm/config/api",
            "description": "System configuration settings (Kafka, KMIP, notifications, etc.)",
            "endpoints": {
                "config": {
                    "get_all": {"method": "GET", "path": "/v1/config/all"},
                    "get": {"method": "GET", "path": "/v1/config", "params": ["key"]},
                    "update": {"method": "PUT", "path": "/v1/config"},
                },
            }
        },
    },
    
    # Common parameter descriptions for AI context
    "common_params": {
        "page": "Page number (0-based for most endpoints)",
        "pageNumber": "Page number (1-based)",
        "size": "Number of items per page",
        "pageSize": "Number of items per page",
        "sort": "Sort field and direction (e.g., 'name,asc')",
        "search": "Search/filter string",
        "filter": "Filter criteria",
    }
}


# ==================== Server State ====================

class ServerState:
    """Manages server state including client and cache."""
    
    def __init__(self):
        self.client: Optional[GCMClient] = None
        self.auth_time: Optional[datetime] = None
        self.session_timeout = timedelta(hours=1)  # Re-auth after 1 hour
    
    def get_client(self) -> GCMClient:
        """Get or create GCM client."""
        if self.client is None:
            host = os.environ.get('GCM_HOST', 'localhost')
            self.client = GCMClient(host=host)
        return self.client
    
    def is_session_valid(self) -> bool:
        """Check if current session is still valid."""
        if not self.client or not self.client.authenticated:
            return False
        # Client handles token refresh internally
        return self.client._ensure_token()
    
    def auto_auth(self) -> Tuple[bool, str]:
        """Attempt auto-authentication using environment variables."""
        username = os.environ.get('GCM_USERNAME')
        password = os.environ.get('GCM_PASSWORD')
        
        if not username or not password:
            return False, "Credentials not found. Set GCM_USERNAME and GCM_PASSWORD environment variables."
        
        client = self.get_client()
        if client.login(username, password):
            self.auth_time = datetime.now()
            return True, f"Authenticated as {client.user_id}"
        return False, "Authentication failed"


state = ServerState()

# ==================== MCP Server ====================

app = Server("gcm-mcp-server")


@app.list_tools()
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


# ==================== MCP Prompts ====================

@app.list_prompts()
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


@app.get_prompt()
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

@app.list_resources()
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


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a GCM resource by URI."""
    uri_str = str(uri)
    if uri_str == "gcm://services":
        services = {}
        for name, svc in GCM_API_SCHEMA["services"].items():
            endpoint_count = sum(len(eps) for eps in svc.get("endpoints", {}).values())
            services[name] = {
                "description": svc["description"],
                "base_path": svc["base"],
                "endpoint_count": endpoint_count,
                "resources": list(svc.get("endpoints", {}).keys())
            }
        return json.dumps(services, indent=2)
    elif uri_str == "gcm://schema":
        return json.dumps(GCM_API_SCHEMA, indent=2)
    elif uri_str == "gcm://config":
        config = {
            "server": "GCM MCP Server",
            "version": "1.0.0",
            "gcm_host": os.environ.get("GCM_HOST", "not configured"),
            "api_port": os.environ.get("GCM_API_PORT", "31443"),
            "keycloak_port": os.environ.get("GCM_KEYCLOAK_PORT", "30443"),
            "auth_mode": os.environ.get("GCM_AUTH_MODE", "oauth2"),
            "verify_ssl": os.environ.get("GCM_VERIFY_SSL", "false"),
            "services_available": list(GCM_API_SCHEMA["services"].keys()),
            "total_endpoints": sum(
                sum(len(eps) for eps in svc.get("endpoints", {}).values())
                for svc in GCM_API_SCHEMA["services"].values()
            )
        }
        return json.dumps(config, indent=2)
    raise ValueError(f"Unknown resource: {uri_str}")


# ==================== Tool Handlers ====================

@app.call_tool()
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
    username = args.get("username") or os.environ.get("GCM_USERNAME")
    password = args.get("password") or os.environ.get("GCM_PASSWORD")
    
    if not username or not password:
        return [TextContent(type="text", text=json.dumps({
            "error": "Credentials required",
            "hint": "Provide username/password or set GCM_USERNAME/GCM_PASSWORD env vars"
        }, indent=2))]
    
    client = state.get_client()
    
    # Capture login output
    import io
    import sys
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
            "available": list(GCM_API_SCHEMA["services"].keys())
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
        import re
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


# Default timeout for API requests (seconds)
API_REQUEST_TIMEOUT = int(os.environ.get('GCM_REQUEST_TIMEOUT', '30'))


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
        # Run blocking requests call in a thread pool with timeout
        result = await asyncio.wait_for(
            asyncio.to_thread(_sync_request, client, method, endpoint, params, body),
            timeout=API_REQUEST_TIMEOUT
        )

        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    except asyncio.TimeoutError:
        return [TextContent(type="text", text=json.dumps({
            "error": f"Request timed out after {API_REQUEST_TIMEOUT}s",
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
        # List all services with descriptions
        services = {}
        for name, svc in GCM_API_SCHEMA["services"].items():
            services[name] = {
                "description": svc["description"],
                "base_path": svc["base"],
                "resources": list(svc.get("endpoints", {}).keys())
            }
        return [TextContent(type="text", text=json.dumps({
            "services": services,
            "usage": "Use gcm_api with service='<name>' and operation='<resource>.<action>'"
        }, indent=2))]
    
    elif category == "endpoints":
        service_name = args.get("service")
        if not service_name:
            return [TextContent(type="text", text=json.dumps({
                "error": "service parameter required",
                "available": list(GCM_API_SCHEMA["services"].keys())
            }, indent=2))]
        
        service = GCM_API_SCHEMA["services"].get(service_name)
        if not service:
            return [TextContent(type="text", text=json.dumps({
                "error": f"Unknown service: {service_name}",
                "available": list(GCM_API_SCHEMA["services"].keys())
            }, indent=2))]
        
        return [TextContent(type="text", text=json.dumps({
            "service": service_name,
            "description": service["description"],
            "base_path": service["base"],
            "endpoints": service.get("endpoints", {})
        }, indent=2))]
    
    elif category == "schema":
        # Return full schema (use sparingly - large token cost)
        return [TextContent(type="text", text=json.dumps(GCM_API_SCHEMA, indent=2))]
    
    elif category == "search":
        query = args.get("query", "").lower()
        if not query:
            return [TextContent(type="text", text=json.dumps({
                "error": "query parameter required",
                "example": "gcm_discover category='search' query='user'"
            }, indent=2))]
        
        # Search through schema
        results = []
        for svc_name, svc in GCM_API_SCHEMA["services"].items():
            for resource, endpoints in svc.get("endpoints", {}).items():
                for action, definition in endpoints.items():
                    full_name = f"{svc_name}.{resource}.{action}"
                    if query in full_name.lower() or query in svc["description"].lower():
                        results.append({
                            "service": svc_name,
                            "operation": f"{resource}.{action}",
                            "method": definition["method"],
                            "path": svc["base"] + definition["path"]
                        })
        
        return [TextContent(type="text", text=json.dumps({
            "query": query,
            "results": results,
            "count": len(results)
        }, indent=2))]
    
    return [TextContent(type="text", text=json.dumps({"error": f"Unknown category: {category}"}))]


# ==================== Main ====================

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
            "services": list(GCM_API_SCHEMA["services"].keys()),
        })

    return Starlette(
        debug=False,
        routes=[
            Route("/health", health),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )


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
