#!/usr/bin/env python3
"""GCM MCP Server — Endpoint discovery + schema caching.

Contains the pre-defined GCM API schema and helper functions
for querying services, endpoints, and searching the schema.
"""

from typing import Any, Dict, List, Optional


# ==================== API Schema (Cached) ====================

# Pre-defined API schema to avoid repeated discovery calls.
# This is transferred once when gcm_discover is called, then cached by the LLM.
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


# ==================== Discovery Helpers ====================

def get_services() -> Dict[str, Any]:
    """List all services with descriptions and resource names."""
    services = {}
    for name, svc in GCM_API_SCHEMA["services"].items():
        services[name] = {
            "description": svc["description"],
            "base_path": svc["base"],
            "resources": list(svc.get("endpoints", {}).keys())
        }
    return services


def get_service_detail(service_name: str) -> Optional[Dict[str, Any]]:
    """Get detailed info for a specific service, or None if not found."""
    service = GCM_API_SCHEMA["services"].get(service_name)
    if not service:
        return None
    return {
        "service": service_name,
        "description": service["description"],
        "base_path": service["base"],
        "endpoints": service.get("endpoints", {})
    }


def get_full_schema() -> Dict[str, Any]:
    """Return the complete API schema."""
    return GCM_API_SCHEMA


def search_endpoints(query: str) -> List[Dict[str, Any]]:
    """Search through schema for endpoints matching query."""
    results = []
    query_lower = query.lower()
    for svc_name, svc in GCM_API_SCHEMA["services"].items():
        for resource, endpoints in svc.get("endpoints", {}).items():
            for action, definition in endpoints.items():
                full_name = f"{svc_name}.{resource}.{action}"
                if query_lower in full_name.lower() or query_lower in svc["description"].lower():
                    results.append({
                        "service": svc_name,
                        "operation": f"{resource}.{action}",
                        "method": definition["method"],
                        "path": svc["base"] + definition["path"]
                    })
    return results


def get_service_catalog() -> Dict[str, Any]:
    """Get service catalog with endpoint counts (for MCP resources)."""
    services = {}
    for name, svc in GCM_API_SCHEMA["services"].items():
        endpoint_count = sum(len(eps) for eps in svc.get("endpoints", {}).values())
        services[name] = {
            "description": svc["description"],
            "base_path": svc["base"],
            "endpoint_count": endpoint_count,
            "resources": list(svc.get("endpoints", {}).keys())
        }
    return services


def get_total_endpoint_count() -> int:
    """Count total endpoints across all services."""
    return sum(
        sum(len(eps) for eps in svc.get("endpoints", {}).values())
        for svc in GCM_API_SCHEMA["services"].values()
    )


def get_service_names() -> List[str]:
    """Get list of all service names."""
    return list(GCM_API_SCHEMA["services"].keys())
