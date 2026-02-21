#!/usr/bin/env python3
"""GCM MCP Server — Environment variable loading.

Single source of truth for all configuration values.
All other modules import from here instead of reading os.environ directly.
"""

import os
import logging

from dotenv import load_dotenv
load_dotenv()

# ==================== GCM Server ====================

GCM_HOST = os.environ.get('GCM_HOST', 'localhost')
GCM_API_PORT = int(os.environ.get('GCM_API_PORT', '31443'))
GCM_KEYCLOAK_PORT = int(os.environ.get('GCM_KEYCLOAK_PORT', '30443'))

# ==================== Authentication ====================

GCM_USERNAME = os.environ.get('GCM_USERNAME')
GCM_PASSWORD = os.environ.get('GCM_PASSWORD')
GCM_CLIENT_ID = os.environ.get('GCM_CLIENT_ID', 'gcmclient')
GCM_CLIENT_SECRET = os.environ.get('GCM_CLIENT_SECRET')  # Required — no default
GCM_AUTH_MODE = os.environ.get('GCM_AUTH_MODE', 'auto')

# ==================== Startup Validation ====================

_REQUIRED_VARS = {
    'GCM_HOST': GCM_HOST,
    'GCM_USERNAME': GCM_USERNAME,
    'GCM_PASSWORD': GCM_PASSWORD,
    'GCM_CLIENT_SECRET': GCM_CLIENT_SECRET,
}


def validate_required_config():
    """Fail fast if any required environment variable is missing.

    Called once at server startup so operators see an immediate,
    actionable error instead of a cryptic 401 from Keycloak later.
    """
    missing = [k for k, v in _REQUIRED_VARS.items() if not v]
    if missing:
        raise SystemExit(
            f"FATAL: Missing required environment variables: {', '.join(missing)}\n"
            f"Set them with -e flags in 'docker run' or in a .env file.\n"
            f"See gcm-mcp-server-e2e-setup-guide.md for details."
        )

# ==================== SSL & Timeouts ====================

GCM_VERIFY_SSL = os.environ.get('GCM_VERIFY_SSL', 'false').lower() == 'true'
GCM_REQUEST_TIMEOUT = int(os.environ.get('GCM_REQUEST_TIMEOUT', '30'))

# ==================== MCP Server Security ====================

# Key store path — override via GCM_MCP_KEY_STORE_PATH env var
# Default: /data/keys.json (inside container, on persistent volume)
GCM_MCP_KEY_STORE_PATH = os.environ.get('GCM_MCP_KEY_STORE_PATH', '/data/keys.json')

# ==================== Logging ====================

GCM_LOG_LEVEL = os.environ.get('GCM_LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=getattr(logging, GCM_LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger."""
    return logging.getLogger(name)
