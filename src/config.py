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
GCM_CLIENT_ID = os.environ.get('GCM_CLIENT_ID', 'admin')
GCM_CLIENT_SECRET = os.environ.get('GCM_CLIENT_SECRET', 'password')
GCM_AUTH_MODE = os.environ.get('GCM_AUTH_MODE', 'auto')

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
