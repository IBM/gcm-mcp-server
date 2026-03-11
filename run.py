"""WXO STDIO entry point for GCM MCP Server."""
import os

# Force STDIO transport
os.environ["MCP_TRANSPORT"] = "stdio"

# Map WXO connection env vars to the bare names expected by config.py
# WXO injects: WXO_CONNECTION_<app_id>_<field> = value
# Our code reads: <field>
_APP_ID = "gcm_creds"
_ENV_KEYS = [
    "GCM_HOST",
    "GCM_USERNAME",
    "GCM_PASSWORD",
    "GCM_CLIENT_SECRET",
    "GCM_API_PORT",
    "GCM_KEYCLOAK_PORT",
    "GCM_CLIENT_ID",
    "GCM_AUTH_MODE",
    "GCM_VERIFY_SSL",
]
for key in _ENV_KEYS:
    wxo_key = f"WXO_CONNECTION_{_APP_ID}_{key}"
    val = os.environ.get(wxo_key)
    if val and not os.environ.get(key):
        os.environ[key] = val

from src.server import main

if __name__ == "__main__":
    main()
