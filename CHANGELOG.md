# Changelog

## v1.0.0 — February 2026

### Summary

The GCM MCP Server now requires API key authentication for all client connections over SSE/HTTP. Previously, the server was open — anyone on the network could connect and interact with GCM through it without any credentials. This release adds admin-managed API key security, fixes unsafe credential defaults, updates all documentation, and hardens the deployment for client distribution.

### Why These Updates Were Made

- **The server had no client-side authentication.** Any network user could connect to the MCP server and execute GCM API calls — list users, manage keys, run scans — without proving identity.
- **Default credentials were unsafe.** `GCM_CLIENT_ID` defaulted to `'admin'` instead of `'gcmclient'`, and `GCM_CLIENT_SECRET` defaulted to `'password'` instead of requiring a real value. This could cause silent authentication failures or security issues.
- **Documentation was outdated.** The README, Setup Guide, and Security docs did not reflect the new API key system, correct defaults, or proper client configuration (e.g., Claude Desktop requires `mcp-remote` proxy).
- **No startup validation.** The server would start with missing required variables (`GCM_HOST`, `GCM_PASSWORD`, `GCM_CLIENT_SECRET`) and fail later at runtime with confusing errors.

### What Changed

| Area | Before | After |
|------|--------|-------|
| **Client auth** | None — open to all network users | API key required (`Authorization: Bearer <key>`) |
| **Key management** | N/A | Admin generates keys via localhost-only `/admin/*` endpoints |
| **Key storage** | N/A | SHA-256 hashed in `/data/keys.json`, persistent volume |
| **`GCM_CLIENT_ID` default** | `'admin'` (wrong) | `'gcmclient'` (correct) |
| **`GCM_CLIENT_SECRET` default** | `'password'` (dangerous) | `None` — server refuses to start without it |
| **Startup validation** | None | `validate_required_config()` checks 4 required vars at boot |
| **`GCM_AUTH_MODE` default** | Documented as `oauth2` | Corrected to `auto` everywhere |
| **Claude Desktop config** | Native SSE with headers (doesn't work) | `mcp-remote` proxy with `--header` args |
| **Admin endpoint access** | N/A | Restricted to `127.0.0.1` / `::1` and Docker bridge `172.17.0.1` |
| **stdio transport** | Was briefly gated by API key | Exempt — user already has local access |

### For Existing Clients (Breaking Change)

**If you were already connected to the MCP server before this update, your connection will stop working.** The server now rejects all requests without a valid API key.

**What you need to do:**

1. **Get an API key from the server admin.** They will generate one for you and send it securely.
2. **Add the key to your MCP client config:**

   **VS Code** — edit `.vscode/mcp.json`:
   ```json
   {
     "servers": {
       "gcm-mcp-server": {
         "type": "sse",
         "url": "http://<mcp-server-host>:8002/sse",
         "headers": {
           "Authorization": "Bearer <your-api-key>"
         }
       }
     }
   }
   ```

   **Claude Desktop** — edit `~/Library/Application Support/Claude/claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "gcm-mcp-server": {
         "command": "npx",
         "args": [
           "mcp-remote",
           "http://<mcp-server-host>:8002/sse",
           "--header",
           "Authorization: Bearer <your-api-key>"
         ]
       }
     }
   }
   ```

   **IBM Bob** — edit `~/Library/Application Support/IBM Bob/User/globalStorage/ibm.bob-code/settings/mcp_settings.json`:
   ```json
   {
     "mcpServers": {
       "gcm-mcp-server": {
         "type": "sse",
         "url": "http://<mcp-server-host>:8002/sse",
         "headers": {
           "Authorization": "Bearer <your-api-key>"
         }
       }
     }
   }
   ```

3. **Reload / restart your AI assistant.**
4. **Test:** Ask *"Use gcm_discover to list all available GCM services."* You should see 11 services.

**That's it.** Everything else (GCM login, token refresh, API routing) works exactly as before. The only change on your side is adding the `Authorization` header.
