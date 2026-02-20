# GCM MCP Server — Setup Guide

Complete step-by-step instructions to deploy the MCP server, onboard clients, and manage API keys.

**Three roles are involved:**

| Role | What they do | Access needed |
|------|-------------|---------------|
| **GCM Admin** | Extracts OIDC credentials from the GCM K8s cluster | SSH to GCM server |
| **MCP Server Admin** | Deploys the container, configures env vars, generates/revokes API keys | SSH to MCP server host |
| **Client (end user)** | Pastes API key + URL into their AI assistant config, starts chatting | Just the key and the URL |

---

## Part A: Server Setup (Admin — one time)

### A1. Get OIDC Client Credentials from the GCM Server

The MCP server authenticates to GCM via Keycloak (GCM's identity provider). You need the OIDC client credentials stored in a Kubernetes secret on the GCM server.

```bash
ssh root@<gcm-server-ip>
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# Client ID (usually 'gcmclient')
kubectl get secret oidc-client-secret -n gcmapp \
  -o jsonpath='{.data.CLIENT_ID}' | base64 -d && echo

# Client Secret
kubectl get secret oidc-client-secret -n gcmapp \
  -o jsonpath='{.data.CLIENT_SECRET}' | base64 -d && echo
```

Save both values — you need them in step A3.

### A2. Pull the Container on the MCP Server Host

SSH into the machine that will host the MCP server (this can be any server with Docker — it does not need to be the GCM server itself):

```bash
ssh root@<mcp-server-host>
docker pull ghcr.io/ibm/gcm-mcp-server:latest
```

The image supports both `linux/amd64` and `linux/arm64`.

### A3. Run the Container

```bash
docker run -d \
  --name gcm-mcp-server \
  --restart unless-stopped \
  -p 8002:8002 \
  -v gcm-mcp-data:/data \
  -e GCM_HOST="<gcm-server-ip>" \
  -e GCM_USERNAME="gcmadmin@gcm.local" \
  -e GCM_PASSWORD="<gcm-password>" \
  -e GCM_CLIENT_ID="gcmclient" \
  -e GCM_CLIENT_SECRET="<from-step-A1>" \
  ghcr.io/ibm/gcm-mcp-server:latest
```

**What each part does:**

| Parameter | Purpose |
|-----------|---------|
| `-p 8002:8002` | Exposes the SSE transport on port 8002 |
| `-v gcm-mcp-data:/data` | Persistent volume — API keys survive container restarts and upgrades |
| `GCM_HOST` | IP or hostname of the GCM server (e.g., `9.30.252.230`) |
| `GCM_USERNAME` | GCM admin account (e.g., `gcmadmin@gcm.local`) |
| `GCM_PASSWORD` | Password for that account |
| `GCM_CLIENT_ID` | OIDC client ID from step A1 (usually `gcmclient`) |
| `GCM_CLIENT_SECRET` | OIDC client secret from step A1 |

> See the [Configuration Reference](README.md#configuration-reference) in the README for all optional variables (ports, timeouts, SSL, etc.).

### A4. Verify the Server

```bash
curl http://localhost:8002/health
```

Expected response:

```json
{
  "status": "ok",
  "server": "GCM MCP Server",
  "version": "1.0.0",
  "transport": "sse",
  "auth_required": true,
  "active_keys": 0,
  "services": [
    "usermanagement", "tde", "assetinventory", "discovery",
    "policy", "policyrisk", "audit", "integration",
    "notifications", "clm", "config"
  ]
}
```

Confirm:
- `auth_required: true` — API key validation is active
- `active_keys: 0` — no keys generated yet (you'll do this next)
- `services` — all 11 GCM services discovered

### A5. Generate API Keys for Clients

Still on the MCP server host (admin endpoints only work from localhost):

```bash
curl -s -X POST http://localhost:8002/admin/keys \
  -H "Content-Type: application/json" \
  -d '{"user": "alice@ibm.com"}' | jq .
```

Response:

```json
{
  "key": "a3f8e9b1c4d7e6f2...full-64-character-hex-string...",
  "user": "alice@ibm.com",
  "created": "2026-02-20T14:30:00Z",
  "key_prefix": "a3f8e9b1"
}
```

> **Copy the `key` value immediately.** It is shown exactly once — the server stores only the SHA-256 hash. The raw key is never stored or retrievable again.

Send the key to the user securely (encrypted email, Slack DM, in person — never a public channel). They also need the server URL: `http://<mcp-server-host>:8002/sse`

Repeat for each client who needs access.

---

## Part B: Client Setup (Each User)

You need two things from the admin:
1. **Server URL** — e.g., `http://9.30.147.112:8002/sse`
2. **API Key** — the 64-character hex string generated for you

### B1. Configure Your AI Assistant

Choose your editor and add the configuration:

#### VS Code (GitHub Copilot)

Create or edit `.vscode/mcp.json` in your project root:

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

Then reload: `Cmd+Shift+P` → **"Reload Window"**

#### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gcm-mcp-server": {
      "type": "sse",
      "url": "http://<mcp-server-host>:8002/sse",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      },
      "alwaysAllow": ["gcm_auth", "gcm_api", "gcm_discover"]
    }
  }
}
```

Restart Claude Desktop.

#### IBM Bob (Cloud Desktop)

Edit `~/Library/Application Support/IBM Bob/User/globalStorage/ibm.bob-code/settings/mcp_settings.json`:

```json
{
  "mcpServers": {
    "gcm-mcp-server": {
      "type": "sse",
      "url": "http://<mcp-server-host>:8002/sse",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      },
      "alwaysAllow": ["gcm_auth", "gcm_api", "gcm_discover"]
    }
  }
}
```

Restart Bob.

### B2. Verify the Connection

After restarting your AI assistant, try this prompt:

> *"Use gcm_discover to list all available GCM services"*

You should see 11 services: usermanagement, tde, assetinventory, discovery, policy, policyrisk, audit, integration, notifications, clm, config.

### B3. Start Chatting with GCM

You can now use natural language to interact with GCM. Example prompts:

| What you want | Prompt |
|---------------|--------|
| Authenticate | *"Log into GCM"* |
| Browse APIs | *"What endpoints are available for TDE key management?"* |
| List users | *"List all GCM users and their roles"* |
| Check keys | *"Show TDE keys expiring this month"* |
| Run a scan | *"Run a discovery scan on server db-prod-01"* |
| Check compliance | *"Which policies have active violations?"* |
| Audit trail | *"Show audit events from the last 24 hours"* |
| Certificates | *"List certificates expiring in 30 days"* |

**You don't need GCM credentials.** The MCP server handles authentication to GCM using credentials configured by the admin on the server side. Your API key only proves you're authorized to talk to the MCP server.

---

## Part C: Key Rotation & Revocation (Admin)

### C1. List Active Keys

SSH into the MCP server host:

```bash
ssh root@<mcp-server-host>
curl -s http://localhost:8002/admin/keys | jq .
```

Output:

```json
[
  {"user": "alice@ibm.com", "key_prefix": "a3f8e9b1", "created": "2026-02-20T14:30:00Z"},
  {"user": "bob@ibm.com",   "key_prefix": "c5d2f7e3", "created": "2026-02-20T15:00:00Z"}
]
```

### C2. Revoke a Key

```bash
curl -s -X DELETE http://localhost:8002/admin/keys/a3f8e9b1
```

The key is immediately invalidated — Alice's next request will get `401 Unauthorized`. No server restart needed.

### C3. Generate a Replacement Key

```bash
curl -s -X POST http://localhost:8002/admin/keys \
  -H "Content-Type: application/json" \
  -d '{"user": "alice@ibm.com"}' | jq .
```

Send the new key to Alice securely.

### C4. Client: Update Your Config

Replace the old key with the new one in your `.vscode/mcp.json` (or equivalent config), then reload your AI assistant.

### When to Rotate Keys

| Situation | Action |
|-----------|--------|
| Key compromised or leaked | Revoke immediately (C2), generate new (C3) |
| User leaves the team | Revoke their key (C2) |
| Scheduled rotation | Generate new key (C3), update client (C4), then revoke old key (C2) |
| Lost key (user forgot it) | Revoke the old key by prefix (C2), generate a new one (C3) |

---

## Running from Source (Alternative)

If you prefer not to use Docker, you can run the MCP server directly with Python 3.10+:

```bash
git clone https://github.com/IBM/gcm-mcp-server.git
cd gcm-mcp-server
pip install -e .

export GCM_HOST=<gcm-server-ip>
export GCM_USERNAME=<your-gcm-username>
export GCM_PASSWORD=<your-gcm-password>
export GCM_CLIENT_SECRET=<from-step-A1>

python -m src.server
```

Generate API keys the same way:

```bash
curl -s -X POST http://localhost:8002/admin/keys \
  -H "Content-Type: application/json" \
  -d '{"user": "bob@company.com"}'
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` on SSE connect | Missing or wrong API key | Check `Authorization: Bearer <key>` header in your config |
| `403 Forbidden` on `/admin/keys` | Calling admin endpoint from non-localhost | SSH into the server first, or use an SSH tunnel: `ssh -L 8002:localhost:8002 root@<host>` |
| Health shows `active_keys: 0` | No keys generated yet | Run `POST /admin/keys` from localhost (step A5) |
| Keys lost after container restart | No persistent volume | Recreate container with `-v gcm-mcp-data:/data` |
| `Connection refused` on port 8002 | Container not running | Check `docker ps` and `docker logs gcm-mcp-server` |
| GCM login fails | Wrong credentials or GCM server unreachable | Verify `GCM_HOST`, `GCM_USERNAME`, `GCM_PASSWORD`, `GCM_CLIENT_SECRET` in `docker inspect gcm-mcp-server` |

---

## Quick Reference

```
Admin: ssh root@<mcp-server-host>

Generate key:   curl -s -X POST http://localhost:8002/admin/keys -H "Content-Type: application/json" -d '{"user":"name@co.com"}'
List keys:      curl -s http://localhost:8002/admin/keys
Revoke key:     curl -s -X DELETE http://localhost:8002/admin/keys/<prefix>
Health check:   curl -s http://localhost:8002/health
Container logs: docker logs gcm-mcp-server --tail 50
```
