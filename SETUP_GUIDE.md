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

You need two things from the server admin:

1. **Server URL** — e.g., `http://9.30.147.112:8002/sse`
2. **API Key** — the 64-character hex string generated for you in step A5

---

### B1. Prerequisites by Client

| Client | Prerequisites |
|--------|---------------|
| **IBM Bob** | IBM Bob installed, MCP support enabled |
| **VS Code** | VS Code 1.99+, GitHub Copilot extension with Chat |
| **Claude Desktop** | Claude Desktop installed, Node.js 18+ (for `mcp-remote` proxy) |

---

### B2. IBM Bob Setup

#### Settings file location

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/IBM Bob/User/globalStorage/ibm.bob-code/settings/mcp_settings.json` |
| Linux | `~/.config/IBM Bob/User/globalStorage/ibm.bob-code/settings/mcp_settings.json` |
| Windows | `%APPDATA%\IBM Bob\User\globalStorage\ibm.bob-code\settings\mcp_settings.json` |

#### Option A — Let Bob configure itself

The easiest way. Open Bob and give it this prompt (replace the placeholders):

```
Please configure the GCM MCP server in my Bob MCP settings file.
Server URL: http://<mcp-server-host>:8002/sse
API Key: <your-api-key>

The settings file is at:
~/Library/Application Support/IBM Bob/User/globalStorage/ibm.bob-code/settings/mcp_settings.json

Add an entry called "gcm-mcp-server" with type "sse", the URL above,
an Authorization Bearer header with my key, and alwaysAllow for
gcm_auth, gcm_api, and gcm_discover. Do not overwrite any existing
mcpServers entries.
```

Bob will write the file and tell you to restart.

#### Option B — Configure manually

Create or edit the settings file with:

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

> If the file already has other MCP servers, add the `gcm-mcp-server` block inside the existing `mcpServers` object — do not replace the whole file.

**Restart Bob** after saving.

#### Verify

Prompt Bob:
> *"List all available GCM services using the MCP server"*

Expected: 11 services (usermanagement, tde, assetinventory, discovery, policy, policyrisk, audit, integration, notifications, clm, config).

---

### B3. VS Code (GitHub Copilot) Setup

#### Requirements
- VS Code 1.99 or later
- GitHub Copilot extension with Chat enabled

#### Settings file location

| Scope | Path |
|-------|------|
| Per-project | `.vscode/mcp.json` in the project root |
| Global (macOS) | `~/Library/Application Support/Code/User/mcp.json` |
| Global (Linux) | `~/.config/Code/User/mcp.json` |
| Global (Windows) | `%APPDATA%\Code\User\mcp.json` |

#### Option A — Let Copilot configure itself

Open GitHub Copilot Chat and ask:

```
Please configure the GCM MCP server in my VS Code MCP settings.
Create or update .vscode/mcp.json in this project with:
- Server name: GCM-MCP
- Type: sse
- URL: http://<mcp-server-host>:8002/sse
- Authorization header: Bearer <your-api-key>
```

Copilot will create or update the file directly. No restart needed.

#### Option B — Configure manually

Create `.vscode/mcp.json` in your project root:

```json
{
  "servers": {
    "GCM-MCP": {
      "type": "sse",
      "url": "http://<mcp-server-host>:8002/sse",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      }
    }
  }
}
```

VS Code picks up the file immediately — no restart needed.

#### Verify

In Copilot Chat:
> *"Use the GCM MCP server to list all available services"*

---

### B4. Claude Desktop Setup

Claude Desktop does not natively support SSE transports with custom headers. A lightweight proxy called `mcp-remote` bridges this gap.

#### Prerequisites

1. **Node.js 18+** — check with `node --version`. Install from [nodejs.org](https://nodejs.org) if missing.
2. **`mcp-remote`** — install once globally:
   ```bash
   npm install -g mcp-remote
   ```

#### Settings file location

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

#### Option A — Let Claude generate the config block

Open Claude Desktop chat and ask:

```
I want to add a GCM MCP server to my Claude Desktop config.
Server URL: http://<mcp-server-host>:8002/sse
API Key: <your-api-key>

The config file is at:
~/Library/Application Support/Claude/claude_desktop_config.json

Show me the exact JSON to add using mcp-remote as the command,
passing the URL and an Authorization Bearer header with my key.
I already have mcp-remote installed globally via npm.
```

Claude will output the exact JSON block to paste into the file.

#### Option B — Configure manually

Edit the config file:

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

> If you already have other MCP servers, add `gcm-mcp-server` inside the existing `mcpServers` object.

**Restart Claude Desktop** after saving.

#### Verify

In a new chat:
> *"List all available GCM services"*

---

### B5. Start Chatting with GCM

Once connected, use natural language. **You never need GCM credentials** — the server handles authentication to GCM internally. Your API key only authorises you to use the MCP server.

| What you want | Example prompt |
|---------------|----------------|
| Browse APIs | *"What GCM endpoints are available for TDE key management?"* |
| List users | *"List all GCM users and their roles"* |
| Check version | *"What version of GCM is running?"* |
| TDE inventory | *"Show all TDE clients in the inventory"* |
| Run a scan | *"Run a discovery scan on server db-prod-01"* |
| Check compliance | *"Which policies have active violations right now?"* |
| Audit trail | *"Show audit events from the last 24 hours"* |
| Certificates | *"List certificates expiring in the next 30 days"* |
| Violations dashboard | *"Give me a summary of current policy violations"* |
| System config | *"Show the current GCM system configuration"* |

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

Replace the old key with the new one in your client config (Claude Desktop or IBM Bob), then reload your AI assistant.

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
