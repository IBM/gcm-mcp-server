# GCM MCP Server

Model Context Protocol (MCP) server for IBM Guardium Cryptography Manager (GCM) 2.0 — Access 292 GCM REST API endpoints through just 3 intelligent MCP tools.

Ask your AI assistant to list cryptographic assets, manage TDE keys, run discovery scans, check policy compliance — all without writing API calls or navigating the GCM console.

![GCM MCP Server: Bridging AI Assistants and IBM Guardium](GCM%20MCP.png)

---

## What You Can Do

The server provides three tools that your AI assistant discovers automatically:

| Tool | What it does |
|------|-------------|
| `gcm_auth` | Manage authentication — login, logout, check status |
| `gcm_api` | Run any GCM operation — list users, create keys, scan assets, check policies |
| `gcm_discover` | Browse available APIs — find endpoints, view parameters, explore services |

**Example prompts you can use:**

- *"Show me all cryptographic assets discovered in the last 7 days"*
- *"List all TDE encryption keys and their expiration dates"*
- *"Run a discovery scan on the Oracle database server"*
- *"Which policies have active violations?"*
- *"Create a new user with read-only access"*

Authentication happens automatically — the server logs into GCM on your first request and refreshes the token as needed. No passwords in your prompts, ever.

---

## Architecture

```mermaid
%%{init: {'theme': 'default'}}%%
flowchart TB
    A(["🤖 AI Assistant"])
    B{{"⚙️ MCP Server"}}
    C[("🔐 Keycloak :30443")]
    D[["🌐 IAG Gateway :31443"]]
    E[/"📦 GCM Services"\]

    A -->|"① API Key (Bearer header)"| B
    B -->|② Validate API Key| B
    B -->|③ Authenticate| C
    C -.->|④ Access Token| B
    B -->|⑤ API Call + Bearer Token| D
    D -->|⑥ Route Request| E
    E -.->|⑦ JSON Response| D
    D -.->|⑧ Forward Data| B
    B -.->|⑨ AI Response| A
```

**How it works — step by step:**

| Step | What happens |
| ---- | --------------------------------------------------------------- |
| ① | AI assistant sends a request to MCP Server **with API key in the `Authorization` header** |
| ② | MCP Server **validates the API key** — rejects with `401 Unauthorized` if missing or wrong |
| ③ | MCP Server sends GCM credentials to Keycloak (GCM's identity provider) |
| ④ | Keycloak validates and returns an `access_token` (5 min TTL) |
| ⑤ | MCP Server calls IAG Gateway with `Bearer <token>` |
| ⑥ | IAG routes the request to the correct GCM microservice |
| ⑦ | GCM service processes and returns JSON |
| ⑧ | IAG passes the response back to MCP Server |
| ⑨ | MCP Server formats and returns the answer to the AI assistant |

> **→ solid arrows** = request &nbsp;&nbsp; **⇢ dotted arrows** = response

---

## Getting Started

> **📖 [Full Setup Guide](SETUP_GUIDE.md)** — Complete step-by-step instructions for server admins and clients, including deployment, client onboarding for VS Code / Claude Desktop / IBM Bob, key rotation, and troubleshooting.

### Quick Start (Admin)

```bash
# 1. Get OIDC credentials from the GCM server (see Setup Guide, step A1)

# 2. Pull and run the container
docker pull ghcr.io/ibm/gcm-mcp-server:latest

docker run -d \
  --name gcm-mcp-server \
  --restart unless-stopped \
  -p 8002:8002 \
  -v gcm-mcp-data:/data \
  -e GCM_HOST="<gcm-server-ip>" \
  -e GCM_USERNAME="<your-gcm-username>" \
  -e GCM_PASSWORD="<your-gcm-password>" \
  -e GCM_CLIENT_ID="gcmclient" \
  -e GCM_CLIENT_SECRET="<oidc-client-secret>" \
  ghcr.io/ibm/gcm-mcp-server:latest

# 3. Verify
curl http://localhost:8002/health

# 4. Generate an API key for a client
curl -s -X POST http://localhost:8002/admin/keys \
  -H "Content-Type: application/json" \
  -d '{"user": "alice@ibm.com"}'
```

Send the key to the user securely — it is shown once and never stored.

### Quick Start (Client)

Get the **server URL** and **API key** from your admin. Add to `.vscode/mcp.json`:

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

Reload VS Code and start chatting. See the [Setup Guide](SETUP_GUIDE.md) for Claude Desktop, IBM Bob, key rotation, and troubleshooting.

---

## Security

The MCP server has **two layers of authentication** — one to protect the MCP server itself, and one to authenticate with GCM.

```mermaid
%%{init: {'theme': 'default'}}%%
flowchart LR
    subgraph "Layer 1: Client → MCP Server"
        A(["AI Assistant"]) -->|"API Key\n(Authorization: Bearer key)"| B{{"MCP Server"}}
    end

    subgraph "Admin (localhost only)"
        E(["Admin (SSH)"]) -->|"POST /admin/keys"| B
    end

    subgraph "Layer 2: MCP Server → GCM"
        B -->|"OAuth2\n(username + password + client_secret)"| C[("Keycloak")]
        C -.->|"access_token"| B
        B -->|"Bearer token"| D[["GCM API"]]
    end

    style A fill:#e1f5fe
    style B fill:#fff3e0
    style C fill:#fce4ec
    style D fill:#e8f5e9
    style E fill:#f3e5f5
```

| Layer | What it protects | How it works |
|-------|-----------------|---------------|
| **Layer 1 — MCP API Key** | Prevents unauthorized clients from connecting to the MCP server | Client sends `Authorization: Bearer <key>` header. MCP server validates the key against the key store. Invalid or missing key → `401 Unauthorized`. |
| **Layer 2 — GCM OAuth2** | Authenticates the MCP server to GCM's APIs via Keycloak | MCP server uses `GCM_USERNAME` + `GCM_PASSWORD` + `GCM_CLIENT_SECRET` to get an OAuth2 token from Keycloak. Token auto-refreshes every 5 min. |

### API Key Management

API keys are managed via **localhost-only admin endpoints** on the MCP server. You must be on the server (SSH) to create, list, or revoke keys. See the [Setup Guide — Key Rotation](SETUP_GUIDE.md#part-c-key-rotation--revocation-admin) for the full procedure.

| Method | Endpoint | Action |
|--------|----------|--------|
| `POST` | `/admin/keys` | Generate a new API key for a user |
| `GET` | `/admin/keys` | List all active keys (masked) |
| `DELETE` | `/admin/keys/{key_prefix}` | Revoke a key |

All `/admin/*` requests from non-localhost IPs → **403 Forbidden**.

**Key storage:** Keys are stored as SHA-256 hashes in `/data/keys.json`. Raw keys are shown once at generation time and never stored or retrievable again. Mount a persistent volume at `/data` to preserve keys across container restarts.

> **`/admin/*` endpoints are only accessible from `localhost`.** The server rejects all admin requests from non-local IPs with `403 Forbidden`. To manage keys from your laptop, use an SSH tunnel: `ssh -L 8002:localhost:8002 root@<mcp-server-host>`
>
> **stdio transport is exempt** from API key validation — the user runs the process locally with their own GCM credentials; GCM Keycloak (Layer 2) is the security gate.

---

## GCM Authentication

GCM uses [Keycloak](https://www.keycloak.org/) as its identity provider. Instead of authenticating directly with GCM, all login requests go through Keycloak's OAuth2/OIDC token endpoint. This is how GCM secures its APIs — every API call requires a Bearer token issued by Keycloak.

The MCP server handles this entirely for you. Credentials are set once in environment variables — you never include passwords in your prompts or tool calls.

```mermaid
sequenceDiagram
    autonumber
    participant M as MCP Server
    participant K as Keycloak
    participant I as IAG Gateway
    participant G as GCM Service

    M->>K: POST /token (username + password + client_id + client_secret)
    K-->>M: access_token + refresh_token (5 min TTL)
    M->>I: POST /v2/authorization (Bearer access_token)
    I-->>M: 200 OK — user authorized
    M->>I: GET /ibm/.../api/v2/resource (Bearer access_token)
    I->>G: Forward request
    G-->>I: JSON response
    I-->>M: JSON response
```

**Step-by-step breakdown:**

| Step | Arrow | What happens |
| ---- | --------------- | --------------------------------------------------------------------- |
| 1 | MCP → Keycloak | Send your GCM credentials + OIDC client credentials to Keycloak |
| 2 | Keycloak → MCP | Receive `access_token` (expires in 300s) and `refresh_token` |
| 3 | MCP → IAG | Authorize the token with GCM's user management service |
| 4 | IAG → MCP | GCM confirms the user is valid and authorized |
| 5 | MCP → IAG | Make actual API call (e.g., list users, create key) with Bearer token |
| 6 | IAG → GCM | IAG routes to the correct microservice |
| 7 | GCM → IAG | Service returns the result |
| 8 | IAG → MCP | Response forwarded back to MCP Server |

> **Token refresh:** When the token expires after 5 minutes, the MCP Server automatically uses the `refresh_token` to get a new `access_token` — no re-login needed.

### Token Lifecycle

```mermaid
stateDiagram-v2
    [*] --> NoToken
    NoToken --> HasToken: ① Auto-login on first API call
    HasToken --> HasToken: ② Token valid - make API calls
    HasToken --> Refreshing: ③ Token expired after 5 min
    Refreshing --> HasToken: ④ Refresh OK - new token
    Refreshing --> NoToken: ⑤ Refresh failed - re-login
```

You don't need to manage any of this — the MCP server handles login, refresh, and re-login automatically.

### Credentials You Need

The MCP server requires **two sets of credentials**, both set as environment variables:

| Credential | Purpose | How to Obtain |
| --- | --- | --- |
| **GCM_USERNAME / GCM_PASSWORD** | Your identity for GCM | Your GCM login credentials |
| **GCM_CLIENT_ID / GCM_CLIENT_SECRET** | OAuth2 client for Keycloak | From a Kubernetes secret on the GCM server |

**Why two sets?** Your username/password prove *who you are*. The client ID/secret prove *which application* is requesting the token. Keycloak requires both to issue an access token.

**Retrieve the OIDC client credentials from the GCM server:** See the [Setup Guide — Step A1](SETUP_GUIDE.md#a1-get-oidc-client-credentials-from-the-gcm-server).

---

## Available GCM Services

| Service | What you can manage | Example prompt |
|---------|-------------------|----------------|
| User Management | Users, roles, licenses | *"List all GCM users and their roles"* |
| TDE | Encryption keys, certificates, TDE clients | *"Show TDE keys expiring this month"* |
| Asset Inventory | Cryptographic objects, IT assets | *"How many crypto assets use RSA-2048?"* |
| Discovery | Scan profiles, discovery jobs | *"Run a discovery scan on server db-prod-01"* |
| Policy | Compliance policies, rules | *"Which policies are currently violated?"* |
| Audit | Audit logs, activity reports | *"Show audit events from the last 24 hours"* |
| Integration | SIEM, KMS connections | *"List all configured SIEM integrations"* |
| Notifications | Alert rules, channels | *"What notification channels are set up?"* |
| CLM | Certificate lifecycle | *"List certificates expiring in 30 days"* |
| Config | System configuration | *"Show current system settings"* |
| Policy Risk | Violations, risk evaluation | *"List all high-severity violations"* |

**Total API coverage:** 292 endpoints across GET, POST, PUT, DELETE operations.

---

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GCM_HOST` | Yes | — | GCM server IP or hostname |
| `GCM_API_PORT` | No | `31443` | API gateway port |
| `GCM_KEYCLOAK_PORT` | No | `30443` | Keycloak port |
| `GCM_USERNAME` | Yes | — | Your GCM username |
| `GCM_PASSWORD` | Yes | — | Your GCM password |
| `GCM_CLIENT_ID` | No | `gcmclient` | OIDC client ID |
| `GCM_CLIENT_SECRET` | Yes | — | OIDC client secret (from K8s) |
| `GCM_AUTH_MODE` | No | `oauth2` | Authentication mode |
| `GCM_VERIFY_SSL` | No | `false` | SSL certificate verification |
| `GCM_REQUEST_TIMEOUT` | No | `30` | API timeout in seconds |
| `GCM_MCP_KEY_STORE_PATH` | No | `/data/keys.json` | Path to the API key store file. Mount a persistent volume at `/data` for container deployments. |

You can set these as environment variables or in a `.env` file alongside the server.

---

## Resources

- [IBM Guardium CM 2.0 Documentation](https://www.ibm.com/docs/en/guardium-cm/2.0.0)
- [GCM Swagger API Reference](https://www.ibm.com/docs/en/guardium-cm/2.0.0?topic=apis-swagger-api)
- [Container Image on ghcr.io](https://github.com/orgs/IBM/packages/container/package/gcm-mcp-server)

---

## Support

**Found a bug?** [Open an issue](https://github.com/IBM/gcm-mcp-server/issues/new) with steps to reproduce and server logs.

**Feature request?** [Open an issue](https://github.com/IBM/gcm-mcp-server/issues/new) with `[Feature Request]` prefix.

**Questions?** Check [existing issues](https://github.com/IBM/gcm-mcp-server/issues) or open a new one.

---

## IBM Public Repository Disclosure

All content in this repository including code has been provided by IBM under the associated open source software license and IBM is under no obligation to provide enhancements, updates, or support. IBM developers produced this code as an open source project (not as an IBM product), and IBM makes no assertions as to the level of quality nor security, and will not be maintaining this code going forward.

---

> **Disclaimer:** This is a Minimum Viable Product (MVP) for testing and demonstration purposes only. Not for production use. No warranty or support guarantees.
