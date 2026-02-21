# Client Layer Security — Hypothesis

## Problem

The MCP server listens on `0.0.0.0:8002` with no authentication. Anyone on the network can connect and control GCM through it.

## Solution

API key authentication — the MCP server checks for a secret token in every request. Only clients with a valid key can connect; everyone else gets 401 Unauthorized.

## Key Management

Keys are generated and managed by an admin through a localhost-only admin interface on the MCP server itself.

### Why Localhost-Only

- Admin must have SSH access to the server → implies trust
- No endpoint is exposed to the network → no one can generate keys remotely
- No separate admin secret needed → protected by network topology
- Works inside containers → admin uses `docker exec` or SSH tunnel

---

## Approaches Considered & Rejected

### 1. Single Shared API Key (env var)

```
GCM_MCP_API_KEY=abc123 → all users share the same key
```

**Rejected:** If the key leaks, everyone is compromised. No way to identify who is using it. No rotation without redeployment.

### 2. Per-User Permanent Keys (key store)

```
Key a3f8... → bob@company.com
Key 7b2c... → tom@company.com
```

**Rejected:** Permanent keys can be shared. Tom can use Bob's key — nothing prevents it. Admin burden to manage a key store.

### 3. Stickiness Mechanisms (IP bind, session lock, concurrent detection)

- **IP binding:** Breaks when users change networks (VPN, WFH, travel)
- **One SSE connection per key:** Creates unnecessary errors, blocks legitimate reconnects
- **Concurrent use detection:** Breaks multi-agent setups where same user runs multiple assistants

**All rejected:** Either break real workflows or are easily circumvented.

### 4. Short-Lived JWT via Keycloak

1. User runs:

   ```bash
   gcm-mcp-server get-token --server https://keycloak:30443 --user bob@gcm.local
   ```

2. Enters their GCM password
3. Gets back a JWT that expires in 8 hours
4. Puts the JWT in their `mcp.json`
5. Next morning, token expired → repeat step 1

**Rejected:** Creates hard dependency on Keycloak. Not all GCM deployments use Keycloak — some use LDAP, SAML, or local accounts. The MCP server must remain IdP-agnostic.

---

## Chosen Approach: Admin-Generated Keys via Localhost API

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Server (:8002)                    │
│                                                         │
│  /sse, /messages     → requires Authorization: Bearer   │
│  /health             → open (monitoring)                 │
│  /admin/*            → localhost only (127.0.0.1/::1)   │
│                                                         │
│  Key Store: /data/keys.json (persistent volume)         │
└─────────────────────────────────────────────────────────┘
```

### Admin Endpoints (localhost only)

| Method | Endpoint | Action |
|--------|----------|--------|
| `POST` | `/admin/keys` | Generate a new API key |
| `GET` | `/admin/keys` | List all active keys (masked) |
| `DELETE` | `/admin/keys/{key_prefix}` | Revoke a key |
| `GET` | `/admin/` | Web UI (optional) |

All `/admin/*` requests from non-localhost IPs → **403 Forbidden**.

### How the Admin Uses It

#### Option A: curl from SSH session

```bash
# SSH into the server
ssh root@appserver1

# Generate a key for Bob
curl -s -X POST http://localhost:8002/admin/keys \
  -H "Content-Type: application/json" \
  -d '{"user": "bob@company.com"}' | jq .

# Response:
# {
#   "key": "a3f8e9b1c4d7...full-64-char-hex",
#   "user": "bob@company.com",
#   "created": "2026-02-20T14:30:00Z",
#   "key_prefix": "a3f8e9b1"
# }
# ⚠️  Key is shown ONCE. Copy it now.

# List active keys
curl -s http://localhost:8002/admin/keys | jq .
# [
#   {"key_prefix": "a3f8e9b1", "user": "bob@company.com", "created": "2026-02-20T14:30:00Z"},
#   {"key_prefix": "7b2cd4e6", "user": "tom@company.com", "created": "2026-02-21T09:00:00Z"}
# ]

# Revoke Bob's key (leaked/compromised)
curl -s -X DELETE http://localhost:8002/admin/keys/a3f8e9b1
# {"status": "revoked", "key_prefix": "a3f8e9b1"}
```

#### Option B: Web UI via SSH tunnel

```bash
# From admin's laptop — create SSH tunnel
ssh -L 8002:localhost:8002 root@appserver1

# Open browser on laptop
open http://localhost:8002/admin/
```

The web UI shows:

- A form: enter user email → click "Generate Key" → key displayed once
- A table: all active keys (prefix, user, created date) with "Revoke" buttons
- Still localhost-only — the SSH tunnel forwards laptop's `localhost:8002` to the server's `localhost:8002`

**Both options hit the same endpoint: `http://localhost:8002/admin/`**

- Option A: you're on the server (SSH) → localhost is the server directly
- Option B: you're on your laptop → SSH tunnel makes localhost point to the server

### What the User Does

1. Requests MCP access from admin (email, Slack, ticket)
2. Admin generates key, sends it to user securely
3. User adds key to their MCP client config (Claude Desktop, IBM Bob, etc.) with the server URL and `Authorization: Bearer <key>` header

1. User connects — server validates key against key store → allowed

### Key Rotation

If a key is compromised:

1. Admin revokes the old key: `curl -X DELETE http://localhost:8002/admin/keys/a3f8e9b1`
2. Generates a new key for the user: `curl -X POST http://localhost:8002/admin/keys -d '{"user":"bob@company.com"}'`
3. Sends new key to user
4. Old key immediately stops working — no restart needed

### Key Storage

```json
// /data/keys.json — inside container on a persistent volume
{
  "keys": {
    "sha256-of-key-1": {
      "user": "bob@company.com",
      "created": "2026-02-20T14:30:00Z",
      "key_prefix": "a3f8e9b1"
    },
    "sha256-of-key-2": {
      "user": "tom@company.com",
      "created": "2026-02-21T09:00:00Z",
      "key_prefix": "7b2cd4e6"
    }
  }
}
```

- Keys stored as SHA-256 hashes (server never stores raw keys)
- Raw key shown once at generation time, never retrievable again
- Key store persists across container restarts via mounted volume

### What This Does and Doesn't Solve

| Concern | Solved? | How |
|---------|---------|-----|
| Open server on network | ✅ | Every request requires valid API key |
| Unauthorized key generation | ✅ | Admin endpoints are localhost-only |
| Key rotation | ✅ | Revoke + regenerate without restart |
| Audit trail | ✅ | Key store records who owns each key |
| Key sharing between users | ❌ | Cannot be technically prevented — mitigated by audit logs and revocation |
| Key leaking externally | ✅ | Revoke immediately, no restart needed |

### stdio Transport

Exempt from API key. The user runs the MCP server as a local process — they already have full access to the binary, the environment, and the GCM credentials. An API key adds nothing.
