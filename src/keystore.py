#!/usr/bin/env python3
"""GCM MCP Server — API Key Store.

Manages per-user API keys with persistent JSON storage.
Keys are stored as SHA-256 hashes — raw keys are never persisted.
Admin operations (create/list/revoke) are exposed via localhost-only endpoints.
"""

import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.config import get_logger

logger = get_logger("gcm-mcp-keystore")

# Default key store path — can be overridden via GCM_MCP_KEY_STORE_PATH env var
_DEFAULT_KEY_STORE_PATH = "/data/keys.json"
KEY_STORE_PATH = os.environ.get("GCM_MCP_KEY_STORE_PATH", _DEFAULT_KEY_STORE_PATH)

# Thread lock for concurrent access
_lock = threading.Lock()


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash a raw API key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _key_prefix(raw_key: str) -> str:
    """First 8 characters of the raw key — used as human-readable identifier."""
    return raw_key[:8]


def _load_store() -> dict:
    """Load the key store from disk. Returns empty store if file doesn't exist."""
    path = Path(KEY_STORE_PATH)
    if not path.exists():
        return {"keys": {}}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        # Ensure expected structure
        if "keys" not in data:
            data["keys"] = {}
        return data
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to read key store at {KEY_STORE_PATH}: {e}")
        return {"keys": {}}


def _save_store(store: dict) -> None:
    """Persist the key store to disk."""
    path = Path(KEY_STORE_PATH)
    # Create parent directories if needed
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "w") as f:
            json.dump(store, f, indent=2)
        # Restrict file permissions (owner read/write only)
        os.chmod(KEY_STORE_PATH, 0o600)
    except IOError as e:
        logger.error(f"Failed to write key store at {KEY_STORE_PATH}: {e}")
        raise


def generate_key(user: str) -> dict:
    """Generate a new API key for a user.

    Returns dict with the raw key (shown once), user, created timestamp,
    and key_prefix for future reference.
    """
    raw_key = secrets.token_hex(32)  # 64-char hex string
    hashed = _hash_key(raw_key)
    prefix = _key_prefix(raw_key)
    now = datetime.now(timezone.utc).isoformat()

    with _lock:
        store = _load_store()
        store["keys"][hashed] = {
            "user": user,
            "created": now,
            "key_prefix": prefix,
        }
        _save_store(store)

    logger.info(f"Generated API key for user '{user}' (prefix: {prefix})")

    return {
        "key": raw_key,
        "user": user,
        "created": now,
        "key_prefix": prefix,
    }


def validate_key(raw_key: str) -> Optional[dict]:
    """Validate a raw API key against the store.

    Returns the key metadata (user, created, key_prefix) if valid, None otherwise.
    """
    if not raw_key:
        return None

    hashed = _hash_key(raw_key)

    with _lock:
        store = _load_store()

    entry = store["keys"].get(hashed)
    if entry:
        logger.debug(f"Key validated for user '{entry['user']}' (prefix: {entry['key_prefix']})")
    return entry


def list_keys() -> list:
    """List all active keys (masked — no raw keys or hashes exposed)."""
    with _lock:
        store = _load_store()

    return [
        {
            "key_prefix": meta["key_prefix"],
            "user": meta["user"],
            "created": meta["created"],
        }
        for meta in store["keys"].values()
    ]


def revoke_key(key_prefix: str) -> Optional[dict]:
    """Revoke a key by its prefix. Returns the revoked key metadata, or None if not found."""
    with _lock:
        store = _load_store()
        # Find the key entry by prefix
        target_hash = None
        target_meta = None
        for hashed, meta in store["keys"].items():
            if meta["key_prefix"] == key_prefix:
                target_hash = hashed
                target_meta = meta
                break

        if target_hash is None:
            return None

        del store["keys"][target_hash]
        _save_store(store)

    logger.info(f"Revoked API key for user '{target_meta['user']}' (prefix: {key_prefix})")
    return {"status": "revoked", "key_prefix": key_prefix, "user": target_meta["user"]}


def has_any_keys() -> bool:
    """Check if any keys exist in the store."""
    with _lock:
        store = _load_store()
    return len(store["keys"]) > 0
