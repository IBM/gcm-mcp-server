"""Two API keys must not share one GCM login."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from src import keystore
from src.tools import current_key, handle_api, handle_auth, state


class _Cookies:
    def clear(self):
        return None


class _Session:
    def __init__(self):
        self.cookies = _Cookies()


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.authenticated = False
        self.user_id = None
        self.base_url = "https://gcm.example"
        self.session = _Session()

    def login(self, username, password):
        self.authenticated = True
        self.user_id = username
        return True

    def _ensure_token(self):
        return self.authenticated


class SessionIsolationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._old_store = keystore.KEY_STORE_PATH
        keystore.KEY_STORE_PATH = str(Path(self.tmp.name) / "keys.json")
        self._old_client = __import__("src.tools", fromlist=["GCMClient"]).GCMClient
        import src.tools as tools
        tools.GCMClient = FakeClient
        state.client = None
        state.clients.clear()
        state.auth_times.clear()
        self.alice = keystore.generate_key("alice")
        self.bob = keystore.generate_key("bob")

    def tearDown(self):
        import src.tools as tools
        tools.GCMClient = self._old_client
        keystore.KEY_STORE_PATH = self._old_store
        self.tmp.cleanup()

    def _meta(self, raw_key):
        return keystore.validate_key(raw_key)

    def test_bob_cannot_use_alice_session(self):
        alice_token = current_key.set(self._meta(self.alice["key"]))
        try:
            login = asyncio.run(
                handle_auth({"action": "login", "username": "alice", "password": "secret"})
            )
        finally:
            current_key.reset(alice_token)
        self.assertIn("authenticated", login[0].text)

        bob_token = current_key.set(self._meta(self.bob["key"]))
        try:
            result = asyncio.run(
                handle_api({"service": "usermanagement", "operation": "users.list"})
            )
            status = asyncio.run(handle_auth({"action": "status"}))
        finally:
            current_key.reset(bob_token)

        body = json.loads(result[0].text)
        self.assertEqual(body["status"], 403)
        shown = json.loads(status[0].text)
        self.assertFalse(shown["authenticated"])
        self.assertNotEqual(shown.get("user_id"), "alice")

    def test_key_cannot_login_as_someone_else(self):
        token = current_key.set(self._meta(self.bob["key"]))
        try:
            result = asyncio.run(
                handle_auth({"action": "login", "username": "alice", "password": "secret"})
            )
        finally:
            current_key.reset(token)
        body = json.loads(result[0].text)
        self.assertEqual(body["status"], 403)


if __name__ == "__main__":
    unittest.main()
