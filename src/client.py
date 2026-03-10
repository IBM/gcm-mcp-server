#!/usr/bin/env python3
"""GCM MCP Server — HTTP client for IBM Guardium Cryptographic Manager.

Provides HTTP methods (GET, POST, PUT, DELETE) for the GCM API.
Authentication is delegated to the auth module.
"""

import json
import os
from typing import Optional, Dict, Any

import requests
import urllib3

from src import config
from src.auth import GCMAuth

urllib3.disable_warnings()


class GCMClient:
    """
    GCM API Client — HTTP only.

    Authentication is handled by GCMAuth.
    Configuration comes from src.config.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        api_port: Optional[int] = None,
        keycloak_port: Optional[int] = None,
        verify_ssl: Optional[bool] = None,
        timeout: int = 30,
    ):
        # Configuration from params or config module
        self.host = host or config.GCM_HOST
        self.api_port = api_port or config.GCM_API_PORT
        self.keycloak_port = keycloak_port or config.GCM_KEYCLOAK_PORT
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.GCM_VERIFY_SSL
        self.timeout = timeout

        # URLs
        self.base_url = f"https://{self.host}:{self.api_port}"
        self.keycloak_url = f"https://{self.host}:{self.keycloak_port}"

        # Session
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Auth (delegated to GCMAuth)
        self._auth = GCMAuth(
            base_url=self.base_url,
            keycloak_url=self.keycloak_url,
            client_id=config.GCM_CLIENT_ID,
            client_secret=config.GCM_CLIENT_SECRET,
            auth_mode=config.GCM_AUTH_MODE,
            session=self.session,
            timeout=self.timeout,
        )

    # ==================== Auth Properties (backward compat) ====================

    @property
    def authenticated(self) -> bool:
        return self._auth.authenticated

    @authenticated.setter
    def authenticated(self, value: bool):
        self._auth.authenticated = value

    @property
    def user_id(self) -> Optional[str]:
        return self._auth.user_id

    @user_id.setter
    def user_id(self, value: Optional[str]):
        self._auth.user_id = value

    @property
    def access_token(self) -> Optional[str]:
        return self._auth.access_token

    def login(self, username: str, password: str) -> bool:
        """Authenticate to GCM. Delegates to GCMAuth."""
        return self._auth.login(username, password)

    def _ensure_token(self) -> bool:
        """Ensure valid token. Delegates to GCMAuth."""
        return self._auth.ensure_token()

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get auth headers. Delegates to GCMAuth."""
        return self._auth.get_auth_headers()

    def _reauth(self) -> bool:
        """Re-authenticate using credentials from config (called on 401)."""
        username = config.GCM_USERNAME
        password = config.GCM_PASSWORD
        if not username or not password:
            return False
        return self._auth.login(username, password)

    # ==================== HTTP Methods ====================

    def get(self, endpoint: str, params: Optional[Dict] = None) -> requests.Response:
        """HTTP GET request. Auto-retries once on 401 (token expiry)."""
        self._ensure_token()
        response = self.session.get(
            f"{self.base_url}{endpoint}",
            params=params,
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
        if response.status_code == 401 and self._reauth():
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                params=params,
                headers=self._get_auth_headers(),
                timeout=self.timeout
            )
        return response

    def post(self, endpoint: str, data: Optional[Dict] = None) -> requests.Response:
        """HTTP POST request. Auto-retries once on 401 (token expiry)."""
        self._ensure_token()
        response = self.session.post(
            f"{self.base_url}{endpoint}",
            json=data,
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
        if response.status_code == 401 and self._reauth():
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                json=data,
                headers=self._get_auth_headers(),
                timeout=self.timeout
            )
        return response

    def put(self, endpoint: str, data: Optional[Dict] = None) -> requests.Response:
        """HTTP PUT request. Auto-retries once on 401 (token expiry)."""
        self._ensure_token()
        response = self.session.put(
            f"{self.base_url}{endpoint}",
            json=data,
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
        if response.status_code == 401 and self._reauth():
            response = self.session.put(
                f"{self.base_url}{endpoint}",
                json=data,
                headers=self._get_auth_headers(),
                timeout=self.timeout
            )
        return response

    def delete(self, endpoint: str) -> requests.Response:
        """HTTP DELETE request. Auto-retries once on 401 (token expiry)."""
        self._ensure_token()
        response = self.session.delete(
            f"{self.base_url}{endpoint}",
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
        if response.status_code == 401 and self._reauth():
            response = self.session.delete(
                f"{self.base_url}{endpoint}",
                headers=self._get_auth_headers(),
                timeout=self.timeout
            )
        return response

    def upload(self, endpoint: str, file_path: str, file_field: str = 'file') -> requests.Response:
        """Upload a file."""
        self._ensure_token()
        with open(file_path, 'rb') as f:
            files = {file_field: (os.path.basename(file_path), f)}
            headers = {'Accept': 'application/json'}
            if self._auth.access_token and self._auth.access_token != "SESSION_COOKIE_AUTH":
                headers['Authorization'] = f'Bearer {self._auth.access_token}'
            return self.session.post(
                f"{self.base_url}{endpoint}",
                files=files,
                headers=headers,
                timeout=self.timeout
            )

    # ==================== Convenience Methods ====================

    def get_version_info(self) -> Dict:
        """Get GCM version information."""
        response = self.get('/ibm/usermanagement/api/v1/system/version-info')
        return response.json() if response.status_code == 200 else {}

    def get_tde_clients(self, page: int = 0, size: int = 20) -> Dict:
        """Get TDE clients list."""
        response = self.get(f'/ibm/encryption/db/tde/api/v1/client-inventory?page={page}&size={size}')
        return response.json() if response.status_code == 200 else {}

    def get_users(self, page: int = 1, size: int = 10) -> Dict:
        """Get users list."""
        response = self.get(f'/ibm/usermanagement/api/v1/users?pageNumber={page}&pageSize={size}')
        return response.json() if response.status_code == 200 else {}


# ==================== Test ====================

if __name__ == "__main__":
    print("=" * 60)
    print("GCM Authentication Test")
    print("=" * 60 + "\n")

    host = os.environ.get('GCM_HOST', '9.30.108.86')
    username = os.environ.get('GCM_USERNAME', 'gcmadmin')
    password = os.environ.get('GCM_PASSWORD')

    if not password:
        print("❌ Set GCM_PASSWORD environment variable")
        exit(1)

    client = GCMClient(host=host)

    if client.login(username, password):
        print("\n✅ SUCCESS!")
        print(f"User: {client.user_id}")

        print("\n📡 Testing API:")
        data = client.get_version_info()
        print(f"Version: {json.dumps(data, indent=2)[:300]}")
    else:
        print("\n❌ FAILED")
