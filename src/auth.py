#!/usr/bin/env python3
"""GCM MCP Server — Token management (OAuth2/OIDC).

Handles all authentication flows for IBM Guardium Cryptographic Manager:
1. OAuth2 Direct Token (requires Keycloak client credentials)
2. Browser-based OIDC (fallback, always works)

Flow (per IBM docs):
1. Get access token from OIDC Provider (Keycloak)
2. Authorize via /api/v2/authorization endpoint
3. Use Bearer token for all API calls
4. Refresh token before expiry
"""

import base64
import re
from typing import Optional, Dict
from datetime import datetime, timedelta
from urllib.parse import urljoin

import requests

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class GCMAuth:
    """OAuth2/OIDC token management for GCM."""

    def __init__(
        self,
        base_url: str,
        keycloak_url: str,
        client_id: str,
        client_secret: str,
        auth_mode: str,
        session: requests.Session,
        timeout: int = 30,
    ):
        self.base_url = base_url
        self.keycloak_url = keycloak_url
        self.token_endpoint = f"{keycloak_url}/realms/gcmrealm/protocol/openid-connect/token"
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_mode = auth_mode
        self.session = session
        self.timeout = timeout

        # Token state
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        self.authenticated: bool = False
        self.user_id: Optional[str] = None

    def login(self, username: str, password: str) -> bool:
        """
        Authenticate to GCM.

        Tries OAuth2 direct token first, falls back to browser OIDC if needed.
        """
        # Try OAuth2 direct token first (faster, cleaner)
        if self.auth_mode in ('auto', 'oauth2'):
            if self._login_oauth2(username, password):
                return True
            if self.auth_mode == 'oauth2':
                return False  # Don't fallback if explicitly set

        # Fallback to browser-based OIDC
        if self.auth_mode in ('auto', 'browser'):
            return self._login_browser_oidc(username, password)

        return False

    # ==================== OAuth2 Direct Token ====================

    def _login_oauth2(self, username: str, password: str) -> bool:
        """Authenticate using OAuth2 Password Grant (direct Keycloak token endpoint)."""
        print(f"🔐 Authenticating as: {username} (OAuth2)")

        try:
            # Step 1: Get token from Keycloak
            print("  [1/2] Getting OAuth2 token...")

            # Build Basic Auth header for client credentials
            client_creds = f"{self.client_id}:{self.client_secret}"
            basic_auth = base64.b64encode(client_creds.encode()).decode()

            token_data = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'scope': 'openid'
            }

            response = self.session.post(
                self.token_endpoint,
                data=token_data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': f'Basic {basic_auth}'
                },
                timeout=self.timeout
            )

            if response.status_code != 200:
                print(f"  ✗ Token request failed: {response.status_code}")
                return False

            token_response = response.json()
            self.access_token = token_response.get('access_token')
            self.refresh_token = token_response.get('refresh_token')

            expires_in = token_response.get('expires_in', 300)
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)

            print(f"  ✓ Token obtained (expires in {expires_in}s)")

            # Step 2: Authorize with GCM
            return self._authorize_token()

        except Exception as e:
            print(f"  ✗ OAuth2 error: {e}")
            return False

    # ==================== Browser-based OIDC ====================

    def _login_browser_oidc(self, username: str, password: str) -> bool:
        """Authenticate using browser-based OIDC flow (follows redirects, parses forms)."""
        print(f"🔐 Authenticating as: {username} (Browser OIDC)")

        try:
            # Step 1: Access protected endpoint to initiate OIDC
            print("  [1/4] Initiating OIDC flow...")
            response = self.session.get(
                f"{self.base_url}/ibm/usermanagement/api/v1/system/version-info",
                allow_redirects=False,
                timeout=self.timeout
            )

            if response.status_code != 302:
                print(f"  ✗ Expected 302, got {response.status_code}")
                return False

            pkms_url = response.headers.get('Location')
            print(f"  ✓ Got PKMS redirect")

            # Step 2: Follow to PKMS OIDC endpoint
            print("  [2/4] Following PKMS OIDC...")
            response = self.session.get(
                pkms_url,
                allow_redirects=False,
                timeout=self.timeout
            )

            keycloak_url = response.headers.get('Location')
            if not keycloak_url:
                print(f"  ✗ No Keycloak redirect")
                return False
            print(f"  ✓ Got Keycloak redirect")

            # Step 3: Get Keycloak login page and submit credentials
            print("  [3/4] Submitting credentials...")
            response = self.session.get(
                keycloak_url,
                allow_redirects=True,
                timeout=self.timeout
            )

            form_action = self._extract_form_action(response.text, response.url)
            if not form_action:
                print("  ✗ Could not find login form")
                return False

            response = self.session.post(
                form_action,
                data={'username': username, 'password': password},
                allow_redirects=True,
                timeout=self.timeout
            )

            if 'Invalid username or password' in response.text:
                print("  ✗ Invalid credentials")
                return False

            print(f"  ✓ Credentials accepted")

            # Step 4: Extract token from cookies/session and authorize
            print("  [4/4] Authorizing session...")

            # The browser flow sets session cookies, we need to get a token
            # Try to call authorization endpoint to validate
            auth_response = self.session.post(
                f"{self.base_url}/ibm/usermanagement/api/v2/authorization",
                json={"tenantId": ""},
                headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                timeout=self.timeout
            )

            if auth_response.status_code == 200:
                auth_data = auth_response.json()
                if auth_data.get('status') == 'OK':
                    self.user_id = auth_data.get('uid')
                    self.authenticated = True
                    # Note: Browser flow uses session cookies, not Bearer token
                    self.access_token = "SESSION_COOKIE_AUTH"
                    print(f"  ✓ Authenticated! User: {self.user_id}")
                    return True

            print(f"  ✗ Authorization failed")
            return False

        except Exception as e:
            print(f"  ✗ Browser OIDC error: {e}")
            return False

    def _extract_form_action(self, html: str, base_url: str) -> Optional[str]:
        """Extract login form action URL from HTML."""
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                form = soup.find('form', {'id': 'kc-form-login'})
                if form and form.get('action'):
                    action = form['action']
                    if not action.startswith('http'):
                        action = urljoin(base_url, action)
                    return action.replace('&amp;', '&')
            except:
                pass

        # Fallback to regex
        match = re.search(r'action="([^"]+)"', html)
        if match:
            action = match.group(1).replace('&amp;', '&')
            if not action.startswith('http'):
                action = urljoin(base_url, action)
            return action

        return None

    # ==================== Token Management ====================

    def _authorize_token(self) -> bool:
        """Authorize access token with GCM."""
        print("  [2/2] Authorizing with GCM...")

        try:
            response = self.session.post(
                f"{self.base_url}/ibm/usermanagement/api/v2/authorization",
                json={"tenantId": ""},
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': f'Bearer {self.access_token}'
                },
                timeout=self.timeout
            )

            if response.status_code != 200:
                print(f"  ✗ Authorization failed: {response.status_code}")
                return False

            auth_data = response.json()
            if auth_data.get('status') != 'OK':
                print(f"  ✗ Authorization status: {auth_data.get('status')}")
                return False

            self.user_id = auth_data.get('uid')
            self.authenticated = True
            print(f"  ✓ Authenticated! User: {self.user_id}")
            return True

        except Exception as e:
            print(f"  ✗ Authorization error: {e}")
            return False

    def refresh_access_token(self) -> bool:
        """Refresh access token using refresh_token."""
        if not self.refresh_token:
            return False

        try:
            client_creds = f"{self.client_id}:{self.client_secret}"
            basic_auth = base64.b64encode(client_creds.encode()).decode()

            response = self.session.post(
                self.token_endpoint,
                data={
                    'grant_type': 'refresh_token',
                    'refresh_token': self.refresh_token
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': f'Basic {basic_auth}'
                },
                timeout=self.timeout
            )

            if response.status_code != 200:
                return False

            token_response = response.json()
            self.access_token = token_response.get('access_token')
            self.refresh_token = token_response.get('refresh_token', self.refresh_token)

            expires_in = token_response.get('expires_in', 300)
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)

            return True
        except:
            return False

    def ensure_token(self) -> bool:
        """Ensure we have a valid token, refreshing if needed."""
        if not self.authenticated:
            return False

        # Browser auth uses session cookies, no token refresh needed
        if self.access_token == "SESSION_COOKIE_AUTH":
            return True

        # Check if token is about to expire
        if self.token_expiry and datetime.now() >= self.token_expiry:
            if not self.refresh_access_token():
                self.authenticated = False
                return False

        return True

    def get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication."""
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        # Add Bearer token if using OAuth2 (not browser session)
        if self.access_token and self.access_token != "SESSION_COOKIE_AUTH":
            headers['Authorization'] = f'Bearer {self.access_token}'

        return headers

    def logout(self):
        """Clear authentication state."""
        self.authenticated = False
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.user_id = None
