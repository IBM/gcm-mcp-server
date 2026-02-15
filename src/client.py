#!/usr/bin/env python3
"""
GCM Authentication - Hybrid OAuth2 + Browser OIDC

Production-grade authentication for IBM Guardium Cryptographic Manager.

Supports two authentication methods:
1. OAuth2 Direct Token (requires Keycloak client credentials)
2. Browser-based OIDC (fallback, always works)

Flow (per IBM docs):
1. Get access token from OIDC Provider (Keycloak)
2. Authorize via /api/v2/authorization endpoint
3. Use Bearer token for all API calls
4. Refresh token before expiry
"""

import requests
import urllib3
import json
import os
import re
import base64
from urllib.parse import urljoin
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

urllib3.disable_warnings()


class GCMClient:
    """
    GCM API Client with OAuth2/OIDC Authentication.
    
    Environment Variables:
        GCM_HOST: GCM server hostname/IP
        GCM_API_PORT: GCM API port (default: 31443)
        GCM_KEYCLOAK_PORT: Keycloak port (default: 30443)
        GCM_USERNAME: Service account username
        GCM_PASSWORD: Service account password
        GCM_CLIENT_ID: OAuth2 client ID (default: admin)
        GCM_CLIENT_SECRET: OAuth2 client secret (default: password)
        GCM_AUTH_MODE: 'oauth2' or 'browser' (default: auto-detect)
        GCM_VERIFY_SSL: Verify SSL certificates (default: false)
    """
    
    def __init__(
        self,
        host: Optional[str] = None,
        api_port: int = 31443,
        keycloak_port: int = 30443,
        verify_ssl: bool = False,
        timeout: int = 30
    ):
        # Configuration from params or environment
        self.host = host or os.environ.get('GCM_HOST', 'localhost')
        self.api_port = int(os.environ.get('GCM_API_PORT', api_port))
        self.keycloak_port = int(os.environ.get('GCM_KEYCLOAK_PORT', keycloak_port))
        self.verify_ssl = os.environ.get('GCM_VERIFY_SSL', str(verify_ssl)).lower() == 'true'
        self.timeout = timeout
        self.auth_mode = os.environ.get('GCM_AUTH_MODE', 'auto')
        
        # URLs
        self.base_url = f"https://{self.host}:{self.api_port}"
        self.keycloak_url = f"https://{self.host}:{self.keycloak_port}"
        self.token_endpoint = f"{self.keycloak_url}/realms/gcmrealm/protocol/openid-connect/token"
        
        # OAuth2 client credentials
        self.client_id = os.environ.get('GCM_CLIENT_ID', 'admin')
        self.client_secret = os.environ.get('GCM_CLIENT_SECRET', 'password')
        
        # Session
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        
        # Token state
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        self.authenticated = False
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
        """
        Authenticate using OAuth2 Password Grant (direct Keycloak token endpoint).
        """
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
        """
        Authenticate using browser-based OIDC flow (follows redirects, parses forms).
        """
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
    
    def _ensure_token(self) -> bool:
        """Ensure we have a valid token."""
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
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication."""
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # Add Bearer token if using OAuth2 (not browser session)
        if self.access_token and self.access_token != "SESSION_COOKIE_AUTH":
            headers['Authorization'] = f'Bearer {self.access_token}'
        
        return headers
    
    # ==================== API Methods ====================
    
    def get(self, endpoint: str, params: Optional[Dict] = None) -> requests.Response:
        """HTTP GET request."""
        self._ensure_token()
        return self.session.get(
            f"{self.base_url}{endpoint}",
            params=params,
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
    
    def post(self, endpoint: str, data: Optional[Dict] = None) -> requests.Response:
        """HTTP POST request."""
        self._ensure_token()
        return self.session.post(
            f"{self.base_url}{endpoint}",
            json=data,
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
    
    def put(self, endpoint: str, data: Optional[Dict] = None) -> requests.Response:
        """HTTP PUT request."""
        self._ensure_token()
        return self.session.put(
            f"{self.base_url}{endpoint}",
            json=data,
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
    
    def delete(self, endpoint: str) -> requests.Response:
        """HTTP DELETE request."""
        self._ensure_token()
        return self.session.delete(
            f"{self.base_url}{endpoint}",
            headers=self._get_auth_headers(),
            timeout=self.timeout
        )
    
    def upload(self, endpoint: str, file_path: str, file_field: str = 'file') -> requests.Response:
        """Upload a file."""
        self._ensure_token()
        with open(file_path, 'rb') as f:
            files = {file_field: (os.path.basename(file_path), f)}
            headers = {'Accept': 'application/json'}
            if self.access_token and self.access_token != "SESSION_COOKIE_AUTH":
                headers['Authorization'] = f'Bearer {self.access_token}'
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
