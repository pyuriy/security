# OAuth 2.0 Hands-On Lab with Python

Welcome to this comprehensive lab on implementing OAuth 2.0 in Python! This guide builds on the OAuth cheat sheet, shifting from theory to practice. You'll implement client-side flows, handle security features like PKCE, and even set up a basic authorization server. By the end, you'll have working code for secure API access.

**Goals**:
- Understand and implement key OAuth flows.
- Practice secure coding with PKCE, state validation, and error handling.
- Test integrations with real providers (e.g., Google) and a local server.
- Debug common issues.

**Duration**: 4-6 hours, depending on experience.

## Prerequisites
- Python 3.8+ installed.
- Virtual environment: `python -m venv oauth-lab && source oauth-lab/bin/activate` (Linux/Mac) or `oauth-lab\Scripts\activate` (Windows).
- Install libraries: `pip install authlib requests flask pytest`.
- API keys: Sign up for a Google OAuth app at [Google Cloud Console](https://console.cloud.google.com/apis/credentials) (enable "Google+ API" or similar for testing). Note your `client_id`, `client_secret`, and set redirect URI to `http://localhost:5000/callback`.
- For local server: No external setup needed.

**Tips**:
- Run code in Jupyter or VS Code for easy testing.
- Use `pytest` for automated tests (included).
- All code is modular; copy-paste into files as noted.

## Lab 1: Authorization Code Flow Basics (30 min)
Implement a basic client that redirects users to Google for consent and fetches an access token.

### Step 1: Basic Client Setup
Create `oauth_client.py`:
```python
from authlib.integrations.requests_client import OAuth2Session
from flask import Flask, redirect, request, session  # For simple web server
import secrets
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session storage

# Google config (replace with yours)
CLIENT_ID = 'your_google_client_id'
CLIENT_SECRET = 'your_google_client_secret'
AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
SCOPE = ['https://www.googleapis.com/auth/userinfo.email']  # Email scope
REDIRECT_URI = 'http://localhost:5000/callback'

client = OAuth2Session(
    CLIENT_ID, CLIENT_SECRET, scope=SCOPE, redirect_uri=REDIRECT_URI
)

@app.route('/')
def index():
    authorization_url, state = client.create_authorization_url(AUTH_URL)
    session['oauth_state'] = state  # Store for CSRF check
    return f'<a href="{authorization_url}">Login with Google</a>'

@app.route('/callback')
def callback():
    if request.args['state'] != session['oauth_state']:
        return 'State mismatch! Possible CSRF attack.', 400
    token = client.fetch_token(
        TOKEN_URL, authorization_response=request.url,
        code=request.args['code']
    )
    session['token'] = token
    return f'Access Token: {token["access_token"]}<br><a href="/userinfo">Get User Info</a>'

@app.route('/userinfo')
def userinfo():
    token = session.get('token')
    if not token:
        return 'No token!', 401
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    resp = client.get('https://www.googleapis.com/oauth2/v1/userinfo', headers=headers)
    return resp.json()

if __name__ == '__main__':
    app.run(debug=True)
```

### Step 2: Run and Test
- `python oauth_client.py`
- Visit `http://localhost:5000`, click login, consent on Google.
- After callback, click "Get User Info" → See JSON with email.

**Expected Output** (userinfo):
```json
{"id": "123...", "email": "user@example.com", "verified_email": true}
```

### Step 3: Exercise
- Modify to request `openid` scope (add to SCOPE list). What changes in the response?
- Add logging: Print `token` details (expires_in, scope).

**Test with Pytest** (create `test_lab1.py`):
```python
import pytest
from oauth_client import app

@pytest.fixture
def client():
    app.testing = True
    return app.test_client()

def test_index_redirect(client):
    rv = client.get('/')
    assert b'Login with Google' in rv.data
```
Run: `pytest test_lab1.py`.

**Common Issue**: "Redirect URI mismatch" → Ensure exact match in Google Console.

## Lab 2: Adding PKCE for Public Clients (45 min)
PKCE secures code exchange for non-confidential clients (e.g., mobile/SPA). Implement it to prevent authorization code interception.

### Step 1: PKCE Generator
Add to `oauth_client.py` (before routes):
```python
import hashlib
import base64

def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge

# In index route, modify:
@app.route('/')
def index():
    code_verifier, code_challenge = generate_pkce_pair()
    session['code_verifier'] = code_verifier
    authorization_url, state = client.create_authorization_url(
        AUTH_URL, code_challenge=code_challenge, code_challenge_method='S256'
    )
    session['oauth_state'] = state
    return f'<a href="{authorization_url}">Login with Google (PKCE)</a>'

# In callback, modify fetch_token:
@app.route('/callback')
def callback():
    if request.args['state'] != session['oauth_state']:
        return 'State mismatch!', 400
    code_verifier = session['code_verifier']
    token = client.fetch_token(
        TOKEN_URL, authorization_response=request.url,
        code=request.args['code'], code_verifier=code_verifier
    )
    # Clear session
    session.pop('code_verifier', None)
    session['token'] = token
    return f'PKCE Token: {token["access_token"]}'
```

### Step 2: Test
- Restart server, login. Check Google Console logs for PKCE params.
- Verify: No client_secret needed in fetch_token for public clients (simulate by commenting it out in OAuth2Session).

### Step 3: Exercise
- Implement `plain` method (insecure): Set `code_challenge_method='plain'`, `code_challenge=code_verifier`. Why is S256 better?
- Challenge: Simulate attack—omit PKCE, observe if Google rejects (it enforces for public clients).

**Security Note**: Always use PKCE for browser/mobile. Test: Use browser dev tools to inspect URL (no secrets exposed).

## Lab 3: Refresh Tokens and Token Management (30 min)
Handle token expiration by refreshing automatically.

### Step 1: Add Refresh Logic
In `oauth_client.py`, add route:
```python
@app.route('/refresh')
def refresh():
    token = session.get('token')
    if not token or 'refresh_token' not in token:
        return 'No refresh token!', 401
    new_token = client.refresh_token(
        TOKEN_URL, refresh_token=token['refresh_token']
    )
    session['token'] = new_token
    return f'Refreshed: Expires in {new_token["expires_in"]}s'

# Auto-refresh in userinfo:
@app.route('/userinfo')
def userinfo():
    token = session.get('token')
    if client.token_expired(token):
        token = client.refresh_token(TOKEN_URL, refresh_token=token['refresh_token'])
        session['token'] = token
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    resp = client.get('https://www.googleapis.com/oauth2/v1/userinfo', headers=headers)
    return resp.json()
```

### Step 2: Test
- Get token, wait ~1 hour (or mock expiration by setting `token['expires_at'] = time.time() - 1`).
- Hit `/userinfo` → Auto-refreshes.
- Manually: `/refresh`.

### Step 3: Exercise
- Store tokens in a file/DB (use `json.dump` to `tokens.json`).
- Challenge: Implement token rotation—log if new refresh_token issued.

**Pro Tip**: Use `client.register_response_hook` for auto-refresh on 401s.

## Lab 4: Client Credentials Flow (M2M) (20 min)
For server-to-server, no user involvement.

### Step 1: M2M Client
Create `m2m_client.py`:
```python
from authlib.integrations.requests_client import OAuth2Session

CLIENT_ID = 'your_m2m_client_id'  # From a provider like Auth0
CLIENT_SECRET = 'your_m2m_client_secret'
TOKEN_URL = 'https://your-provider.com/token'
SCOPE = 'write:api'

client = OAuth2Session(CLIENT_ID, CLIENT_SECRET, scope=SCOPE)

token = client.fetch_token(
    TOKEN_URL, grant_type='client_credentials'
)
headers = {'Authorization': f'Bearer {token["access_token"]}'}
resp = client.get('https://api.example.com/protected', headers=headers)
print(resp.json())
```

### Step 2: Local Test
Use a mock API (or Postman Echo). For real: Set up Auth0 machine-to-machine app.

### Step 3: Exercise
- Add scope validation: Assert `SCOPE` in `token['scope']`.
- Challenge: Implement token caching with TTL (use `cachetools` if installed, or dict with expiry).

## Lab 5: Error Handling and Security Auditing (45 min)
Handle errors gracefully and audit for vulns.

### Step 1: Enhanced Error Handler
In `oauth_client.py`:
```python
from authlib.oauth2 import OAuth2Error

@app.route('/callback')
def callback():
    try:
        # ... existing code ...
        token = client.fetch_token(...)
    except OAuth2Error as e:
        return f'OAuth Error: {e.error} - {e.description}', 400
    except Exception as e:
        return f'Unexpected: {str(e)}', 500
```

### Step 2: Security Audit Checklist
Run these tests:
- **CSRF**: Tamper state in callback URL → Should fail.
- **Invalid Code**: Manually POST bad code to `/callback` → `invalid_grant`.
- **Scope Overreach**: Request extra scope, deny on Google → `access_denied`.
- **TLS Check**: Change REDIRECT_URI to `http://` (if allowed) → Warn in console.

Add logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
# In routes: logging.info(f"Token fetched for scope: {token['scope']}")
```

### Step 3: Exercise
- Implement nonce for OIDC (add to auth URL, validate in ID token if using OpenID).
- Challenge: Use `bandit` or `safety` (pip install) to scan code: `bandit oauth_client.py`.

**Pytest for Errors** (`test_lab5.py`):
```python
def test_invalid_state(client):
    rv = client.get('/callback?state=wrong')
    assert b'State mismatch' in rv.data
```

## Lab 6: Building a Simple OAuth Provider (Authorization Server) (60 min)
Use Authlib to create a local AS. Clients can auth against it.

### Step 1: Provider Setup
Create `oauth_provider.py`:
```python
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant
from authlib.oauth2.rfc6750 import BearerTokenValidator
from flask import Flask, jsonify, request, redirect, url_for
from werkzeug.security import generate_password_hash
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.debug = True

# In-memory DB (use SQLAlchemy for prod)
CLIENT_DB = {'client1': {'client_id': 'client1', 'client_secret': generate_password_hash('secret'), 'redirect_uris': ['http://localhost:5001/cb']}}
TOKEN_DB = {}
USER_DB = {'user1': {'username': 'user1', 'password': generate_password_hash('pass')}}

class AuthCodeGrant(AuthorizationCodeGrant):
    def authenticate_user(self, client):
        user = request.form.get('user')
        if user in USER_DB:
            return user  # Simulate auth
        return None

    def create_authorization_code(self, client, grant_user, request):
        code = super().create_authorization_code(client, grant_user, request)
        TOKEN_DB[code] = {'user': grant_user, 'client': client['client_id']}
        return code

    def authenticate_code(self, code):
        return TOKEN_DB.get(code)

server = AuthorizationServer(app, query_client=CLIENT_DB)
server.register_grant(AuthorizationCodeGrant)

# Protected endpoint
@app.route('/api/user')
@server.protect_resource
def user():
    return jsonify({'user': request.user})

if __name__ == '__main__':
    app.run(port=5000)
```

### Step 2: Client to Test Provider
Create `test_client.py` (runs on port 5001):
```python
from flask import Flask, redirect, request
from authlib.integrations.requests_client import OAuth2Session

app = Flask(__name__)
app.secret_key = 'test'

CLIENT_ID = 'client1'
CLIENT_SECRET = 'secret'  # Hashed in provider
AUTH_URL = 'http://localhost:5000/oauth/authorize'
TOKEN_URL = 'http://localhost:5000/oauth/token'
REDIRECT_URI = 'http://localhost:5001/cb'

client = OAuth2Session(CLIENT_ID, CLIENT_SECRET, redirect_uri=REDIRECT_URI)

@app.route('/')
def index():
    auth_url, _ = client.create_authorization_url(AUTH_URL)
    return f'<a href="{auth_url}">Auth with Local Server</a> (user=user1&pass=pass)'

@app.route('/cb')
def cb():
    token = client.fetch_token(TOKEN_URL, authorization_response=request.url)
    resp = client.get('http://localhost:5000/api/user', token=token)
    return resp.json()

if __name__ == '__main__':
    app.run(port=5001)
```

### Step 3: Run and Test
- Terminal 1: `python oauth_provider.py`
- Terminal 2: `python test_client.py`
- Visit `http://localhost:5001`, click auth, submit form with user1/pass.
- Callback → See `{'user': 'user1'}`.

### Step 4: Exercise
- Add PKCE support: Override `create_authorization_url` to include challenge.
- Add refresh grant: Register `RefreshTokenGrant`.
- Challenge: Integrate JWT tokens (use `PyJWT`): Sign ID tokens with `server.create_id_token`.

**Debug Tip**: Check `/oauth/token` errors in provider logs.

## Final Challenges
1. **Integration**: Hook Lab 1 client to your provider (update URLs).
2. **Security Audit**: Run OWASP ZAP on localhost → Fix any medium vulns.
3. **Scale**: Add DB persistence (SQLite) for tokens/clients.
4. **OIDC Extension**: Add discovery endpoint (`/.well-known/openid-configuration`).

## Wrap-Up
Commit your code to Git. Review: Did you implement PKCE everywhere? Test with `pytest -v`. For production, audit with tools like `oauth2-proxy`.

**Resources**:
- Authlib Examples: [GitHub Repo](https://github.com/lepture/authlib/tree/master/examples)
- Google OAuth Docs: [Developers Guide](https://developers.google.com/identity/protocols/oauth2)
- Test Provider: Use [ORCID Sandbox](https://sandbox.orcid.org) for more scopes.

Stuck? Debug with `pdb` or share errors. Happy coding!
