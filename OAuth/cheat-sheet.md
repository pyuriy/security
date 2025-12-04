# OAuth 2.0 Cheat Sheet with Python

OAuth 2.0 (RFC 6749) is an authorization framework enabling third-party applications to obtain limited access to HTTP services on behalf of a resource owner. It focuses on authorization (not authentication, though often paired with OpenID Connect). Use it for secure API access without sharing credentials.

## Key Concepts
| Term              | Description |
|-------------------|-------------|
| **Resource Owner** | User who owns the data (e.g., end-user). |
| **Client**        | Application requesting access (e.g., your Python app). |
| **Authorization Server (AS)** | Server issuing tokens after user consent (e.g., Google, Auth0). |
| **Resource Server (RS)** | Server hosting protected resources (e.g., API endpoint). |
| **Access Token**  | Credential representing authorization (usually short-lived). |
| **Refresh Token** | Long-lived token to obtain new access tokens. |
| **Scope**         | Permissions requested (e.g., `read:email`). |
| **Redirect URI**  | Client's endpoint for AS callbacks. |
| **State**         | Opaque value to prevent CSRF (recommended). |

**Extensions**: PKCE (RFC 7636) for public clients; DPoP/mTLS for token binding.

## Python Libraries
- **Authlib**: Modern, full-featured (client/server). Supports all flows, PKCE, OIDC. Install: `pip install authlib`.
- **requests-oauthlib**: Lightweight for `requests` integration. Install: `pip install requests-oauthlib`.
- **Avoid**: Older libs like `python-social-auth` (deprecated).

Example setup (Authlib client):
```python
from authlib.integrations.requests_client import OAuth2Session

client_id = 'your_client_id'
client_secret = 'your_client_secret'  # For confidential clients
server_metadata = {
    'authorization_endpoint': 'https://example.com/auth',
    'token_endpoint': 'https://example.com/token',
    'userinfo_endpoint': 'https://example.com/userinfo',  # Optional
}
client = OAuth2Session(client_id, client_secret, scope='read:email', server_metadata=server_metadata)
```

## Grant Types / Flows
OAuth 2.0 defines flows (grant types) for different scenarios. Use **Authorization Code + PKCE** for most web/mobile apps (secure, supports public clients).

### 1. Authorization Code Flow (Recommended for User-Involved Apps)
User authenticates via browser redirect; client exchanges code for token. Use PKCE for public clients (e.g., SPAs, mobile).

#### Authorization Request (GET to AS)
| Parameter              | Required | Example Value | Notes |
|------------------------|----------|---------------|-------|
| `response_type`        | Yes     | `code`       | Fixed. |
| `client_id`            | Yes     | `abc123`     | Your app ID. |
| `redirect_uri`         | No      | `https://client.com/cb` | Must match registered URI. |
| `scope`                | No      | `read:email` | Space-separated. |
| `state`                | Rec.    | `xyz789`     | CSRF protection (random string). |
| `code_challenge`       | PKCE    | `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` | SHA256(base64(code_verifier)). |
| `code_challenge_method`| PKCE    | `S256`       | Or `plain` (insecure). |

**Python (Generate PKCE - Authlib/Stdlib)**:
```python
import secrets
import hashlib
import base64

def generate_pkce(length=128):
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(length // 8 * 3 // 4)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge  # Use in session

code_verifier, code_challenge = generate_pkce()
# Store verifier securely (e.g., session)
```

**Python (Redirect User - Authlib)**:
```python
# In Flask/FastAPI route
authorization_url, state = client.create_authorization_url(
    scope='read:email', state=secrets.token_urlsafe(32),
    code_challenge=code_challenge, code_challenge_method='S256'
)
return redirect(authorization_url)  # User sees login/consent
```

#### Token Request (POST to AS)
| Parameter       | Required | Example Value | Notes |
|-----------------|----------|---------------|-------|
| `grant_type`    | Yes     | `authorization_code` | Fixed. |
| `code`          | Yes     | `SplxlOBeZQQYbYS6WXEqJz` | From redirect. |
| `redirect_uri`  | Yes     | `https://client.com/cb` | Match auth request. |
| `client_id`     | Yes     | `abc123`     | - |
| `code_verifier` | PKCE    | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` | Redeem verifier. |

**Python (Exchange Code - Authlib)**:
```python
# After redirect back to /cb?code=...&state=...
token = client.fetch_token(
    token_url=server_metadata['token_endpoint'],
    code=request.args['code'],
    code_verifier=code_verifier  # From session
)
print(token)  # {'access_token': '...', 'token_type': 'Bearer', ...}
```

#### Response
| Parameter      | Required | Example |
|----------------|----------|---------|
| `access_token` | Yes     | `ya29.a0AfH6SMD...` |
| `token_type`   | Yes     | `Bearer` |
| `expires_in`   | Rec.    | `3600` (seconds) |
| `refresh_token`| No      | `1//xEoDL4...` |
| `scope`        | No      | `read:email` |

**Use Token**:
```python
headers = {'Authorization': f'Bearer {token["access_token"]}'}
response = requests.get('https://api.example.com/user', headers=headers)
```

### 2. Client Credentials Flow (Machine-to-Machine, No User)
For server-to-server; confidential clients only.

#### Token Request (POST to AS)
| Parameter    | Required | Example |
|--------------|----------|---------|
| `grant_type` | Yes     | `client_credentials` |
| `scope`      | No      | `write:posts` |

**Python (Authlib)**:
```python
token = client.fetch_token(
    token_url=server_metadata['token_endpoint'],
    grant_type='client_credentials',
    scope='write:posts'
)
```

#### Response
Same as above (no refresh token typically).

### 3. Refresh Token Flow
Renew expired access tokens.

#### Token Request (POST to AS)
| Parameter       | Required | Example |
|-----------------|----------|---------|
| `grant_type`    | Yes     | `refresh_token` |
| `refresh_token` | Yes     | `1//xEoDL4...` |
| `scope`         | No      | `read:email` |

**Python (Authlib)**:
```python
new_token = client.fetch_token(
    token_url=server_metadata['token_endpoint'],
    refresh_token=token['refresh_token'],
    grant_type='refresh_token'
)
token = new_token  # Update stored token
```

#### Response
Same as access token response.

**Avoid**: Resource Owner Password Credentials (exposes user creds); Implicit (exposes tokens in URL).

## Error Handling
Common errors (JSON response):
| Error Code          | Description |
|---------------------|-------------|
| `invalid_request`   | Malformed request. |
| `invalid_client`    | Auth failed. |
| `invalid_grant`     | Bad code/token. |
| `unauthorized_client`| Client not allowed. |
| `access_denied`     | User denied. |

**Python**:
```python
try:
    token = client.fetch_token(...)
except Exception as e:  # Authlib raises OAuthError
    print(e.error)  # e.g., 'invalid_grant'
```

## Security Best Practices (OWASP)
| Practice | Why/How |
|----------|---------|
| **Use PKCE** | Prevents code interception; always for public clients. Enforce `code_verifier`. |
| **State/Nonce** | CSRF protection; bind to user session. |
| **TLS Everywhere** | Encrypt all endpoints; no plain HTTP redirects. |
| **Sender-Constrain Tokens** | Use mTLS/DPoP to bind tokens to client. |
| **Minimal Scopes** | Request only needed perms; validate on RS. |
| **Refresh Rotation** | Issue new refresh token on use; bind to client. |
| **Audience Restriction** | Limit tokens to specific RS via `aud` claim. |
| **Avoid Implicit** | Use Code Flow; tokens in URLs are risky. |
| **Client Auth** | Prefer asymmetric (e.g., private_key_jwt) over shared secrets. |
| **No User Creds** | Never store/use passwords in clients. |

**Common Pitfalls**:
- Open redirects (exfiltrate codes).
- Token replay (mitigate with constraints).
- Downgrades (enforce PKCE methods).

For server-side impl (e.g., Flask), see Authlib docs: Register grants, use `AuthorizationServer`.

## Resources
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [Authlib Docs](https://docs.authlib.org/en/latest/)
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)  
- [OAuth 2.0 Cheatsheet](https://mijolabs.github.io/oauth2-cheatsheet/)
