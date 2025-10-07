## Overview

This document explains how Google OAuth 2.0 authentication works in our FastAPI application, the libraries used, and the complete authentication flow.

## Architecture

The application implements OAuth 2.0 Authorization Code Flow with OpenID Connect (OIDC) for user authentication. This is the most secure OAuth flow for web applications as it never exposes tokens to the browser.

## Required Libraries

### Core Dependencies

1. **FastAPI** (`fastapi==0.104.1`)
    - Modern Python web framework
    - Provides the base application structure and routing
    - Handles HTTP requests and responses
2. **Authlib** (`authlib==1.2.1`)
    - OAuth/OIDC client library
    - Handles the OAuth 2.0 protocol implementation
    - Manages token exchange and user info retrieval
    - Provides integration with Starlette/FastAPI
3. **Starlette** (`starlette==0.27.0`)
    - ASGI framework (FastAPI is built on top of Starlette)
    - Provides middleware support, including SessionMiddleware
    - Handles session management

## OAuth 2.0 Flow Explanation

### Step 1: User Initiates Login

```
User clicks "Login with Google" → GET /login

```

**What happens:**

- User is redirected to the `/login/google` endpoint
- Application creates an authorization URL pointing to Google's OAuth server
- Redirect URI is specified: `http://localhost:8000/auth/callback`
- Requested scopes: `openid email profile`

**Code:**

```python
@app.get("/login/google")
async def login(request: Request):
    redirect_uri = "http://localhost:8000/auth/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

```

### Step 2: Redirect to Google

```
Browser → Google OAuth Server (accounts.google.com)

```

**What happens:**

- User is redirected to Google's login page
- URL contains: client_id, redirect_uri, scope, response_type=code, state (CSRF token)
- User sees Google's consent screen
- User authenticates with Google credentials
- User grants permission to share profile information

### Step 3: Google Redirects Back

```
Google → http://localhost:8000/auth/callback?code=AUTHORIZATION_CODE&state=STATE

```

**What happens:**

- After successful authentication, Google redirects back to our callback URL
- URL includes an authorization code (short-lived, single-use)
- State parameter is included for CSRF protection

### Environment Variables

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
SECRET_KEY=your-random-secret-key-min-32-chars

```

### OAuth Configuration in Code

```python
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

```

```python
from starlette.requests import Request

@app.get("/login/google")
async def login_via_google(request: Request):
    redirect_uri = request.url_for('auth_via_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google")
async def auth_via_google(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user = token['userinfo']
    return dict(user)
```

## References

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [Authlib Documentation](https://docs.authlib.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
