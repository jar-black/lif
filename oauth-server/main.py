"""OAuth 2.0 Authorization Server for LIF MCP Hub.

Implements Authorization Code + PKCE flow with Dynamic Client Registration (RFC 7591).
Single-user system designed for home use with Claude.ai as the primary client.
"""

import hashlib
import base64
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Query, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import jwt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DOMAIN = os.environ.get("DOMAIN", "localhost")
OWNER_PASSWORD: str = ""  # loaded on first use
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_HOURS = int(os.environ.get("JWT_EXPIRES_HOURS", "1"))
REFRESH_EXPIRES_DAYS = int(os.environ.get("REFRESH_EXPIRES_DAYS", "30"))

BASE_URL = os.environ.get("BASE_URL", f"https://{DOMAIN}")

# ---------------------------------------------------------------------------
# In-memory stores (acceptable for single-user home deployment)
# ---------------------------------------------------------------------------

clients: dict[str, dict] = {}          # client_id -> client metadata
auth_codes: dict[str, dict] = {}       # code -> {client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires}
refresh_tokens: set[str] = set()       # set of active refresh token JTIs

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="LIF OAuth Server", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")


def _check_password(candidate: str) -> bool:
    global OWNER_PASSWORD
    if not OWNER_PASSWORD:
        OWNER_PASSWORD = os.environ.get("OWNER_PASSWORD", "")
        if not OWNER_PASSWORD:
            raise RuntimeError("OWNER_PASSWORD environment variable is not set")
    return secrets.compare_digest(candidate, OWNER_PASSWORD)


# ---------------------------------------------------------------------------
# Discovery endpoints
# ---------------------------------------------------------------------------

@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/auth/authorize",
        "token_endpoint": f"{BASE_URL}/auth/token",
        "registration_endpoint": f"{BASE_URL}/auth/register",
        "introspection_endpoint": f"{BASE_URL}/auth/introspect",
        "revocation_endpoint": f"{BASE_URL}/auth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp"],
    }


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    return {
        "resource": BASE_URL,
        "authorization_servers": [BASE_URL],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------

@app.post("/auth/register")
async def register_client(request: Request):
    body = await request.json()
    client_id = secrets.token_urlsafe(24)
    client_secret = secrets.token_urlsafe(48)

    client_meta = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name", ""),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "client_secret_post"),
    }
    clients[client_id] = client_meta

    return JSONResponse(
        content={
            **client_meta,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,  # never expires
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------

@app.get("/auth/authorize", response_class=HTMLResponse)
async def authorize_form(
    request: Request,
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query("S256"),
    state: str = Query(""),
    scope: str = Query(""),
    response_type: str = Query("code"),
):
    if client_id not in clients:
        raise HTTPException(400, "Unknown client_id")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": state,
        "scope": scope,
        "response_type": response_type,
        "error": None,
    })


@app.post("/auth/authorize")
async def authorize_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form("S256"),
    state: str = Form(""),
    scope: str = Form(""),
    response_type: str = Form("code"),
):
    # Validate credentials
    if username != "owner" or not _check_password(password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
            "scope": scope,
            "response_type": response_type,
            "error": "Invalid username or password.",
        }, status_code=401)

    # Generate authorization code
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "expires": time.time() + 300,  # 5 minutes
    }

    params = {"code": code}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urlencode(params)}",
        status_code=302,
    )


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


def _issue_tokens(scope: str) -> dict:
    now = datetime.now(timezone.utc)
    access_payload = {
        "sub": "owner",
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + JWT_EXPIRES_HOURS * 3600,
        "scope": scope,
    }
    access_token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    jti = str(uuid.uuid4())
    refresh_payload = {
        "sub": "owner",
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + REFRESH_EXPIRES_DAYS * 86400,
        "jti": jti,
        "scope": scope,
    }
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    refresh_tokens.add(jti)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRES_HOURS * 3600,
        "refresh_token": refresh_token,
        "scope": scope,
    }


@app.post("/auth/token")
async def token_endpoint(
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    code_verifier: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    refresh_token: str = Form(None),
):
    # --- Authorization Code Grant ---
    if grant_type == "authorization_code":
        if not code or not code_verifier:
            raise HTTPException(400, "code and code_verifier are required")

        stored = auth_codes.pop(code, None)
        if stored is None:
            raise HTTPException(400, "invalid or expired authorization code")
        if stored["expires"] < time.time():
            raise HTTPException(400, "authorization code expired")
        if redirect_uri and stored["redirect_uri"] != redirect_uri:
            raise HTTPException(400, "redirect_uri mismatch")
        if not _verify_pkce(code_verifier, stored["code_challenge"], stored["code_challenge_method"]):
            raise HTTPException(400, "PKCE verification failed")

        return _issue_tokens(stored.get("scope", ""))

    # --- Refresh Token Grant ---
    if grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(400, "refresh_token is required")
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except Exception:
            raise HTTPException(400, "invalid refresh token")

        jti = payload.get("jti")
        if not jti or jti not in refresh_tokens:
            raise HTTPException(400, "refresh token has been revoked")

        # Rotate: revoke old, issue new
        refresh_tokens.discard(jti)
        return _issue_tokens(payload.get("scope", ""))

    raise HTTPException(400, f"unsupported grant_type: {grant_type}")


# ---------------------------------------------------------------------------
# Introspection (RFC 7662)
# ---------------------------------------------------------------------------

@app.post("/auth/introspect")
async def introspect(token: str = Form(...)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return {"active": False}

    # If it's a refresh token, check revocation
    jti = payload.get("jti")
    if jti and jti not in refresh_tokens:
        return {"active": False}

    return {
        "active": True,
        "sub": payload.get("sub"),
        "scope": payload.get("scope", ""),
        "exp": payload.get("exp"),
        "iat": payload.get("iat"),
    }


# ---------------------------------------------------------------------------
# Revocation (RFC 7009)
# ---------------------------------------------------------------------------

@app.post("/auth/revoke")
async def revoke(token: str = Form(...)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti:
            refresh_tokens.discard(jti)
    except Exception:
        pass  # RFC 7009: always return 200
    return {}
