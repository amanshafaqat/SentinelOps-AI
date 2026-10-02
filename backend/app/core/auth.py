"""Authentication and Role-Based Authorization Framework for SentinelOps AI.

Enforces an explicit server-side authorization matrix across API resources:
Resource             Read       Modify
Events               Auth      Analyst/Admin
Alerts               Auth      System/Admin
Incidents            Auth      Analyst/Admin
Notes                Auth      Authorized Analyst/Admin
Reports              Auth      Authorized Analyst/Admin
AI Investigation     Auth      Authorized Analyst/Admin
Audit                Auth      Admin / Lead Analyst

Supports:
- Signed HS256 JWT tokens using standard HMAC-SHA256 (no external dependencies)
- Bearer static tokens for service-to-service / automated workflows
- Role-based header overrides (X-Actor-Role, X-Actor-Name)
- Default fallback for interactive browser demonstration mode
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Any, Callable, Dict, List, Optional, Set
from fastapi import Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.core.logging import logger

# Role Definition & Permissions
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {
        "events:read",
        "events:write",
        "alerts:read",
        "alerts:modify",
        "incidents:read",
        "incidents:write",
        "notes:read",
        "notes:write",
        "notes:delete",
        "reports:read",
        "reports:write",
        "ai:investigate",
        "audit:read",
        "*",
    },
    "lead_analyst": {
        "events:read",
        "events:write",
        "alerts:read",
        "alerts:modify",
        "incidents:read",
        "incidents:write",
        "notes:read",
        "notes:write",
        "notes:delete",
        "reports:read",
        "reports:write",
        "ai:investigate",
        "audit:read",
    },
    "soc_analyst": {
        "events:read",
        "events:write",
        "alerts:read",
        "incidents:read",
        "incidents:write",
        "notes:read",
        "notes:write",
        "notes:delete",
        "reports:read",
        "reports:write",
        "ai:investigate",
        "audit:read",
    },
    "analyst": {
        "events:read",
        "events:write",
        "alerts:read",
        "incidents:read",
        "incidents:write",
        "notes:read",
        "notes:write",
        "notes:delete",
        "reports:read",
        "reports:write",
        "ai:investigate",
        "audit:read",
    },
    "system": {
        "events:read",
        "alerts:read",
        "alerts:modify",
        "incidents:write",
        "audit:read",
    },
    "viewer": {
        "events:read",
        "alerts:read",
        "incidents:read",
        "notes:read",
        "reports:read",
    },
}


class AuthUser(BaseModel):
    """Authenticated user context containing identity, role, and granted scopes."""

    username: str
    role: str = "soc_analyst"
    email: Optional[str] = None
    permissions: Set[str] = Field(default_factory=set)

    def has_permission(self, permission: str) -> bool:
        """Evaluates whether the user holds the requested permission or superuser scope."""
        if "*" in self.permissions or "admin" == self.role.lower():
            return True
        return permission in self.permissions


def _b64_url_encode(data: bytes) -> str:
    """Encodes bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64_url_decode(s: str) -> bytes:
    """Decodes URL-safe base64 string with padding restoration."""
    padding = "=" * (4 - (len(s) % 4)) if len(s) % 4 != 0 else ""
    return base64.urlsafe_b64decode(s + padding)


def create_access_token(
    payload: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Creates a signed HS256 JWT access token without third-party dependencies."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    
    header = {"alg": "HS256", "typ": "JWT"}
    body = {**payload, "iat": int(now.timestamp()), "exp": int(expire.timestamp())}
    
    encoded_header = _b64_url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_body = _b64_url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    
    signing_input = f"{encoded_header}.{encoded_body}".encode("utf-8")
    signature = hmac.new(
        settings.jwt_secret_key.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    
    encoded_sig = _b64_url_encode(signature)
    return f"{encoded_header}.{encoded_body}.{encoded_sig}"


def decode_access_token(token: str) -> Dict[str, Any]:
    """Validates signature and claims of an HS256 JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    encoded_header, encoded_body, encoded_sig = parts
    signing_input = f"{encoded_header}.{encoded_body}".encode("utf-8")
    
    expected_sig = hmac.new(
        settings.jwt_secret_key.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    
    provided_sig = _b64_url_decode(encoded_sig)
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        body = json.loads(_b64_url_decode(encoded_body).decode("utf-8"))
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unparseable token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err
    
    exp = body.get("exp")
    if exp and datetime.now(timezone.utc).timestamp() > exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return body


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_actor_role: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
) -> AuthUser:
    """Dependency that extracts and authenticates the requesting actor.

    In production:
    - Requires valid signed JWT Bearer token
    - Rejects static development tokens ('token-*')
    - Rejects identity spoofing via arbitrary X-Actor-* headers
    - Disables unauthenticated fallback

    In development/testing:
    - Supports JWT tokens, developer static tokens, explicit test headers, and demo fallback
    """
    # 1. Bearer Token Check
    if authorization:
        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Expected 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token = parts[1].strip()

        # Reject development static tokens in production
        if token.startswith("token-"):
            if settings.is_production:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Static development tokens are not permitted in production.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            role_hint = token.replace("token-", "").lower()
            role = role_hint if role_hint in ROLE_PERMISSIONS else "viewer"
            username = f"{role}_user"
            perms = ROLE_PERMISSIONS.get(role, set())
            return AuthUser(username=username, role=role, permissions=perms)
        
        # Standard signed JWT token verification
        claims = decode_access_token(token)
        username = claims.get("sub") or claims.get("username") or "authenticated_user"
        role = claims.get("role", "soc_analyst").lower()
        perms = ROLE_PERMISSIONS.get(role, set())
        return AuthUser(username=username, role=role, permissions=perms)

    # 2. Explicit Role / Actor Header (Development & Testing only)
    if x_actor_role or x_actor_name:
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Identity headers are not permitted in production without a valid Bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        role = (x_actor_role or "soc_analyst").lower()
        if role not in ROLE_PERMISSIONS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Unknown actor role '{x_actor_role}'.",
            )
        username = (x_actor_name or f"{role}_user").strip()
        perms = ROLE_PERMISSIONS.get(role, set())
        return AuthUser(username=username, role=role, permissions=perms)

    # 3. In production: unauthenticated access to protected endpoints is strictly forbidden
    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Default demo mode actor (development/testing sandbox only)
    default_role = "soc_analyst"
    return AuthUser(
        username="soc_analyst",
        role=default_role,
        permissions=ROLE_PERMISSIONS.get(default_role, set()),
    )


def require_permission(permission: str) -> Callable[..., AuthUser]:
    """Factory creating a FastAPI dependency that enforces a specific permission."""

    def _dependency(user: AuthUser = Header(None)) -> AuthUser:
        # Note: FastAPI dependency resolver will pass get_current_user when configured
        pass

    def dependency(
        request: Request,
        authorization: Optional[str] = Header(None),
        x_actor_role: Optional[str] = Header(None),
        x_actor_name: Optional[str] = Header(None),
    ) -> AuthUser:
        user = get_current_user(
            request=request,
            authorization=authorization,
            x_actor_role=x_actor_role,
            x_actor_name=x_actor_name,
        )
        if not user.has_permission(permission):
            logger.warning(
                "Access denied for user '%s' [role: %s] requesting permission '%s' on %s %s",
                user.username,
                user.role,
                permission,
                request.method,
                request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: User '{user.username}' with role '{user.role}' lacks required permission '{permission}'.",
            )
        return user

    return dependency
