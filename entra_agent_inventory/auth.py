"""Inbound authentication for HTTP mode, and caller identity for the audit log.

Modes (MCP_AUTH_MODE):
  none     Local development on loopback only. The server refuses to listen on a
           non-loopback address in this mode unless MCP_ALLOW_UNAUTHENTICATED=true.
  api_key  Shared bearer key (MCP_API_KEY), constant-time compared. For dev and
           sandbox. No caller identity beyond "holder of the key". (ellswoau)
  entra    Microsoft Entra access tokens validated in-process: signature against
           the tenant's published keys, issuer, audience, expiry. Uses the MCP
           SDK's TokenVerifier hook, so the server also publishes OAuth protected
           resource metadata for MCP clients. Caller identity comes from the
           validated token, never from forwarded headers. (renyamaura-bot's
           APIM design documents headers its code never reads - this avoids that.)

Production pattern [A]: entra mode behind APIM or Container Apps ingress. The
token must be a v2.0 access token issued for this server's app registration
(set requestedAccessTokenVersion = 2 on that registration). [ML]
"""

from __future__ import annotations

import asyncio
import getpass
import hmac
import json
import logging
from typing import Any, Callable

from .config import settings

log = logging.getLogger("entra-agent-inventory.auth")

try:
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.auth.provider import AccessToken, TokenVerifier
    from mcp.server.auth.settings import AuthSettings
except ImportError:  # pragma: no cover - very old SDKs
    get_access_token = lambda: None  # noqa: E731
    AccessToken = TokenVerifier = AuthSettings = None  # type: ignore[assignment,misc]

PUBLIC_PATHS = ("/health",)


# --- caller identity ---------------------------------------------------------

def caller_identity() -> dict[str, Any]:
    if settings.transport == "stdio":
        try:
            user = getpass.getuser()
        except Exception:  # noqa: BLE001
            user = "unknown"
        return {"auth": "stdio", "os_user": user}
    if settings.auth_mode == "api_key":
        return {"auth": "api_key"}
    if settings.auth_mode == "entra":
        token = get_access_token()
        if token is None:
            return {"auth": "entra", "identity": None}
        c = token.claims or {}
        return {
            "auth": "entra",
            "oid": c.get("oid"),
            "app_id": c.get("azp") or c.get("appid"),
            "upn": c.get("preferred_username") or c.get("upn"),
            "name": c.get("name"),
            "identity_type": c.get("idtyp") or ("app" if "scp" not in c else "user"),
            "roles": c.get("roles", []),
        }
    return {"auth": "none"}


def caller_has_role(role: str) -> bool:
    """True when the role is not enforced in this mode, or the caller holds it."""
    if not role or settings.auth_mode != "entra":
        return True
    token = get_access_token()
    return bool(token and role in (token.scopes or []))


def require_tenant_wide() -> None:
    """Gate for tools that return a tenant-wide list (list_ownerless_agents). Raises PermissionError, reported as 'forbidden'."""
    if not caller_has_role(settings.sweep_role):
        raise PermissionError(f"Tenant-wide lists require the app role '{settings.sweep_role}'.")


# --- api_key mode ------------------------------------------------------------

class ApiKeyMiddleware:
    """Pure ASGI middleware: requires `Authorization: Bearer <MCP_API_KEY>`."""

    def __init__(self, app: Any, api_key: str) -> None:
        self.app = app
        self.expected = f"Bearer {api_key}".encode()

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or scope.get("path", "") in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return
        supplied = b""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                supplied = value
                break
        if hmac.compare_digest(supplied, self.expected):
            await self.app(scope, receive, send)
            return
        body = json.dumps({"error": "unauthorized"}).encode()
        await send({"type": "http.response.start", "status": 401, "headers": [
            (b"content-type", b"application/json"),
            (b"www-authenticate", b'Bearer realm="entra-agent-inventory"'),
            (b"content-length", str(len(body)).encode()),
        ]})
        await send({"type": "http.response.body", "body": body})


# --- entra mode --------------------------------------------------------------

class EntraTokenVerifier:
    """Validates Microsoft Entra v2.0 access tokens for this server."""

    def __init__(self, tenant_id: str, audiences: list[str],
                 key_resolver: Callable[[str], Any] | None = None) -> None:
        import jwt  # PyJWT

        self._jwt = jwt
        self.issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        self.audiences = audiences
        if key_resolver is None:
            jwks = jwt.PyJWKClient(
                f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
                cache_keys=True, lifespan=3600,
            )
            key_resolver = lambda token: jwks.get_signing_key_from_jwt(token).key  # noqa: E731
        self._resolve_key = key_resolver

    async def verify_token(self, token: str) -> Any:
        try:
            key = await asyncio.to_thread(self._resolve_key, token)
            claims = self._jwt.decode(
                token, key=key, algorithms=["RS256"], audience=self.audiences,
                issuer=self.issuer, options={"require": ["exp", "iss", "aud"]},
            )
        except Exception as exc:  # noqa: BLE001 - any failure means "not authenticated"
            log.warning("rejected bearer token: %s", type(exc).__name__)
            return None
        scopes = (claims.get("scp") or "").split() + list(claims.get("roles") or [])
        return AccessToken(
            token=token,
            client_id=claims.get("azp") or claims.get("appid") or "",
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=claims.get("aud") if isinstance(claims.get("aud"), str) else None,
            subject=claims.get("oid") or claims.get("sub"),
            claims=claims,
        )


def build_auth() -> tuple[Any, Any]:
    """Returns (token_verifier, auth_settings) for entra mode, else (None, None)."""
    if settings.auth_mode != "entra":
        return None, None
    missing = [name for name, value in (
        ("MCP_AUTH_TENANT_ID", settings.auth_tenant_id),
        ("MCP_AUTH_AUDIENCE", settings.auth_audience),
        ("MCP_RESOURCE_URL", settings.resource_url),
    ) if not value]
    if missing:
        raise SystemExit(f"MCP_AUTH_MODE=entra requires: {', '.join(missing)}")
    verifier = EntraTokenVerifier(settings.auth_tenant_id, settings.auth_audience)
    auth = AuthSettings(
        issuer_url=f"https://login.microsoftonline.com/{settings.auth_tenant_id}/v2.0",
        resource_server_url=settings.resource_url,
        required_scopes=[settings.required_role] if settings.required_role else None,
        validate_token_resource=False,  # audience is checked by the verifier
    )
    return verifier, auth
