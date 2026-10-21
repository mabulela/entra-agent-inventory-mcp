"""Server assembly and transports.

stdio: launched by Visual Studio / VS Code / any MCP client as a local process.
streamable-http: for Container Apps. Adds /health (public), and inbound auth
according to MCP_AUTH_MODE. Refuses to listen on a non-loopback address without
auth unless MCP_ALLOW_UNAUTHENTICATED=true.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from . import __version__, prompts, tools
from .auth import ApiKeyMiddleware, build_auth
from .config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s %(message)s",
                    stream=sys.stderr)  # stdout carries the MCP protocol in stdio mode
log = logging.getLogger("entra-agent-inventory")

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server

    SDK_MAJOR = 2
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

    SDK_MAJOR = 1

INSTRUCTIONS = (
    "Read-only, live assessment of Microsoft Entra identities for agent governance and the move "
    "to agent identities. Every tool reads Microsoft Graph on demand for identities named by "
    "object ID: classify_principal and the get_* tools for one identity, assess_principals for up "
    "to 25, compare_coexistence for a legacy and a new identity side by side. "
    "list_ownerless_agents is the only tenant-wide list. There is no tenant-wide sweep or search "
    "by name. Confirmed agents come from Entra itself (Agent ID objects, or Copilot Studio's own "
    "tag on legacy agents); likely agents are a heuristic score with evidence - present them as "
    "candidates to confirm with the listed contact, never as facts. Sections marked not_permitted "
    "are gaps, not findings. Start a new tenant with check_access."
)
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def build_server() -> Any:
    verifier, auth = build_auth()
    kwargs: dict[str, Any] = {"instructions": INSTRUCTIONS}
    if verifier is not None:
        kwargs.update(token_verifier=verifier, auth=auth)
    if SDK_MAJOR == 2:
        server = _Server(name="entra-agent-inventory", version=__version__, **kwargs)
    else:
        server = _Server("entra-agent-inventory", host=settings.host, port=settings.port,
                         transport_security=_transport_security(), **kwargs)

    @server.custom_route("/health", methods=["GET"])
    async def health(_request: Any) -> Any:
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok", "service": "entra-agent-inventory",
                             "version": __version__, "auth_mode": settings.auth_mode})

    tools.register(server)
    prompts.register(server)
    return server


def _transport_security() -> Any:
    if not settings.allowed_hosts:
        return None
    from mcp.server.transport_security import TransportSecuritySettings

    return TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                     allowed_hosts=settings.allowed_hosts)


def http_app(server: Any) -> Any:
    if SDK_MAJOR == 2:
        app = server.streamable_http_app(host=settings.host,
                                         transport_security=_transport_security())
    else:
        app = server.streamable_http_app()
    if settings.auth_mode == "api_key":
        if not settings.api_key:
            raise SystemExit("MCP_AUTH_MODE=api_key requires MCP_API_KEY")
        app = ApiKeyMiddleware(app, settings.api_key)
    return app


def check_safe_to_listen() -> None:
    if settings.host in LOOPBACK or settings.auth_mode != "none":
        return
    if settings.allow_unauthenticated:
        log.warning("Listening on %s WITHOUT authentication (MCP_ALLOW_UNAUTHENTICATED=true). "
                    "Only do this behind a gateway that authenticates every request.",
                    settings.host)
        return
    raise SystemExit(
        f"Refusing to listen on {settings.host} without authentication. Set MCP_AUTH_MODE=entra "
        "(production) or MCP_API_KEY (dev), or MCP_ALLOW_UNAUTHENTICATED=true if an "
        "authenticating gateway sits in front."
    )


def run() -> None:
    log.info("entra-agent-inventory %s starting (transport=%s, auth=%s, mcp sdk %s)",
             __version__, settings.transport, settings.auth_mode, SDK_MAJOR)
    server = build_server()
    if settings.transport == "stdio":
        server.run("stdio")
        return
    if settings.transport != "streamable-http":
        raise SystemExit("MCP_TRANSPORT must be 'stdio' or 'streamable-http'")
    check_safe_to_listen()
    import uvicorn

    # Uvicorn trusts X-Forwarded-* only from FORWARDED_ALLOW_IPS (default 127.0.0.1).
    # Nothing here relies on forwarded headers for security decisions.
    uvicorn.run(http_app(server), host=settings.host, port=settings.port, log_level="info")
