"""Structured audit trail: one JSON record per tool call.

Each record holds who called, what was asked, the outcome, how long it took and
the Graph request-id on failure. Tool *results* are never written: the output
of this server maps the tenant's non-human identities, and copying it into a
log would create a second, less protected copy (renyamaura-bot's anti-pattern).
Secrets in arguments are redacted (muketps).

Records go to stderr (stdout carries the MCP protocol in stdio mode); in
Container Apps, stderr flows to Log Analytics. Set AUDIT_LOG_FILE to also append
JSON Lines to a file. A failed audit write is logged as an error, not ignored.
"""

from __future__ import annotations

import functools
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from .auth import caller_identity
from .config import settings
from .graph import GraphError
from .validation import InvalidInput

log = logging.getLogger("entra-agent-inventory.audit")
SENSITIVE_KEYS = {"token", "access_token", "authorization", "secret", "client_secret",
                  "password", "api_key", "key"}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "[REDACTED]" if k.lower() in SENSITIVE_KEYS else _sanitize(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + "..."
    return value


def write_record(record: dict[str, Any]) -> None:
    line = json.dumps(record, default=str)
    log.info("audit %s", line)
    if settings.audit_file:
        try:
            with open(settings.audit_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.error("audit file write failed: %s", exc)


def error_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, GraphError):
        hint = {
            401: "Token rejected. Check the credential configuration.",
            403: "Missing Graph permission or Entra role. Run the check_access tool.",
            404: "Object not found in this tenant.",
        }.get(exc.status, "")
        return {"error": "graph_error", "status": exc.status, "path": exc.path,
                "message": exc.message, "graph_request_id": exc.request_id, "hint": hint}
    if isinstance(exc, PermissionError):
        return {"error": "forbidden", "message": str(exc)}
    if isinstance(exc, InvalidInput):
        return {"error": "invalid_input", "message": str(exc)}
    if type(exc).__name__ in ("ClientAuthenticationError", "CredentialUnavailableError"):
        return {"error": "credential_error",
                "message": "Could not get a Microsoft Graph token.",
                "hint": "Set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (or "
                        "AZURE_CLIENT_CERTIFICATE_PATH) for an app registration, or run with a "
                        "managed identity in Azure."}
    log.exception("unexpected error")
    return {"error": "internal_error", "message": type(exc).__name__}


def audited(func: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
    """Wrap a tool: audit record, timing, and errors returned as data."""

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        started = time.perf_counter()
        record: dict[str, Any] = {
            "event": "tool_call",
            "audit_id": str(uuid.uuid4()),
            "time": datetime.now(timezone.utc).isoformat(),
            "tool": func.__name__,
            "args": _sanitize({k: v for k, v in kwargs.items() if k != "ctx"}),
            "caller": caller_identity(),
        }
        try:
            result = await func(*args, **kwargs)
            record["outcome"] = "error" if isinstance(result, dict) and "error" in result else "ok"
            return result
        except Exception as exc:  # noqa: BLE001 - tools return errors as data
            result = error_payload(exc)
            record["outcome"] = "denied" if isinstance(exc, PermissionError) else "error"
            record["error"] = result.get("error")
            record["graph_request_id"] = result.get("graph_request_id")
            return result
        finally:
            record["duration_ms"] = round((time.perf_counter() - started) * 1000)
            try:
                write_record(record)
            except Exception as exc:  # noqa: BLE001
                log.error("audit write failed for %s: %s", func.__name__, exc)

    return wrapper
