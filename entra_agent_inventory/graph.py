"""Read-only Microsoft Graph client.

There are deliberately no POST/PATCH/DELETE methods: this server can only read.
batch_get() posts to /$batch, but only ever with GET requests inside.

Behaviour adopted from the repos reviewed:
  * Graph request-id is kept on every error, for Microsoft support escalation (muketps).
  * A 401 re-mints the token once and retries once, unless Graph says the app is
    missing a permission - re-minting can't fix that (ellswoau).
  * 429/503/504 honour Retry-After with bounded backoff.
  * nextLink is only followed to the configured Graph host, so the bearer token
    can't be sent anywhere else.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import httpx

from .config import settings

log = logging.getLogger("entra-agent-inventory.graph")

PERMISSION_ERROR_CODES = {"Authorization_RequestDenied", "Forbidden", "accessDenied"}


class GraphError(Exception):
    def __init__(self, status: int, message: str, path: str,
                 request_id: str | None = None, code: str | None = None) -> None:
        super().__init__(f"Graph {status} on {path}: {message}")
        self.status = status
        self.message = message
        self.path = path
        self.request_id = request_id
        self.code = code


class GraphClient:
    def __init__(self, credential: Any = None) -> None:
        self._credential = credential
        self._http = httpx.AsyncClient(timeout=60.0)
        self._token: str | None = None
        self._token_expires = 0
        self._lock = asyncio.Lock()

    # --- tokens -----------------------------------------------------------

    async def _get_token(self, force: bool = False) -> str:
        async with self._lock:
            now = int(datetime.now(timezone.utc).timestamp())
            if not force and self._token and now < self._token_expires - 300:
                return self._token
            if self._credential is None:
                from azure.identity.aio import DefaultAzureCredential

                self._credential = DefaultAzureCredential()
            token = await self._credential.get_token(settings.graph_scope)
            self._token, self._token_expires = token.token, token.expires_on
            return self._token

    async def token_claims(self) -> dict[str, Any]:
        """Decode (not validate) our own Graph token to report granted app roles."""
        token = await self._get_token()
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
        except (IndexError, ValueError):
            return {}

    # --- requests ---------------------------------------------------------

    def _url(self, path: str, beta: bool) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            if not path.startswith(settings.graph_root + "/"):
                raise GraphError(0, "refusing to follow a non-Graph URL", path)
            return path
        return f"{settings.graph_root}/{'beta' if beta else 'v1.0'}{path}"

    async def get(self, path: str, *, params: dict[str, str] | None = None,
                  beta: bool = False, headers: dict[str, str] | None = None) -> dict[str, Any]:
        url = self._url(path, beta)
        short_path = path.split("?")[0]
        reminted = False
        attempt = 0
        while True:
            attempt += 1
            token = await self._get_token()
            req_headers = {"Authorization": f"Bearer {token}"}
            if headers:
                req_headers.update(headers)
            resp = await self._http.get(url, params=params, headers=req_headers)
            request_id = resp.headers.get("request-id") or resp.headers.get("client-request-id")

            if resp.status_code in (429, 503, 504) and attempt < 5:
                wait = resp.headers.get("Retry-After")
                delay = int(wait) if wait and wait.isdigit() else 2 ** attempt
                log.warning("Graph %s on %s, retrying in %ss", resp.status_code, short_path, delay)
                await asyncio.sleep(min(delay, 60))
                continue

            if resp.status_code < 400:
                return resp.json()

            code, message = _parse_error(resp)
            if resp.status_code == 401 and not reminted and code not in PERMISSION_ERROR_CODES:
                reminted = True
                await self._get_token(force=True)
                continue
            raise GraphError(resp.status_code, message[:500], short_path, request_id, code)

    async def get_all(self, path: str, *, params: dict[str, str] | None = None,
                      beta: bool = False, headers: dict[str, str] | None = None,
                      max_items: int = 1000,
                      on_page: Callable[[int], Awaitable[None]] | None = None,
                      ) -> tuple[list[dict[str, Any]], bool]:
        """Follow @odata.nextLink up to max_items. Returns (items, truncated)."""
        items: list[dict[str, Any]] = []
        page = await self.get(path, params=params, beta=beta, headers=headers)
        while True:
            items.extend(page.get("value", []))
            if on_page:
                await on_page(len(items))
            next_link = page.get("@odata.nextLink")
            if len(items) >= max_items:
                return items[:max_items], bool(next_link) or len(items) > max_items
            if not next_link:
                return items, False
            page = await self.get(next_link, headers=headers)

    async def batch_get(self, paths: list[str], *, beta: bool = False,
                        headers: dict[str, str] | None = None) -> dict[str, Any]:
        """GET many relative paths through Graph JSON batching (20 per batch). [ML]

        $batch is a POST on the wire, but every inner request is forced to GET and
        must be a relative Graph path, so this cannot write. Returns
        {path: response-body | GraphError}. Throttled inner requests are retried.
        """
        for p in paths:
            if not p.startswith("/") or "://" in p or p.startswith("//"):
                raise GraphError(0, "batch paths must be relative Graph paths", p)
        results: dict[str, Any] = {}
        pending = list(dict.fromkeys(paths))
        url = f"{settings.graph_root}/{'beta' if beta else 'v1.0'}/$batch"
        for attempt in range(4):
            if not pending:
                break
            throttled: list[str] = []
            wait = 0
            for start in range(0, len(pending), 20):
                chunk = pending[start:start + 20]
                body = {"requests": [{"id": str(i), "method": "GET", "url": p,
                                      **({"headers": headers} if headers else {})}
                                     for i, p in enumerate(chunk)]}
                token = await self._get_token()
                resp = await self._http.post(url, json=body,
                                             headers={"Authorization": f"Bearer {token}"})
                if resp.status_code in (429, 503, 504):
                    throttled += chunk
                    ra = resp.headers.get("Retry-After")
                    wait = max(wait, int(ra) if ra and ra.isdigit() else 2 ** (attempt + 1))
                    continue
                if resp.status_code >= 400:
                    code, message = _parse_error(resp)
                    err = GraphError(resp.status_code, message[:300], "/$batch",
                                     resp.headers.get("request-id"), code)
                    results.update({p: err for p in chunk})
                    continue
                for item in resp.json().get("responses", []):
                    path = chunk[int(item["id"])]
                    status = int(item.get("status", 500))
                    if status in (429, 503, 504):
                        throttled.append(path)
                        ra = (item.get("headers") or {}).get("Retry-After")
                        wait = max(wait, int(ra) if ra and str(ra).isdigit() else 2 ** (attempt + 1))
                    elif status >= 400:
                        err_body = (item.get("body") or {}).get("error", {})
                        results[path] = GraphError(status, err_body.get("message", ""), path,
                                                   (item.get("headers") or {}).get("request-id"),
                                                   err_body.get("code"))
                    else:
                        results[path] = item.get("body") or {}
            pending = throttled
            if pending:
                log.warning("batch: %d requests throttled, retrying in %ss", len(pending), wait)
                await asyncio.sleep(min(wait, 60))
        for p in pending:
            results[p] = GraphError(429, "still throttled after retries", p)
        return results

    async def close(self) -> None:
        await self._http.aclose()
        if self._credential is not None and hasattr(self._credential, "close"):
            await self._credential.close()


def _parse_error(resp: httpx.Response) -> tuple[str | None, str]:
    try:
        err = resp.json().get("error", {})
        return err.get("code"), err.get("message") or resp.text
    except ValueError:
        return None, resp.text


async def section(coro: Awaitable[Any], needs: str) -> dict[str, Any]:
    """Run one part of a multi-part result. A permission failure in one part
    becomes a labelled gap instead of failing the whole tool."""
    try:
        return {"status": "ok", "data": await coro}
    except GraphError as exc:
        if exc.status in (401, 403):
            return {"status": "not_permitted", "needs": needs,
                    "graph_request_id": exc.request_id}
        if exc.status == 404:
            return {"status": "not_found", "graph_request_id": exc.request_id}
        return {"status": "error", "http_status": exc.status, "message": exc.message,
                "graph_request_id": exc.request_id}


graph = GraphClient()
