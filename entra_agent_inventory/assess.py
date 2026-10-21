"""assess_principals: a fresh, live assessment of up to 25 identities at once.

Each identity is scored by scoring.build_row(), the same engine classify_principal
uses, and returned as one flat row plus the grouped assessment.

(No `from __future__ import annotations` here: the MCP SDK inspects these
signatures, including the Context parameter, at registration time.)
"""

import asyncio
from typing import Any

from . import collectors as C
from .audit import audited
from .config import settings
from .graph import GraphError, section
from .scoring import build_row
from .tools import READ_ONLY, Context, _assessment, _progress
from .validation import InvalidInput, check_guid


def register(server: Any) -> None:

    @server.tool(annotations=READ_ONLY)
    @audited
    async def assess_principals(ctx: Context, object_ids: list[str]) -> dict[str, Any]:
        """Fresh, live assessment of a few identities with the same scoring as
        classify_principal: agent status and likelihood with evidence, priority,
        exposures, contact, credentials and migration wave, one row per identity.

        Args:
            object_ids: Entra object IDs (GUIDs), up to 25 per call.
        """
        from .facts import live_facts

        limit = settings.t("assess_max_principals")
        if not isinstance(object_ids, list) or not object_ids:
            raise InvalidInput("object_ids must be a non-empty list of object IDs")
        if len(object_ids) > limit:
            raise InvalidInput(f"At most {limit} identities per call; split the list.")
        ids = list(dict.fromkeys(check_guid(i, "object_ids[]") for i in object_ids))

        policies = await section(C.list_ca_policies(), "Policy.Read.All")
        tenant_id = (await C.g().token_claims()).get("tid")
        sem = asyncio.Semaphore(settings.graph_concurrency)
        done = 0

        async def one(oid: str) -> dict[str, Any]:
            nonlocal done
            try:
                async with sem:
                    facts = await live_facts(oid, 30, tenant_id,
                                             policies.get("data") if policies["status"] == "ok" else None)
                if facts["label"] in ("user", "entra_agent_user"):
                    return {"object_id": oid, "error": "users aren't scored; use classify_principal"}
                row = build_row(facts)
                return {"object_id": oid, "display_name": row["display_name"],
                        "assessment": _assessment(row), "row": row,
                        "gaps": facts.get("gaps", [])}
            except GraphError as exc:
                return {"object_id": oid, "error": "not found" if exc.status == 404 else
                        f"graph {exc.status}", "graph_request_id": exc.request_id}
            finally:
                done += 1
                await _progress(ctx, done, len(ids), f"Assessed {done}/{len(ids)}")

        results = await asyncio.gather(*(one(i) for i in ids))
        return {"assessed": len(ids), "results": results,
                "note": "Live data, 30-day sign-in window."}
