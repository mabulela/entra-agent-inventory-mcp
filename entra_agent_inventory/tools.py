"""MCP tool definitions. All read-only, all audited, all fixed-query.

(No `from __future__ import annotations` here: the MCP SDK inspects these
signatures, including the Context parameter, at registration time.)
"""

import asyncio
from collections import Counter
from typing import Any

from mcp.types import ToolAnnotations

from . import analysis as A
from . import collectors as C
from .audit import audited
from .auth import caller_has_role, require_tenant_wide
from .config import settings
from .graph import GraphError, section
from .scoring import max_likelihood
from .validation import InvalidInput, check_guid, clamp, clamp_days

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import Context
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import Context  # type: ignore[no-redef]

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                            idempotentHint=True, openWorldHint=False)

EXPECTED_TOOLS = (
    # live: one or a few identities, fresh from Graph
    "list_ownerless_agents", "classify_principal", "get_agent_signins", "compare_coexistence",
    "get_credential_inventory", "get_access_footprint", "get_conditional_access_coverage",
    "get_principal_changes", "check_access", "assess_principals",
)


# --- shared building blocks -----------------------------------------------------------

async def _credential_bundle(sp: dict[str, Any], label: str) -> dict[str, Any]:
    """Directory credential facts for one principal, plus the derived wave."""
    if label == "managed_identity":
        return {"credentials": [], "note": "Credentials are platform-managed by Azure.",
                "migration_profile": A.wave_from_directory(label, sp, [], None)}

    app_id = sp.get("agentIdentityBlueprintId") if label == "entra_agent_identity" else sp.get("appId")
    app_section = await section(C.get_application(app_id), "Application.Read.All")
    app = app_section.get("data") if app_section["status"] == "ok" else None

    fics: list[dict[str, Any]] = []
    fic_status = "skipped"
    if app:
        fic_section = await section(C.get_fics(app["id"]), "Application.Read.All")
        fic_status = fic_section["status"]
        fics = fic_section.get("data") or []

    consumers = await section(C.get_consumers(sp["id"]), "Application.Read.All")
    creds = A.credential_inventory(app, sp, fics)
    n_consumers = len(consumers["data"]) if consumers["status"] == "ok" else None

    result: dict[str, Any] = {
        "application": ({"object_id": app.get("id"), "app_id": app.get("appId"),
                         "sign_in_audience": app.get("signInAudience")} if app else None),
        "credentials": creds,
        "summary": {
            "by_type": dict(Counter(c["type"] for c in creds)),
            "by_status": dict(Counter(c.get("status", "n/a") for c in creds)),
            "next_expiry_days": min((c["days_to_expiry"] for c in creds
                                     if c.get("days_to_expiry") is not None
                                     and c["days_to_expiry"] >= 0), default=None),
        },
        "federated_credentials_lookup": fic_status,
        "inbound_consumers": consumers,
        "migration_profile": A.wave_from_directory(label, sp, creds, n_consumers),
    }
    if label == "entra_agent_identity":
        result["note"] = ("Agent identity credentials live on the blueprint, not the identity. [ML] "
                          "Looking up the blueprint as an application is unverified. [U]")
    elif not app and app_section["status"] in ("ok", "not_found"):
        result["note"] = ("No app registration in this tenant (multitenant or third-party app); "
                          "only service-principal credentials are visible.")
    elif app_section["status"] == "not_permitted":
        result["note"] = "Application lookup not permitted: needs Application.Read.All."
    return result


def _assessment(row: dict[str, Any]) -> dict[str, Any]:
    """The scoring fields of an assessed row, grouped for chat answers."""
    return {
        "agent_status": row["agent_status"], "likelihood": row["likelihood"],
        "likelihood_max": max_likelihood(), "likely_threshold": settings.t("likely_threshold"),
        "priority": row["priority"],
        "signals": [s for s in str(row["signals"]).split("|") if s],
        "exposures": [s for s in str(row["exposures"]).split("|") if s],
        "evidence": row["evidence"],
        "contact": {"name": row["contact_name"], "upn": row["contact_upn"], "type": row["contact_type"]},
        "ca_status": row["ca_status"],
    }


def _is_user(label: str) -> bool:
    return label in ("user", "entra_agent_user")


async def _progress(ctx: Any, progress: float, total: Any, message: str) -> None:
    """Best-effort progress notification; never allowed to break a tool."""
    try:
        await ctx.report_progress(progress, total, message)
    except Exception:  # noqa: BLE001 - no request context, client gone, etc.
        pass


# --- registration ------------------------------------------------------------------------

def register(server: Any) -> None:

    @server.tool(annotations=READ_ONLY)
    @audited
    async def list_ownerless_agents(max_results: int = 100) -> dict[str, Any]:
        """Native Microsoft Entra agent identities that have no owners, live from Graph,
        newest first, each with its sponsors (who to contact when there is no owner).
        Needs the tenant-wide app role.

        Only native agent identities are checked. Blueprint principals and agents on
        ordinary service principals (for example older Copilot Studio agents) aren't; check
        those one by one with classify_principal or assess_principals (contact_type).

        Args:
            max_results: Identities to return (1-500, default 100). total_matches gives
                the full count.
        """
        require_tenant_wide()
        limit = clamp(max_results, 1, 500)
        found = await C.find_ownerless_agents(settings.t("agent_list_scan_limit"))
        matches = sorted(found["items"], key=lambda i: i.get("createdDateTime") or "", reverse=True)
        page = matches[:limit]
        sponsors = await C.sponsors_for([i["id"] for i in page]) if page else {}
        identities = []
        for i in page:
            view = A.principal_view(i)
            sp = sponsors.get(i["id"])
            view["sponsors"] = sp if sp is not None else "unknown (lookup failed)"
            identities.append(view)
        return {
            "total_matches": len(matches),
            "total_is_complete": not found["scan_limit_reached"],
            "returned_without_sponsor": sum(1 for i in identities if i["sponsors"] == []),
            "returned": len(page), "order": "newest first (createdDateTime)",
            "filtered_by": found["filtered_by"],
            "identities_per_blueprint": Counter(
                i.get("agentIdentityBlueprintId") or "none" for i in matches).most_common(),
            "identities": identities,
        }

    @server.tool(annotations=READ_ONLY)
    @audited
    async def classify_principal(object_id: str, activity_days: int = 30) -> dict[str, Any]:
        """Classify one Entra object and assess it with the same scoring as assess_principals.

        Returns what the object is (agent identity, blueprint, agent user, managed
        identity, service principal or user), its agent likelihood (0 to likelihood_max) with the
        signals behind it, its priority and exposures, the first reachable contact
        (owner, sponsor or creator), and the migration wave from its directory
        credentials.

        Args:
            object_id: Entra object ID (GUID).
            activity_days: Sign-in window in days (1-30, default 30).
        """
        from .facts import live_facts
        from .scoring import build_row

        oid = check_guid(object_id, "object_id")
        days = clamp_days(activity_days)
        obj = await C.get_principal(oid)
        label = A.directory_label(obj)
        result: dict[str, Any] = {"principal": A.principal_view(obj),
                                  "directory_classification": label,
                                  "is_native_agent": label.startswith("entra_agent")}
        if label in ("user", "entra_agent_user"):
            # Users aren't scored; their sign-ins show whether they act as an agent user.
            events, truncated = await C.signins_for(oid, is_user=True, days=days, max_items=1000)
            subjects = sorted({(e.get("agent") or {}).get("agentSubjectType")
                               for e in events} - {None, "notAgentic"})
            result["signins"] = {"days": days, "count": len(events), "truncated": truncated,
                                 "agentic_subject_types_seen": subjects}
            if "agentIDuser" in subjects:
                result["directory_classification"] = "entra_agent_user (from sign-in logs)"
                result["is_native_agent"] = True
            return result

        policies = await section(C.list_ca_policies(), "Policy.Read.All")
        tenant_id = (await C.g().token_claims()).get("tid")
        facts = await live_facts(oid, days, tenant_id,
                                 policies.get("data") if policies["status"] == "ok" else None)
        row = build_row(facts)
        result["assessment"] = _assessment(row)
        result["signins"] = {k: v for k, v in (facts.get("signins") or {}).items() if k != "resources"}
        result["signins"]["top_resources"] = (facts.get("signins") or {}).get("resources", [])[:8]
        bundle = await _credential_bundle(obj, label)
        result["migration_profile"] = bundle["migration_profile"]
        result["credential_summary"] = bundle.get("summary")
        result["gaps"] = facts.get("gaps", [])
        return result

    @server.tool(annotations=READ_ONLY)
    @audited
    async def get_agent_signins(object_id: str, days: int = 7,
                                include_samples: bool = True) -> dict[str, Any]:
        """Summarise sign-in activity for one principal, including which Conditional
        Access policies were evaluated and with what result.

        Args:
            object_id: Entra object ID (GUID).
            days: Lookback window (1-30, default 7).
            include_samples: Include up to 20 recent events (trimmed fields).
        """
        oid = check_guid(object_id, "object_id")
        days = clamp_days(days)
        obj = await C.get_principal(oid)
        label = A.directory_label(obj)
        events, truncated = await C.signins_for(oid, is_user=_is_user(label), days=days,
                                                max_items=settings.max_signin_events)
        result: dict[str, Any] = {
            "principal": A.principal_view(obj), "directory_classification": label, "days": days,
            "summary": A.summarise_signins(events, truncated),
            "conditional_access_results": A.applied_ca_summary(events),
        }
        if include_samples:
            keep = ("createdDateTime", "resourceDisplayName", "appDisplayName",
                    "clientCredentialType", "conditionalAccessStatus", "ipAddress")
            result["recent_events"] = [
                {**{k: e.get(k) for k in keep},
                 "errorCode": (e.get("status") or {}).get("errorCode"),
                 "agentType": A.agent_type(e)} for e in events[:20]]
        return result

    @server.tool(annotations=READ_ONLY)
    @audited
    async def compare_coexistence(legacy_object_id: str, new_object_id: str,
                                  days: int = 14) -> dict[str, Any]:
        """Compare a legacy identity with its new agent identity during coexistence.

        Shows whether the legacy identity is still active, which resources only it
        still calls, the new identity's failure rate, Conditional Access results on
        the new identity (including report-only), and any sensitive changes made to
        the legacy identity during the window - for example a credential added while
        it was meant to be winding down.

        Args:
            legacy_object_id: Object ID of the legacy service principal or MI.
            new_object_id: Object ID of the new agent identity.
            days: Lookback window (1-30, default 14).
        """
        legacy_id = check_guid(legacy_object_id, "legacy_object_id")
        new_id = check_guid(new_object_id, "new_object_id")
        days = clamp_days(days)
        legacy_obj, new_obj = await asyncio.gather(C.get_principal(legacy_id),
                                                   C.get_principal(new_id))
        legacy_label, new_label = A.directory_label(legacy_obj), A.directory_label(new_obj)
        (legacy_ev, legacy_tr), (new_ev, new_tr) = await asyncio.gather(
            C.signins_for(legacy_id, is_user=_is_user(legacy_label), days=days,
                          max_items=settings.max_signin_events),
            C.signins_for(new_id, is_user=_is_user(new_label), days=days,
                          max_items=settings.max_signin_events),
        )
        legacy_app = await section(C.get_application(legacy_obj.get("appId")), "Application.Read.All")
        targets = [legacy_id] + ([legacy_app["data"]["id"]]
                                 if legacy_app["status"] == "ok" and legacy_app["data"] else [])
        changes = await section(C.directory_changes(targets, days), "AuditLog.Read.All")
        sensitive = ([A.summarise_audit(a) for a in changes["data"]
                      if A.classify_activity(a.get("activityDisplayName") or "") == "high"]
                     if changes["status"] == "ok" else None)

        legacy_res = {e.get("resourceDisplayName") or "unknown" for e in legacy_ev}
        new_res = {e.get("resourceDisplayName") or "unknown" for e in new_ev}
        new_fail = sum(1 for e in new_ev if A.failure(e))
        rate = round(new_fail / len(new_ev), 3) if new_ev else None
        new_ca = A.applied_ca_summary(new_ev)
        ca_failures = [p for p in new_ca if any(k in ("failure", "reportOnlyFailure")
                                                for k in p["results"])]
        # Graph omits CA details without Policy.Read.All; absent != "no policies applied". [ML]
        ca_visible = any("appliedConditionalAccessPolicies" in e for e in new_ev)
        threshold = settings.t("cutover_max_failure_rate")
        checks = {
            "new_identity_is_native_agent": new_label.startswith("entra_agent"),
            "new_identity_active": bool(new_ev),
            "legacy_still_active": bool(legacy_ev),
            "resources_only_on_legacy": sorted(legacy_res - new_res),
            "new_identity_failure_rate": rate,
            "ca_policies_failing_on_new_identity": (ca_failures if ca_visible else
                                                    "unknown (needs Policy.Read.All)"),
            "sensitive_changes_on_legacy": (len(sensitive) if sensitive is not None
                                            else f"unknown ({changes['status']})"),
        }
        unknowns = [k for k, v in checks.items() if isinstance(v, str) and v.startswith("unknown")]
        ready = (checks["new_identity_is_native_agent"] and checks["new_identity_active"]
                 and not checks["resources_only_on_legacy"] and (rate or 0) <= threshold
                 and not ca_failures and sensitive == [] and not unknowns)
        return {
            "days": days,
            "legacy": {"principal": A.principal_view(legacy_obj), "classification": legacy_label,
                       "summary": A.summarise_signins(legacy_ev, legacy_tr)},
            "new": {"principal": A.principal_view(new_obj), "classification": new_label,
                    "summary": A.summarise_signins(new_ev, new_tr),
                    "conditional_access_results": new_ca},
            "checks": checks,
            "sensitive_changes_on_legacy": sensitive,
            "cutover_signal": "looks ready for review" if ready else "not ready",
            "unknown_checks": unknowns,
            "note": f"[A] Indicative only. Thresholds (failure rate <= {threshold}, resource "
                    "parity, no CA failures, no sensitive legacy changes) are this project's defaults.",
        }

    @server.tool(annotations=READ_ONLY)
    @audited
    async def get_credential_inventory(object_id: str) -> dict[str, Any]:
        """List the credentials registered for a principal in the directory - secrets,
        certificates and federated credentials, on both the app registration and the
        service principal - with expiry, plus the migration wave they imply.

        Credentials expiring soon are flagged: migrate those identities instead of
        rotating them.

        Args:
            object_id: Object ID (GUID) of the service principal, MI or agent identity.
        """
        oid = check_guid(object_id, "object_id")
        sp = await C.get_principal(oid)
        label = A.directory_label(sp)
        if _is_user(label):
            raise InvalidInput("object_id is a user; credential inventory applies to service "
                             "principals, managed identities and agent identities.")
        bundle = await _credential_bundle(sp, label)
        return {"principal": A.principal_view(sp), "directory_classification": label,
                "warning_window_days": settings.t("credential_expiry_warning_days"), **bundle}

    @server.tool(annotations=READ_ONLY)
    @audited
    async def get_access_footprint(object_id: str) -> dict[str, Any]:
        """Everything a principal can reach and everyone who owns or depends on it:
        application permissions (resolved to names), delegated grants, directory
        roles, owners, sponsors (agent identities and blueprint principals) and inbound consumers. Ends with
        migration blockers, such as a privileged directory role.

        Each section reports its own status; a missing Graph permission produces a
        labelled gap instead of failing the whole call.

        Args:
            object_id: Object ID (GUID) of the service principal, MI or agent identity.
        """
        oid = check_guid(object_id, "object_id")
        sp = await C.get_principal(oid)
        label = A.directory_label(sp)
        if _is_user(label):
            raise InvalidInput("object_id is a user; use this for service principals, managed "
                             "identities and agent identities.")

        async def app_roles() -> list[dict[str, Any]]:
            items, resources = await C.get_app_role_assignments(oid)
            return A.resolve_app_roles(items, resources)

        app_section = await section(C.get_application(sp.get("appId")), "Application.Read.All")
        app = app_section.get("data") if app_section["status"] == "ok" else None
        tasks = {
            "application_permissions": section(app_roles(), "Application.Read.All"),
            "delegated_grants": section(C.get_delegated_grants(oid), "Directory.Read.All"),
            "directory_roles": section(C.get_directory_roles(oid), "RoleManagement.Read.Directory"),
            "owners_service_principal": section(C.get_owners(f"/servicePrincipals/{oid}"),
                                                "Application.Read.All"),
            "inbound_consumers": section(C.get_consumers(oid), "Application.Read.All"),
        }
        if app:
            tasks["owners_app_registration"] = section(C.get_owners(f"/applications/{app['id']}"),
                                                       "Application.Read.All")
        if label in C.SPONSOR_SOURCES:
            tasks["sponsors"] = section(C.get_sponsors(oid, label), C.SPONSOR_SOURCES[label][2])
        keys = list(tasks)
        values = await asyncio.gather(*tasks.values())
        sections = dict(zip(keys, values))

        perms = sections["application_permissions"]
        high_risk = ([p for p in perms["data"] if p["high_risk"]] if perms["status"] == "ok" else None)
        return {
            "principal": A.principal_view(sp), "directory_classification": label,
            **sections,
            "high_risk_permissions": high_risk,
            "migration_blockers": A.migration_blockers(sections["directory_roles"],
                                                       sections["delegated_grants"],
                                                       sections["inbound_consumers"], sp),
            "gaps": ["Directory roles: active direct assignments only; PIM-eligible and "
                     "group-inherited roles aren't included.",
                     "Azure RBAC (subscription/resource roles) isn't covered by Graph."],
        }

    @server.tool(annotations=READ_ONLY)
    @audited
    async def get_conditional_access_coverage(object_id: str) -> dict[str, Any]:
        """Which Conditional Access policies actually cover this principal, which only
        report, which exclude it, and the cases that leave it unprotected:
        managed identities (not covered), group-only assignment (not enforced for
        service principals), and filter-based policies that need manual checking.

        Args:
            object_id: Object ID (GUID) of the service principal, MI, agent identity or agent user.
        """
        oid = check_guid(object_id, "object_id")
        obj = await C.get_principal(oid)
        label = A.directory_label(obj)
        policies = await C.list_ca_policies()
        ids = [oid, obj.get("appId"), obj.get("agentIdentityBlueprintId")]
        groups_section = (await section(C.get_group_ids(oid), "GroupMember.Read.All [U]")
                          if not _is_user(label) else {"status": "skipped"})
        group_ids = groups_section.get("data") if groups_section["status"] == "ok" else None
        tenant_id = (await C.g().token_claims()).get("tid")
        owner = obj.get("appOwnerOrganizationId")
        owned_here = not owner or not tenant_id or owner.lower() == tenant_id.lower()
        result = A.evaluate_ca(policies, label, ids, group_ids, owned_by_tenant=owned_here)
        if label.startswith("entra_agent"):
            result["notes"].append("Agent policies require Microsoft 365 E7, or Agent 365 with "
                                   "Entra P1 / M365 E3. A policy targeting the agent identity "
                                   "doesn't cover its agent user, and vice versa. [ML]")
        elif label == "service_principal":
            result["notes"].append("Creating or changing CA policies for workload identities "
                                   "needs Workload Identities Premium. [ML]")
        return {"principal": A.principal_view(obj), "directory_classification": label,
                "policies_evaluated": len(policies),
                "group_membership_check": groups_section["status"], **result}

    @server.tool(annotations=READ_ONLY)
    @audited
    async def get_principal_changes(object_id: str, days: int = 30,
                                    min_severity: str = "low") -> dict[str, Any]:
        """Directory changes made to a principal and its app registration: credentials
        added, owners changed, permissions granted, enable/disable. During
        coexistence, any credential added to the legacy identity is a red flag.

        Args:
            object_id: Object ID (GUID) of the principal.
            days: Lookback window (1-30, default 30).
            min_severity: Lowest severity to return: info, low, medium or high.
        """
        oid = check_guid(object_id, "object_id")
        days = clamp_days(days)
        order = ["info", "low", "medium", "high"]
        if min_severity not in order:
            raise InvalidInput(f"min_severity must be one of {order}")
        obj = await C.get_principal(oid)
        targets = [oid]
        if not _is_user(A.directory_label(obj)):
            app = await section(C.get_application(obj.get("appId")), "Application.Read.All")
            if app["status"] == "ok" and app["data"]:
                targets.append(app["data"]["id"])
        events = [A.summarise_audit(a) for a in await C.directory_changes(targets, days)]
        kept = [e for e in events if order.index(e["severity"]) >= order.index(min_severity)]
        return {"principal": A.principal_view(obj), "days": days, "targets_queried": targets,
                "total_events": len(events),
                "by_severity": dict(Counter(e["severity"] for e in events)),
                "events": kept[:200], "truncated": len(kept) > 200}

    @server.tool(annotations=READ_ONLY)
    @audited
    async def check_access() -> dict[str, Any]:
        """Self-test: which Graph permissions this server actually has, which tools
        each missing one affects, and whether the beta agent fields are present.
        Run this first in a new tenant."""
        return await run_access_check()

    from . import assess

    assess.register(server)


PROBES = (
    # (permission, required?, path, beta, params, affects)
    ("AgentIdentity.Read.All", "required", "/servicePrincipals/microsoft.graph.agentIdentity",
     False, {"$top": "1"}, ["list_ownerless_agents"]),
    ("Application.Read.All", "required", "/applications", False, {"$top": "1", "$select": "id"},
     ["classify_principal", "get_credential_inventory", "get_access_footprint"]),
    ("AuditLog.Read.All (sign-ins, beta)", "required", "/auditLogs/signIns", True,
     {"$top": "1", "$filter": "signInEventTypes/any(t: t eq 'servicePrincipal')"},
     ["get_agent_signins", "compare_coexistence"]),
    ("AuditLog.Read.All (sign-in summaries, beta)", "required",
     "/auditLogs/getSummarizedServicePrincipalSignIns(aggregationWindow='d1')", True, {"$top": "1"},
     ["classify_principal", "assess_principals"]),
    ("AuditLog.Read.All (directory audits)", "required", "/auditLogs/directoryAudits", False,
     {"$top": "1"}, ["get_principal_changes", "compare_coexistence"]),
    ("Policy.Read.All", "recommended", "/identity/conditionalAccess/policies", False,
     {"$top": "1"}, ["get_conditional_access_coverage", "CA results in sign-ins"]),
    ("RoleManagement.Read.Directory", "recommended", "/roleManagement/directory/roleAssignments",
     True, {"$top": "1"}, ["get_access_footprint (directory roles, privileged-role blocker)"]),
    ("Directory.Read.All", "optional", "/oauth2PermissionGrants", False, {"$top": "1"},
     ["get_access_footprint (delegated grants)"]),
    ("GroupMember.Read.All [U]", "optional", "/groups", False, {"$top": "1", "$select": "id"},
     ["get_conditional_access_coverage (group-assignment check)"]),
)


async def run_access_check() -> dict[str, Any]:
    from . import collectors

    g = collectors.g()
    claims = await g.token_claims()
    results, agent_fields = [], None
    for permission, level, path, beta, params, affects in PROBES:
        try:
            data = await g.get(path, params=params, beta=beta,
                               headers=collectors.PREFER_ENUMS if beta else None)
            status = "ok"
            rid = None
            if path == "/auditLogs/signIns" and data.get("value"):
                agent_fields = "agent" in data["value"][0]
        except GraphError as exc:
            status = "missing" if exc.status in (401, 403) else f"error {exc.status}"
            rid = exc.request_id
        results.append({"permission": permission, "level": level, "status": status,
                        "affects": affects, "graph_request_id": rid})
    missing_required = [r["permission"] for r in results
                        if r["level"] == "required" and r["status"] != "ok"]
    return {
        "tenant_id": claims.get("tid"), "app_id": claims.get("appid") or claims.get("azp"),
        "granted_app_roles": sorted(claims.get("roles") or []),
        "probes": results,
        "beta_agent_fields_in_signins": (agent_fields if agent_fields is not None
                                         else "unknown (no sign-in returned)"),
        "ready": not missing_required, "missing_required": missing_required,
        "note": "Directory.Read.All is broad; grant it only if you need delegated grants.",
    }
