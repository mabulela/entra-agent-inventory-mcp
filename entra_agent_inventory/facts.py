"""Facts: the normalised inputs scoring.build_row() needs for one principal.

live_facts() builds them for one principal on demand (classify_principal,
assess_principals), normalising Graph responses with the helpers below.
"""

from __future__ import annotations

import asyncio
from typing import Any

from . import analysis as A
from . import collectors as C
from .config import settings
from .graph import GraphError
from .scoring import NATIVE_LABELS, confirming_tags, signin_facts
from .validation import since

SUMMARY_SP = "/auditLogs/getSummarizedServicePrincipalSignIns(aggregationWindow='d1')"
SUMMARY_MSI = "/auditLogs/getSummarizedMsiSignIns(aggregationWindow='d1')"
SP_LIST_SELECT = ("id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,"
                  "accountEnabled,createdDateTime,tags,alternativeNames,passwordCredentials,"
                  "keyCredentials,replyUrls")


# --- normalisers -------------------------------------------------------------------

def norm_people(value: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": o.get("id"), "name": o.get("displayName") or "",
             "upn": o.get("userPrincipalName") or o.get("mail") or "",
             "type": (o.get("@odata.type") or "").lower()} for o in value]


def norm_app_roles(assignments: list[dict[str, Any]],
                   resources: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"resource": r["resource"], "permission": r["permission"], "kind": "application",
             "high_risk": r["high_risk"]} for r in A.resolve_app_roles(assignments, resources)]


def norm_grants(grants: list[dict[str, Any]], resource_names: dict[str, str]) -> list[dict[str, Any]]:
    high = settings.high_risk_permissions
    out = []
    for gr in grants:
        for scope in (gr.get("scope") or "").split():
            out.append({"resource": resource_names.get(gr.get("resourceId"), gr.get("resourceId")),
                        "permission": scope, "kind": "delegated", "high_risk": scope in high})
    return out


def norm_roles(assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"role": (a.get("roleDefinition") or {}).get("displayName"),
             "is_privileged": bool((a.get("roleDefinition") or {}).get("isPrivileged"))}
            for a in assignments]


def creator_from_audit(item: dict[str, Any]) -> dict[str, Any]:
    init = item.get("initiatedBy") or {}
    user, app = init.get("user") or {}, init.get("app") or {}
    if user.get("userPrincipalName") or user.get("id"):
        return {"name": user.get("displayName") or user.get("userPrincipalName") or "",
                "upn": user.get("userPrincipalName") or "", "kind": "user"}
    return {"name": app.get("displayName") or "", "upn": "", "kind": "app"}


def is_microsoft(sp: dict[str, Any]) -> bool:
    """Microsoft first-party apps (Exchange, Graph ...): listed, not scored. Native agent
    identities never count, even when a Microsoft-owned blueprint (Copilot Studio)
    created them, and neither do legacy agents carrying a confirmed_agent_tags tag:
    they are your agents to govern."""
    if A.directory_label(sp) in NATIVE_LABELS or confirming_tags(sp):
        return False
    return (sp.get("appOwnerOrganizationId") or "").lower() in {
        t.lower() for t in settings.t("microsoft_owner_tenants")}


def ca_status(policies: list[dict[str, Any]] | None, sp: dict[str, Any], label: str,
              tenant_id: str | None) -> str:
    if policies is None:
        return "unknown"
    if is_microsoft(sp):
        return "not evaluated"
    if label == "managed_identity":
        return "not applicable"  # MIs aren't covered by CA [ML]
    owner = sp.get("appOwnerOrganizationId")
    owned = not owner or not tenant_id or owner.lower() == tenant_id.lower()
    verdict = A.evaluate_ca(policies, label,
                            [sp.get("id"), sp.get("appId"), sp.get("agentIdentityBlueprintId")],
                            None, owned_by_tenant=owned)["verdict"]
    return verdict


# --- live, one principal ---------------------------------------------------------------

async def live_facts(object_id: str, days: int, tenant_id: str | None,
                     policies: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Facts for one principal from live Graph calls. Missing permissions leave
    a section empty and are listed in facts['gaps'] instead of failing."""
    g = C.g()
    sp = await C.get_principal(object_id)
    label = A.directory_label(sp)
    gaps: list[str] = []
    facts: dict[str, Any] = {"sp": sp, "label": label, "microsoft_managed": is_microsoft(sp),
                             "gaps": gaps}

    async def opt(coro: Any, needs: str, default: Any = None) -> Any:
        try:
            return await coro
        except GraphError as exc:
            if exc.status in (401, 403):
                gaps.append(f"needs {needs}")
            elif exc.status != 404:
                gaps.append(f"{needs.split()[0]} lookup failed ({exc.status})")
            return default

    async def signins() -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        cutoff = since(days)
        for path in (SUMMARY_SP, SUMMARY_MSI):
            items, _ = await g.get_all(path, beta=True, headers=C.PREFER_ENUMS, max_items=5000,
                                       params={"$filter": f"servicePrincipalId eq '{object_id}'"})
            rows += [r for r in items if (r.get("aggregationDateTime") or "") >= cutoff[:10]]
        return signin_facts(rows)

    async def creator() -> dict[str, Any] | None:
        data = await g.get("/auditLogs/directoryAudits", params={
            "$filter": f"activityDateTime ge {since(30)} and activityDisplayName eq "
                       f"'Add service principal' and targetResources/any(t: t/id eq '{object_id}')",
            "$top": "1"})
        items = data.get("value", [])
        return creator_from_audit(items[0]) if items else None

    async def app_perms() -> list[dict[str, Any]]:
        items, resources = await C.get_app_role_assignments(object_id)
        return norm_app_roles(items, resources)

    async def grants() -> list[dict[str, Any]]:
        data = await g.get(f"/servicePrincipals/{object_id}/oauth2PermissionGrants")
        names = {rid: (C._resource_cache.get(rid) or {}).get("displayName", rid)
                 for rid in {x.get("resourceId") for x in data.get("value", [])}}
        return norm_grants(data.get("value", []), names)

    async def roles() -> list[dict[str, Any]]:
        data = await g.get("/roleManagement/directory/roleAssignments", beta=True, params={
            "$filter": f"principalId eq '{object_id}'", "$expand": "roleDefinition"})
        return norm_roles(data.get("value", []))

    async def owners(path: str) -> list[dict[str, Any]]:
        data = await g.get(f"{path}/owners", params={"$select": "id,displayName,userPrincipalName"})
        return norm_people(data.get("value", []))

    is_user = label in ("user", "entra_agent_user")
    facts["signins"] = await opt(signins(), "AuditLog.Read.All", {})
    if is_user or facts["microsoft_managed"]:
        # Users aren't scored; Microsoft apps are listed, not scored .
        return facts

    app = await opt(C.get_application(sp.get("agentIdentityBlueprintId")
                                      if label == "entra_agent_identity" else sp.get("appId")),
                    "Application.Read.All")
    fics = (await opt(C.get_fics(app["id"]), "Application.Read.All", [])) if app else []
    results = await asyncio.gather(
        opt(app_perms(), "Application.Read.All", []),
        opt(grants(), "Directory.Read.All", None),
        opt(roles(), "RoleManagement.Read.Directory", None),
        opt(owners(f"/servicePrincipals/{object_id}"), "Application.Read.All", None),
        opt(owners(f"/applications/{app['id']}"), "Application.Read.All", None) if app
        else asyncio.sleep(0, result=[]),
        opt(C.get_sponsors(object_id, label), C.SPONSOR_SOURCES[label][2], [])
        if label in C.SPONSOR_SOURCES else asyncio.sleep(0, result=[]),
        opt(creator(), "AuditLog.Read.All", None),
    )
    perms, delegated, role_list, sp_owners, app_owners, sponsors, created_by = results
    creds = A.credential_inventory(app, sp, fics) if label != "managed_identity" else []
    facts.update({
        "app_permissions": perms, "delegated": delegated or [], "roles": role_list or [],
        "sp_owners": sp_owners or [], "app_owners": app_owners or [], "sponsors": sponsors or [],
        "creator": created_by,
        "contacts_known": sp_owners is not None,
        "credentials": creds, "fic_count": len(fics),
        # For an agent identity, `app` is its blueprint: its redirect URIs aren't the identity's.
        "redirect_uris": ((app.get("web") or {}).get("redirectUris") or []
                          if app and label != "entra_agent_identity" else []),
        "wave": A.wave_from_directory(label, sp, creds, None)["wave"],
        "ca_status": ca_status(policies, sp, label, tenant_id),
    })
    return facts
