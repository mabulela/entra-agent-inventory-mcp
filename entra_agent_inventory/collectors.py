"""Graph data collection. Every query is fixed and parameterised with validated
GUIDs; nothing here accepts a free-form path or filter.

Graph permissions per collector (application, least privileged):
  principal, credentials, app roles, owners, consumers   Application.Read.All [ML]
  agent identities                                       AgentIdentity.Read.All [ML]
  sign-ins (beta), directory audits                      AuditLog.Read.All [ML]
  directory role assignments (beta, isPrivileged)        RoleManagement.Read.Directory [ML]
  delegated permission grants                            Directory.Read.All [ML] (broad - optional)
  conditional access policies, CA results in sign-ins    Policy.Read.All [ML]
  group memberships                                      GroupMember.Read.All [U]
  users (classify user objects)                          User.Read.All
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from . import graph as graph_mod
from .config import settings
from .graph import GraphError
from .validation import GUID_RE, since

PREFER_ENUMS = {"Prefer": "include-unknown-enum-members"}
SERVICE_EVENT_TYPES = ("servicePrincipal", "managedIdentity")
USER_EVENT_TYPES = ("interactiveUser", "nonInteractiveUser")
SIGNIN_SELECT = ",".join([
    "id", "createdDateTime", "servicePrincipalId", "servicePrincipalName", "userId",
    "userPrincipalName", "appId", "appDisplayName", "resourceDisplayName", "resourceId",
    "status", "signInEventTypes", "clientCredentialType", "federatedCredentialId",
    "managedServiceIdentity", "agent", "conditionalAccessStatus", "ipAddress",
    "appliedConditionalAccessPolicies",
])
SP_SELECT = ",".join([
    "id", "appId", "displayName", "servicePrincipalType", "appOwnerOrganizationId",
    "accountEnabled", "createdDateTime", "tags", "alternativeNames",
    "passwordCredentials", "keyCredentials", "appRoles", "replyUrls",
])


def g() -> graph_mod.GraphClient:
    return graph_mod.graph  # looked up at call time so tests can swap it


# --- principals ---------------------------------------------------------------

async def get_principal(object_id: str) -> dict[str, Any]:
    """Service principal first (covers agent identities and MIs), then user."""
    try:
        sp = await g().get(f"/servicePrincipals/{object_id}")
        if "alternativeNames" not in sp or "passwordCredentials" not in sp:
            # Some tenants return a reduced default property set; ask explicitly.
            try:
                extra = await g().get(f"/servicePrincipals/{object_id}", params={"$select": SP_SELECT})
                sp = {**extra, **sp}
            except GraphError:
                pass
        return sp
    except GraphError as exc:
        if exc.status != 404:
            raise
    return await g().get(
        f"/users/{object_id}",
        params={"$select": "id,displayName,userPrincipalName,userType,accountEnabled"},
    )


async def get_service_principal(object_id: str) -> dict[str, Any]:
    return await g().get(f"/servicePrincipals/{object_id}")


AGENT_IDENTITIES = "/servicePrincipals/microsoft.graph.agentIdentity"
AGENT_SELECT = ("id,appId,displayName,accountEnabled,agentIdentityBlueprintId,createdByAppId,"
                "createdDateTime,servicePrincipalType,tags,disabledByMicrosoftStatus")


async def find_ownerless_agents(scan_limit: int) -> dict[str, Any]:
    """Native agent identities with no owners.

    Graph filters on owners/$count eq 0 as an advanced query (ConsistencyLevel:
    eventual + $count). [ML] If Graph refuses it on agent identities, read up to
    scan_limit identities and check their owners through $batch instead. Graph refuses
    with 400, or with a repeatable 500 on the agentIdentity cast [F] (lab tenant, 2026-10-20).
    """
    params = {"$select": AGENT_SELECT, "$top": "100", "$filter": "owners/$count eq 0",
              "$count": "true"}
    try:
        items, truncated = await g().get_all(AGENT_IDENTITIES, params=params,
                                             headers={"ConsistencyLevel": "eventual"},
                                             max_items=scan_limit)
        return {"items": items, "scan_limit_reached": truncated, "filtered_by": "graph"}
    except GraphError as exc:
        if exc.status not in (400, 500):
            raise
    items, truncated = await g().get_all(AGENT_IDENTITIES, params={"$top": "100"}, max_items=scan_limit)
    paths = {i["id"]: f"/servicePrincipals/{i['id']}/owners?$select=id" for i in items}
    owners = await g().batch_get(list(paths.values())) if paths else {}
    # Keep an identity only when Graph confirmed it has no owners; unknown isn't ownerless.
    items = [i for i in items if isinstance(owners.get(paths[i["id"]]), dict)
             and not owners[paths[i["id"]]].get("value")]
    return {"items": items, "scan_limit_reached": truncated,
            "filtered_by": f"this server (Graph rejected the filter; checked up to {scan_limit} agent identities)"}


async def sponsors_for(ids: list[str]) -> dict[str, list[dict[str, Any]] | None]:
    """Sponsors for a few agent identities through $batch. None means the lookup failed."""
    paths = {i: f"/servicePrincipals/{i}/microsoft.graph.agentIdentity/sponsors"
                f"?$select=id,displayName,userPrincipalName" for i in ids}
    results = await g().batch_get(list(paths.values()), beta=True)
    out: dict[str, list[dict[str, Any]] | None] = {}
    for i, p in paths.items():
        body = results.get(p)
        out[i] = ([{"name": x.get("displayName"), "upn": x.get("userPrincipalName")}
                   for x in body.get("value", [])] if isinstance(body, dict) else None)
    return out


# --- sign-ins --------------------------------------------------------------------

def event_type_clause(types: tuple[str, ...]) -> str:
    inner = " or ".join(f"t eq '{t}'" for t in types)
    return f"signInEventTypes/any(t: {inner})"


async def fetch_signins(filter_expr: str, *, max_items: int,
                        on_page: Callable[[int], Awaitable[None]] | None = None,
                        ) -> tuple[list[dict[str, Any]], bool]:
    params = {"$filter": filter_expr, "$top": "1000", "$select": SIGNIN_SELECT}
    try:
        return await g().get_all("/auditLogs/signIns", params=params, beta=True,
                                 headers=PREFER_ENUMS, max_items=max_items, on_page=on_page)
    except GraphError as exc:
        if exc.status not in (400, 500):
            raise
        params.pop("$select")  # retry once with the default property set
        return await g().get_all("/auditLogs/signIns", params=params, beta=True,
                                 headers=PREFER_ENUMS, max_items=max_items, on_page=on_page)


async def signins_for(object_id: str, *, is_user: bool, days: int,
                      max_items: int) -> tuple[list[dict[str, Any]], bool]:
    id_field = "userId" if is_user else "servicePrincipalId"
    types = USER_EVENT_TYPES if is_user else SERVICE_EVENT_TYPES
    f = (f"createdDateTime ge {since(days)} and {id_field} eq '{object_id}' "
         f"and {event_type_clause(types)}")
    return await fetch_signins(f, max_items=max_items)


async def service_signins(days: int, on_page: Callable[[int], Awaitable[None]] | None = None
                          ) -> tuple[list[dict[str, Any]], bool]:
    f = f"createdDateTime ge {since(days)} and {event_type_clause(SERVICE_EVENT_TYPES)}"
    return await fetch_signins(f, max_items=settings.max_signin_events, on_page=on_page)


# --- application object and credentials ------------------------------------------

async def get_application(app_id: str) -> dict[str, Any] | None:
    """The app registration behind a service principal, if it lives in this tenant."""
    if not app_id or not GUID_RE.match(app_id):  # Graph-sourced, but checked anyway
        return None
    try:
        return await g().get(
            f"/applications(appId='{app_id}')",
            params={"$select": "id,appId,displayName,passwordCredentials,keyCredentials,"
                               "signInAudience,createdDateTime,web"},
        )
    except GraphError as exc:
        if exc.status == 404:
            return None
        raise


async def get_fics(application_object_id: str) -> list[dict[str, Any]]:
    data = await g().get(f"/applications/{application_object_id}/federatedIdentityCredentials")
    return data.get("value", [])


async def get_consumers(sp_id: str) -> list[dict[str, Any]]:
    """Principals assigned app roles ON this app (inbound callers)."""
    items, _ = await g().get_all(f"/servicePrincipals/{sp_id}/appRoleAssignedTo",
                                 params={"$top": "100"}, max_items=500)
    return [{"principal": i.get("principalDisplayName"), "principal_id": i.get("principalId"),
             "principal_type": i.get("principalType")} for i in items]


# --- access footprint ---------------------------------------------------------------

_resource_cache: dict[str, dict[str, Any]] = {}


async def get_app_role_assignments(sp_id: str) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    items, _ = await g().get_all(f"/servicePrincipals/{sp_id}/appRoleAssignments",
                                 params={"$top": "100"}, max_items=1000)
    resources: dict[str, dict[str, Any]] = {}
    for rid in {i.get("resourceId") for i in items if i.get("resourceId")}:
        if rid not in _resource_cache:
            try:
                _resource_cache[rid] = await g().get(
                    f"/servicePrincipals/{rid}", params={"$select": "id,displayName,appId,appRoles"})
            except GraphError:
                _resource_cache[rid] = {}
        resources[rid] = _resource_cache[rid]
    return items, resources


async def get_delegated_grants(sp_id: str) -> list[dict[str, Any]]:
    data = await g().get(f"/servicePrincipals/{sp_id}/oauth2PermissionGrants")
    return [{"resource_id": x.get("resourceId"), "consent_type": x.get("consentType"),
             "user_id": x.get("principalId"), "scopes": (x.get("scope") or "").split()}
            for x in data.get("value", [])]


async def get_owners(path: str) -> list[dict[str, Any]]:
    data = await g().get(f"{path}/owners", params={"$select": "id,displayName,userPrincipalName"})
    return [{"id": o.get("id"), "name": o.get("displayName"), "upn": o.get("userPrincipalName"),
             "type": o.get("@odata.type")} for o in data.get("value", [])]


# Principals that carry sponsors: label -> (type cast, beta, permission).
# Agent identities: [U] path form, beta. Blueprint principals: v1.0, Application.Read.All [ML].
SPONSOR_SOURCES = {
    "entra_agent_identity": ("microsoft.graph.agentIdentity", True, "AgentIdentity.Read.All [U]"),
    "entra_agent_blueprint_principal": ("microsoft.graph.agentIdentityBlueprintPrincipal", False,
                                        "Application.Read.All"),
}


def sponsors_path(sp_id: str, label: str) -> str:
    return f"/servicePrincipals/{sp_id}/{SPONSOR_SOURCES[label][0]}/sponsors"


async def get_sponsors(sp_id: str, label: str = "entra_agent_identity") -> list[dict[str, Any]]:
    """Sponsors of an agent identity or blueprint principal; degrades gracefully if the path differs."""
    data = await g().get(sponsors_path(sp_id, label), beta=SPONSOR_SOURCES[label][1])
    return [{"id": o.get("id"), "name": o.get("displayName"), "upn": o.get("userPrincipalName")}
            for o in data.get("value", [])]


async def get_directory_roles(principal_id: str) -> list[dict[str, Any]]:
    """Active, directly assigned directory roles. PIM-eligible and group-inherited
    assignments are not included. isPrivileged is a beta property. [ML]"""
    data = await g().get("/roleManagement/directory/roleAssignments", beta=True, params={
        "$filter": f"principalId eq '{principal_id}'", "$expand": "roleDefinition"})
    out = []
    for a in data.get("value", []):
        rd = a.get("roleDefinition") or {}
        out.append({"role": rd.get("displayName"), "template_id": rd.get("templateId"),
                    "is_privileged": rd.get("isPrivileged"),
                    "scope": a.get("directoryScopeId")})
    return out


async def get_group_ids(sp_id: str) -> set[str]:
    items, _ = await g().get_all(f"/servicePrincipals/{sp_id}/transitiveMemberOf/microsoft.graph.group",
                                 params={"$select": "id"}, max_items=1000)
    return {i["id"].lower() for i in items if i.get("id")}


# --- conditional access and directory changes ---------------------------------------

async def list_ca_policies() -> list[dict[str, Any]]:
    items, _ = await g().get_all("/identity/conditionalAccess/policies", max_items=1000)
    return items


async def directory_changes(target_ids: list[str], days: int) -> list[dict[str, Any]]:
    """Directory audit events where any of the IDs is a target. [ML] targetResources
    supports $filter eq on id. Beta for the agentType fields."""
    async def one(tid: str) -> list[dict[str, Any]]:
        params = {"$filter": f"activityDateTime ge {since(days)} and "
                             f"targetResources/any(t: t/id eq '{tid}')", "$top": "500"}
        try:
            items, _ = await g().get_all("/auditLogs/directoryAudits", params=params, beta=True,
                                         headers=PREFER_ENUMS, max_items=1000)
        except GraphError as exc:
            if exc.status != 400:
                raise
            items, _ = await g().get_all("/auditLogs/directoryAudits", params=params, max_items=1000)
        return items

    results = await asyncio.gather(*(one(t) for t in target_ids if t and GUID_RE.match(t)))
    seen, merged = set(), []
    for batch in results:
        for item in batch:
            if item.get("id") not in seen:
                seen.add(item.get("id"))
                merged.append(item)
    return sorted(merged, key=lambda a: a.get("activityDateTime") or "", reverse=True)
