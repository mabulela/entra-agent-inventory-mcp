"""Pure analysis functions: no Graph calls, no I/O. Easy to unit-test.

Platform facts relied on here:
  [ML] @odata.type #microsoft.graph.agentIdentity identifies an agent identity.
  [ML] Sign-in agent fields (agent.agentType / agentSubjectType) are Graph beta.
  [ML] CA for workload identities: managed identities and multitenant / Microsoft
       apps aren't covered; group-assigned policies aren't enforced for service
       principals - the SP must be assigned directly.
  [ML] CA "Users" assignments don't apply to agent users.
  [F]  Managed identity SPs carry alternativeNames with "isExplicit=True" for
       user-assigned identities and the Azure resource ID.
  [A]  Scoring weights, wave mapping, severity keywords: design choices of this project.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

from .config import settings

AGENTIC_TYPES = {"agenticApp", "agenticAppInstance", "agentIdentityBlueprintPrincipal", "agentIDuser"}

FIC_ISSUERS = (
    ("token.actions.githubusercontent.com", "GitHub Actions"),
    ("oic.prod-aks.azure.com", "AKS / Kubernetes"),
    ("login.microsoftonline.com", "Microsoft Entra (managed identity as credential)"),
    ("sts.windows.net", "Microsoft Entra"),
    ("vstoken.dev.azure.com", "Azure DevOps"),
    ("app.terraform.io", "Terraform Cloud"),
)


# --- principals ---------------------------------------------------------------

def directory_label(obj: dict[str, Any]) -> str:
    odata_type = (obj.get("@odata.type") or "").lower()
    if odata_type.endswith("agentidentity"):
        return "entra_agent_identity"
    if odata_type.endswith("agentidentityblueprintprincipal"):
        return "entra_agent_blueprint_principal"
    if "agent" in odata_type and "user" in odata_type:
        return "entra_agent_user"
    if obj.get("servicePrincipalType") == "ManagedIdentity":
        return "managed_identity"
    if odata_type.endswith(".user") or "userPrincipalName" in obj:
        return "user"
    return "service_principal"


def principal_view(obj: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "displayName", "appId", "userPrincipalName", "servicePrincipalType",
            "agentIdentityBlueprintId", "createdByAppId", "appOwnerOrganizationId",
            "accountEnabled", "createdDateTime", "tags")
    view = {k: obj.get(k) for k in keys if obj.get(k) not in (None, [], "")}
    view["odata_type"] = obj.get("@odata.type")
    return view


def managed_identity_kind(sp: dict[str, Any]) -> dict[str, Any]:
    names = sp.get("alternativeNames") or []
    explicit = next((n for n in names if n.lower().startswith("isexplicit=")), None)
    resource = next((n for n in names if n.startswith("/subscriptions/")), None)
    if explicit is None:
        kind = "unknown"
    else:
        kind = "user-assigned" if explicit.split("=", 1)[1].lower() == "true" else "system-assigned"
    return {"kind": kind, "azure_resource_id": resource, "confidence": "[F]"}


# --- sign-ins ------------------------------------------------------------------

def is_ai_resource(event: dict[str, Any]) -> bool:
    name = (event.get("resourceDisplayName") or "").lower()
    return any(hint in name for hint in settings.t("ai_resource_hints"))


def agent_type(event: dict[str, Any]) -> str:
    return (event.get("agent") or {}).get("agentType") or "notAgentic"


def failure(event: dict[str, Any]) -> bool:
    return (event.get("status") or {}).get("errorCode", 0) not in (0, None)


def summarise_signins(events: list[dict[str, Any]], truncated: bool) -> dict[str, Any]:
    if not events:
        return {"total": 0, "truncated": truncated}
    failures = [e for e in events if failure(e)]
    times = sorted(e["createdDateTime"] for e in events if e.get("createdDateTime"))
    return {
        "total": len(events),
        "truncated": truncated,
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "failures": len(failures),
        "failure_rate": round(len(failures) / len(events), 3),
        "top_failure_reasons": Counter(
            (e.get("status") or {}).get("failureReason") or "unknown" for e in failures
        ).most_common(5),
        "resources": Counter(e.get("resourceDisplayName") or "unknown" for e in events).most_common(15),
        "event_types": Counter(t for e in events for t in (e.get("signInEventTypes") or [])).most_common(),
        "agent_types_seen": Counter(agent_type(e) for e in events).most_common(),
        "credential_types": Counter(e.get("clientCredentialType") or "n/a" for e in events).most_common(),
        "conditional_access": Counter(e.get("conditionalAccessStatus") or "n/a" for e in events).most_common(),
        "distinct_ip_addresses": len({e.get("ipAddress") for e in events if e.get("ipAddress")}),
    }


def applied_ca_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-policy result counts from sign-ins (needs Policy.Read.All, else empty). [ML]"""
    per_policy: dict[str, Counter] = {}
    names: dict[str, str] = {}
    for e in events:
        for p in e.get("appliedConditionalAccessPolicies") or []:
            pid = p.get("id") or p.get("displayName") or "unknown"
            names[pid] = p.get("displayName") or pid
            per_policy.setdefault(pid, Counter())[p.get("result") or "unknown"] += 1
    return [{"policy_id": pid, "display_name": names[pid], "results": dict(c)}
            for pid, c in sorted(per_policy.items(), key=lambda kv: names[kv[0]])]


def _wave(credential: str, wave: str, source: str, **extra: Any) -> dict[str, Any]:
    return {"credential": credential, "wave": wave, "source": source, **extra}


# --- credentials (directory) ------------------------------------------------------

def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def describe_credential(entry: dict[str, Any], kind: str, owner: str,
                        now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    end = _parse_dt(entry.get("endDateTime"))
    days_left = (end - now).days if end else None
    warn = settings.t("credential_expiry_warning_days")
    status = ("no_expiry" if end is None else "expired" if days_left < 0
              else "expiring" if days_left <= warn else "valid")
    out = {
        "type": kind, "on": owner, "display_name": entry.get("displayName"),
        "key_id": entry.get("keyId"), "start": entry.get("startDateTime"),
        "end": entry.get("endDateTime"), "days_to_expiry": days_left, "status": status,
    }
    if kind == "certificate":
        out["usage"] = entry.get("usage")
    return out


def describe_fic(fic: dict[str, Any]) -> dict[str, Any]:
    issuer = fic.get("issuer") or ""
    source = next((label for marker, label in FIC_ISSUERS if marker in issuer), "external IdP")
    return {"type": "federated", "name": fic.get("name"), "issuer": issuer,
            "subject": fic.get("subject"), "audiences": fic.get("audiences"), "source": source}


def credential_inventory(app: dict[str, Any] | None, sp: dict[str, Any],
                         fics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    creds: list[dict[str, Any]] = []
    for owner, obj in (("application", app), ("service_principal", sp)):
        if not obj:
            continue
        creds += [describe_credential(c, "secret", owner) for c in obj.get("passwordCredentials") or []]
        for c in obj.get("keyCredentials") or []:
            # Signing certificates on an SP (SAML) are not sign-in credentials.
            if owner == "service_principal" and c.get("usage") == "Sign":
                continue
            creds.append(describe_credential(c, "certificate", owner))
    creds += [describe_fic(f) for f in fics]
    return creds


def wave_from_directory(label: str, sp: dict[str, Any], creds: list[dict[str, Any]],
                        inbound_consumers: int | None) -> dict[str, Any]:
    """[A] Migration wave derived from the credential type:
    1 secret/no consumers, 2 secret/with consumers, 3 certificate, 4 WIF,
    5 system-assigned MI, 6 user-assigned MI."""
    if label == "managed_identity":
        mi = managed_identity_kind(sp)
        wave = {"user-assigned": "6", "system-assigned": "5"}.get(mi["kind"], "5 or 6")
        return _wave(f"{mi['kind']} managed identity", wave, "directory",
                     azure_resource_id=mi["azure_resource_id"], confidence="[F]")
    if label.startswith("entra_agent"):
        return _wave("blueprint-managed", "already migrated", "directory")
    active = [c for c in creds if c.get("status") != "expired"]
    types = {c["type"] for c in active}
    if not types:
        return _wave("no active credential found", "unknown", "directory")
    consumers_note = None
    if "secret" in types:
        if inbound_consumers is None:
            wave = "1 or 2"
        else:
            wave = "2" if inbound_consumers > 0 else "1"
            consumers_note = (f"{inbound_consumers} principal(s) hold app roles on this app"
                              if inbound_consumers else "no app-role consumers found")
        cred = "client secret" + (" (plus other types)" if len(types) > 1 else "")
    elif "certificate" in types:
        wave, cred = "3", "certificate" + (" (plus federation)" if "federated" in types else "")
    else:
        wave, cred = "4", "workload identity federation"
    out = _wave(cred, wave, "directory")
    if consumers_note:
        out["consumers"] = consumers_note
        out["note"] = ("Consumers that validate this appId out-of-band (custom middleware, "
                       "MCP allowlists) aren't visible in the directory.")
    return out


# --- access footprint ------------------------------------------------------------

def resolve_app_roles(assignments: list[dict[str, Any]],
                      resources: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    high_risk = settings.high_risk_permissions
    out = []
    for a in assignments:
        res = resources.get(a.get("resourceId") or "", {})
        role = next((r for r in res.get("appRoles") or [] if r.get("id") == a.get("appRoleId")), {})
        value = role.get("value") or ("default access" if a.get("appRoleId") ==
                                      "00000000-0000-0000-0000-000000000000" else a.get("appRoleId"))
        out.append({"resource": a.get("resourceDisplayName") or res.get("displayName"),
                    "resource_id": a.get("resourceId"), "permission": value,
                    "high_risk": value in high_risk, "granted": a.get("createdDateTime")})
    return sorted(out, key=lambda r: (not r["high_risk"], r["resource"] or "", r["permission"] or ""))


def migration_blockers(roles: dict[str, Any], grants: dict[str, Any],
                       consumers: dict[str, Any], sp: dict[str, Any]) -> list[str]:
    """[A] Checks that block or complicate a move to an agent identity."""
    blockers = []
    if roles.get("status") == "ok":
        priv = [r["role"] for r in roles["data"] if r.get("is_privileged")]
        if priv:
            blockers.append(f"Holds privileged directory role(s) {priv}; privileged roles can't be "
                            "assigned to an agent identity. Redesign or use "
                            "human-initiated PIM before migrating.")
    if grants.get("status") == "ok" and grants["data"]:
        blockers.append(f"{len(grants['data'])} delegated permission grant(s): the blueprint must "
                        "declare the same delegated scopes and users or an admin must re-consent.")
    if consumers.get("status") == "ok" and consumers["data"]:
        blockers.append(f"{len(consumers['data'])} principal(s) hold app roles on this app: "
                        "coordinate audience/appId changes with them (wave 2 pattern).")
    owner_tenant = sp.get("appOwnerOrganizationId")
    if owner_tenant and owner_tenant in set(settings.t("microsoft_owner_tenants")):
        blockers.append("Microsoft first-party app: not a migration candidate.")
    return blockers


# --- conditional access ----------------------------------------------------------

def find_references(obj: Any, needles: set[str], path: str = "") -> list[str]:
    """Paths inside a policy where any of the IDs appear, whatever the field name.
    Used for agent targeting, whose Graph field names aren't documented yet. [U]"""
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits += find_references(v, needles, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for v in obj:
            hits += find_references(v, needles, path)
    elif isinstance(obj, str) and obj.lower() in needles:
        hits.append(path)
    return sorted(set(hits))


def evaluate_ca(policies: list[dict[str, Any]], label: str, ids: Iterable[str],
                group_ids: set[str] | None, owned_by_tenant: bool = True) -> dict[str, Any]:
    needles = {i.lower() for i in ids if i}
    if label == "service_principal" and not owned_by_tenant:
        return {"verdict": "not covered", "enforced": [], "report_only": [], "excluded_by": [],
                "filter_based": [], "other_references": [], "group_assignment_ineffective": [],
                "notes": ["This app is registered in another tenant (multitenant or third-party). "
                          "CA for workload identities covers only single-tenant service principals "
                          "registered in your tenant. [ML]"]}
    enforced, report_only, excluded, filter_based, group_only, other_refs = [], [], [], [], [], []
    for p in policies:
        state = p.get("state")
        if state == "disabled":
            continue
        cond = p.get("conditions") or {}
        ca = cond.get("clientApplications") or {}
        include = {s.lower() for s in ca.get("includeServicePrincipals") or []}
        exclude = {s.lower() for s in ca.get("excludeServicePrincipals") or []}
        brief = {"id": p.get("id"), "name": p.get("displayName"), "state": state,
                 "grant": (p.get("grantControls") or {}).get("builtInControls")}
        if needles & exclude:
            excluded.append(brief)
            continue
        matched = bool(needles & include) or (
            "serviceprincipalsinmytenant" in include and label == "service_principal")
        if matched:
            (enforced if state == "enabled" else report_only).append(brief)
            continue
        if ca.get("servicePrincipalFilter"):
            filter_based.append({**brief, "rule": (ca["servicePrincipalFilter"] or {}).get("rule")})
            continue
        refs = find_references(cond, needles)
        if refs:
            other_refs.append({**brief, "referenced_at": refs})
            continue
        if group_ids:
            inc_groups = {g.lower() for g in (cond.get("users") or {}).get("includeGroups") or []}
            if inc_groups & group_ids:
                group_only.append(brief)

    notes = []
    if label == "managed_identity":
        notes.append("Managed identities aren't covered by Conditional Access. [ML] "
                     "Use access reviews and least-privilege RBAC instead.")
    if group_only:
        notes.append("Policies reach this principal only through group membership; that is "
                     "not enforced for service principals or agent users - assign directly. [ML]")
    if filter_based:
        notes.append("Some policies use a custom-security-attribute filter; check the "
                     "principal's attributes against the rule. [ML]")
    if other_refs:
        notes.append("Some policies reference this principal outside includeServicePrincipals "
                     "(likely agent or blueprint targeting). Field names unverified. [U]")
    verdict = ("enforced" if enforced else "report-only" if report_only
               else "not covered")
    return {"verdict": verdict, "enforced": enforced, "report_only": report_only,
            "excluded_by": excluded, "filter_based": filter_based,
            "other_references": other_refs, "group_assignment_ineffective": group_only,
            "notes": notes}


# --- directory changes -----------------------------------------------------------

def classify_activity(name: str) -> str:
    lowered = (name or "").lower()
    for keyword, severity in settings.t("sensitive_activity_keywords"):
        if keyword in lowered:
            return severity
    return "info"


def summarise_audit(a: dict[str, Any]) -> dict[str, Any]:
    init = a.get("initiatedBy") or {}
    user, app = init.get("user") or {}, init.get("app") or {}
    targets = []
    for t in a.get("targetResources") or []:
        targets.append({
            "id": t.get("id"), "type": t.get("type"), "name": t.get("displayName"),
            "agent_type": t.get("agentType"),
            "changed": [{"property": m.get("displayName"),
                         "old": (m.get("oldValue") or "")[:200],
                         "new": (m.get("newValue") or "")[:200]}
                        for m in t.get("modifiedProperties") or []],
        })
    return {
        "time": a.get("activityDateTime"), "activity": a.get("activityDisplayName"),
        "severity": classify_activity(a.get("activityDisplayName") or ""),
        "result": a.get("result"), "category": a.get("category"),
        "initiated_by": {"user": user.get("userPrincipalName"), "user_id": user.get("id"),
                         "app": app.get("displayName"),
                         "app_sp_id": app.get("servicePrincipalId"),
                         "agent_type": user.get("agentType") or app.get("agentType")},
        "targets": targets,
    }
