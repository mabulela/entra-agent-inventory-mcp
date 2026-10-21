"""Scoring: one engine for classify_principal and assess_principals, so both tools
answer with the same columns and rules.

Two separate numbers (decision: split):
  * Agent likelihood, 0 to the sum of the weights (21 by default): "is this an agent?"
    The sum of the weighted agent signals that fire. No cap.
  * Priority: likelihood plus exposure ("how urgent is it?").

Agent status:
  confirmed  native Entra Agent ID object (agent identity, blueprint principal, agent user),
             or a legacy service principal with a tag in confirmed_agent_tags (Copilot
             Studio's AgentCreatedBy:CopilotStudio / power-virtual-agents-*), whatever its score
  likely     legacy identity with likelihood >= likely_threshold (decided: 6)
  unlikely   everything else that is scored
  not_scored Microsoft first-party apps (decided: listed, not scored)

Priority (decided: likelihood + exposure):
  urgent          agent (confirmed or likely) with any high-severity exposure
  governance_gap  confirmed agent without an owner/sponsor, or with no CA coverage
  review          agent without high exposure, or an unlikely identity with a signal in
                  review_unlikely_signals (default: agent_like_name), so a person checks it
  ok              everything else
  microsoft_managed  not scored

All weights, thresholds and permission groups live in the config tuning. [A]
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .config import settings

# Code, label, kind, severity (exposure only). Order = output order.
SIGNALS: list[tuple[str, str, str, str]] = [
    ("created_by_agent_platform", "Created by Copilot Studio/Foundry", "likelihood", ""),
    ("connects_to_mcp", "Connects to MCP server", "likelihood", ""),
    ("ai_resource_access", "Azure OpenAI / Foundry sign-ins", "likelihood", ""),
    ("uses_ai_gateway", "Calls an AI gateway (APIM)", "likelihood", ""),
    ("agent_like_name", "Agent-like name", "likelihood", ""),
    ("agent_marker", "Agent tag or security attribute", "likelihood", ""),
    ("bot_framework_redirect", "Bot Framework redirect URI", "likelihood", ""),
    ("high_volume", "50+ daily sign-ins", "likelihood", ""),
    ("multi_resource", "3+ resources per day", "likelihood", ""),
    ("federated_credential", "Federated identity credential", "likelihood", ""),
    ("mail_send", "Mail.Send granted", "exposure", "high"),
    ("broad_files_write", "Broad SharePoint/Files write", "exposure", "high"),
    ("calendar_teams", "Calendar/Teams permissions", "exposure", "medium"),
    ("no_contact", "No owner, sponsor or creator", "exposure", "high"),
    ("privileged_role", "Privileged directory role", "exposure", "high"),
    ("other_high_risk", "Other high-risk permission", "exposure", "high"),
    ("credential_expiring", "Credential expiring or expired", "exposure", "medium"),
]
SIGNAL_CODES = [s[0] for s in SIGNALS]
SEVERITY = {s[0]: s[3] for s in SIGNALS if s[2] == "exposure"}
NATIVE_LABELS = {"entra_agent_identity", "entra_agent_blueprint_principal", "entra_agent_user"}

# Row columns returned by assess_principals (and usable as CSV headers).
PRINCIPAL_COLUMNS = [
    "object_id", "app_id", "display_name", "principal_type", "microsoft_managed",
    "agent_status", "likelihood", "priority", "signals", "exposures",
    *[f"sig_{c}" for c in SIGNAL_CODES],
    "contact_name", "contact_upn", "contact_type", "owner_count",
    "created_datetime", "created_by_app_id", "last_sign_in", "signins_30d",
    "active_days_30d", "max_daily_signins", "distinct_resources_30d", "ai_signins_30d",
    "top_resources", "app_permission_count", "top_permissions", "high_risk_permissions",
    "privileged_roles", "credential_types", "next_credential_expiry_days",
    "expired_credentials", "migration_wave", "ca_status", "evidence",
]
PERMISSION_COLUMNS = ["object_id", "display_name", "resource", "permission", "kind",
                      "category", "high_risk"]


# --- sign-in facts ------------------------------------------------------------------

def signin_facts(rows: list[dict[str, Any]], last_sign_in: str | None = None) -> dict[str, Any]:
    """Aggregate summarized sign-in rows (one per SP/resource/IP/day) into facts."""
    hints = [h.lower() for h in settings.t("ai_resource_hints")]
    mcp_ids = {i.lower() for i in settings.t("mcp_server_app_ids")}
    mcp_names = {n.lower() for n in settings.t("mcp_server_resource_names")}
    gw_ids = {i.lower() for i in settings.t("ai_gateway_app_ids")}
    gw_names = {n.lower() for n in settings.t("ai_gateway_resource_names")}
    per_day: dict[str, int] = {}
    per_day_resources: dict[str, set[str]] = {}
    per_resource: dict[str, int] = {}
    total = ai = mcp = gateway = 0
    agentic: set[str] = set()
    for r in rows:
        count = int(r.get("signInCount") or 0)
        day = (r.get("aggregationDateTime") or "")[:10]
        res = r.get("resourceDisplayName") or r.get("resourceId") or "unknown"
        total += count
        per_day[day] = per_day.get(day, 0) + count
        per_day_resources.setdefault(day, set()).add(res)
        per_resource[res] = per_resource.get(res, 0) + count
        if any(h in res.lower() for h in hints):
            ai += count
        if (r.get("resourceId") or "").lower() in mcp_ids or res.lower() in mcp_names:
            mcp += count
        if (r.get("resourceId") or "").lower() in gw_ids or res.lower() in gw_names:
            gateway += count
        at = (r.get("agent") or {}).get("agentType")
        if at and at != "notAgentic":
            agentic.add(at)
    return {
        "total": total, "active_days": len([d for d, c in per_day.items() if c]),
        "max_daily": max(per_day.values(), default=0),
        "max_daily_resources": max((len(v) for v in per_day_resources.values()), default=0),
        "resources": sorted(per_resource, key=per_resource.get, reverse=True),
        "ai_signins": ai, "mcp_signins": mcp, "gateway_signins": gateway, "agentic_types": sorted(agentic),
        "last_sign_in": last_sign_in or (max(per_day) if per_day else None),
    }


# --- signals -----------------------------------------------------------------------------

def _perm_names(perms: list[dict[str, Any]]) -> set[str]:
    return {p.get("permission") or "" for p in perms}


def confirming_tags(sp: dict[str, Any]) -> list[str]:
    """The principal's tags listed in confirmed_agent_tags (case-insensitive; a trailing *
    matches a prefix). Copilot Studio tags its legacy agents this way. [ML]"""
    patterns = [p.lower() for p in settings.t("confirmed_agent_tags")]
    return [tag for tag in sp.get("tags") or []
            if any(tag.lower().startswith(p[:-1]) if p.endswith("*") else tag.lower() == p
                   for p in patterns)]


def bot_framework_redirects(uris: list[str]) -> list[str]:
    """Redirect URIs whose host is a Bot Framework token service host or a subdomain of
    one. The host is parsed, so a look-alike such as token.botframework.com.example.net
    doesn't match."""
    hosts = [h.lower() for h in settings.t("bot_framework_redirect_hosts")]
    found = []
    for uri in uris:
        try:
            host = urlsplit(uri).hostname or ""
        except ValueError:
            continue
        if any(host == h or host.endswith("." + h) for h in hosts) and uri not in found:
            found.append(uri)
    return found


def detect_signals(f: dict[str, Any]) -> tuple[dict[str, bool], dict[str, str]]:
    """Returns (signal -> fired, signal -> evidence)."""
    sp = f["sp"]
    s = f.get("signins") or {}
    perms = f.get("app_permissions") or []
    names = _perm_names(perms) | {p.get("permission") or "" for p in f.get("delegated") or []}
    name_re = settings.agent_name_re
    hit: dict[str, bool] = {c: False for c in SIGNAL_CODES}
    why: dict[str, str] = {}

    creator_app = sp.get("createdByAppId")
    if creator_app and creator_app in set(settings.t("agent_creator_app_ids")):
        hit["created_by_agent_platform"], why["created_by_agent_platform"] = True, f"created by app {creator_app}"
    if s.get("mcp_signins"):
        hit["connects_to_mcp"], why["connects_to_mcp"] = True, f"{s['mcp_signins']} sign-ins to listed MCP servers"
    if s.get("ai_signins"):
        hit["ai_resource_access"], why["ai_resource_access"] = True, f"{s['ai_signins']} sign-ins to AI resources"
    if s.get("gateway_signins"):
        hit["uses_ai_gateway"], why["uses_ai_gateway"] = True, f"{s['gateway_signins']} sign-ins to AI gateway"
    if name_re.search(sp.get("displayName") or ""):
        hit["agent_like_name"], why["agent_like_name"] = True, "agent-like display name"
    tags = [t for t in sp.get("tags") or [] if name_re.search(t)]
    marker = settings.t("agent_security_attribute")
    csa = (f.get("csa") or {}).get(marker.get("set") or "", {}) if marker.get("set") else {}
    if tags or (csa and csa.get(marker.get("attribute"))):
        hit["agent_marker"], why["agent_marker"] = True, (f"tags {tags}" if tags else "security attribute")
    # Redirect URIs: the service principal's replyUrls, plus its own app registration's
    # web redirect URIs when the app lives in this tenant.
    bot = bot_framework_redirects((sp.get("replyUrls") or []) + (f.get("redirect_uris") or []))
    if bot:
        hit["bot_framework_redirect"], why["bot_framework_redirect"] = True, f"redirect URI {bot[0]}"
    if s.get("max_daily", 0) >= settings.t("high_volume_daily_signins"):
        hit["high_volume"], why["high_volume"] = True, f"peak {s['max_daily']} sign-ins/day"
    if s.get("max_daily_resources", 0) >= settings.t("multi_resource_daily"):
        hit["multi_resource"], why["multi_resource"] = True, f"{s['max_daily_resources']} resources in one day"
    if f.get("fic_count"):
        hit["federated_credential"], why["federated_credential"] = True, f"{f['fic_count']} federated credential(s)"

    mail = names & set(settings.t("mail_send_permissions"))
    if mail:
        hit["mail_send"], why["mail_send"] = True, ", ".join(sorted(mail))
    files = names & set(settings.t("broad_files_write_permissions"))
    if files:
        hit["broad_files_write"], why["broad_files_write"] = True, ", ".join(sorted(files))
    prefixes = tuple(settings.t("calendar_teams_permission_prefixes"))
    cal = sorted(n for n in names if n.startswith(prefixes))
    if cal:
        hit["calendar_teams"], why["calendar_teams"] = True, ", ".join(cal[:4])
    contact = f.get("contact") or resolve_contact(f)
    if contact["type"] == "none" and f.get("contacts_known", True):
        hit["no_contact"], why["no_contact"] = True, "no owner, sponsor or creator found"
    priv = [r["role"] for r in f.get("roles") or [] if r.get("is_privileged")]
    if priv:
        hit["privileged_role"], why["privileged_role"] = True, ", ".join(priv)
    grouped = set(settings.t("mail_send_permissions")) | set(settings.t("broad_files_write_permissions"))
    other = sorted((names & set(settings.t("high_risk_app_permissions"))) - grouped)
    if other:
        hit["other_high_risk"], why["other_high_risk"] = True, ", ".join(other[:4])
    creds = f.get("credentials") or []
    bad = [c for c in creds if c.get("status") in ("expiring", "expired") and c.get("type") != "federated"]
    if bad:
        hit["credential_expiring"], why["credential_expiring"] = True, \
            f"{len(bad)} credential(s) {'/'.join(sorted({c['status'] for c in bad}))}"
    return hit, why


def max_likelihood() -> int:
    """Top of the scale: every likelihood signal firing (21 with the default weights)."""
    return sum(settings.t("likelihood_weights").values())


def likelihood(hit: dict[str, bool]) -> int:
    weights = settings.t("likelihood_weights")
    return sum(w for code, w in weights.items() if hit.get(code))


def resolve_contact(f: dict[str, Any]) -> dict[str, str]:
    """First reachable contact: SP owner (user) > app owner (user) > sponsor > creator."""
    def first_user(items: list[dict[str, Any]] | None) -> dict[str, Any] | None:
        items = items or []
        users = [o for o in items if (o.get("type") or "").endswith("user") or o.get("upn")]
        return (users or items or [None])[0]

    for kind, items in (("sp_owner", f.get("sp_owners")), ("app_owner", f.get("app_owners")),
                        ("sponsor", f.get("sponsors"))):
        who = first_user(items)
        if who:
            return {"type": kind, "name": who.get("name") or "", "upn": who.get("upn") or ""}
    creator = f.get("creator")
    if creator and (creator.get("upn") or creator.get("name")):
        return {"type": "creator", "name": creator.get("name") or "", "upn": creator.get("upn") or ""}
    return {"type": "none", "name": "", "upn": ""}


def agent_status(label: str, microsoft: bool, score: int, tagged: bool = False) -> str:
    if label in NATIVE_LABELS or tagged:
        return "confirmed"
    if microsoft:
        return "not_scored"
    return "likely" if score >= settings.t("likely_threshold") else "unlikely"


def priority(status: str, hit: dict[str, bool], contact_type: str, ca_status: str) -> str:
    if status == "not_scored":
        return "microsoft_managed"
    agent = status in ("confirmed", "likely")
    high = any(hit[c] for c, sev in SEVERITY.items() if sev == "high")
    if agent and high:
        return "urgent"
    if status == "confirmed" and (contact_type in ("creator", "none") or ca_status == "not covered"):
        return "governance_gap"
    if agent:
        return "review"
    # Below the threshold, but a weak hint someone should look at (decided 2026-10-21).
    if status == "unlikely" and any(hit.get(c) for c in settings.t("review_unlikely_signals")):
        return "review"
    return "ok"


# --- row ---------------------------------------------------------------------------------

def principal_type(label: str) -> str:
    return {"entra_agent_identity": "agent_identity",
            "entra_agent_blueprint_principal": "agent_blueprint_principal",
            "entra_agent_user": "agent_user", "managed_identity": "managed_identity",
            "user": "user"}.get(label, "application")


def build_row(f: dict[str, Any]) -> dict[str, Any]:
    """Facts for one principal -> one row (PRINCIPAL_COLUMNS)."""
    sp = f["sp"]
    label = f["label"]
    microsoft = bool(f.get("microsoft_managed"))
    contact = resolve_contact(f)
    f = {**f, "contact": contact}
    hit, why = detect_signals(f)
    if microsoft:  # listed, not scored (decision)
        hit = {c: False for c in SIGNAL_CODES}
        why = {}
    score = 0 if microsoft else likelihood(hit)
    tagged = confirming_tags(sp) if label not in NATIVE_LABELS else []
    status = agent_status(label, microsoft, score, bool(tagged))
    if tagged:
        why = {"confirmed_by": f"tag {tagged[0]}", **why}
    ca_status = f.get("ca_status") or "unknown"
    prio = priority(status, hit, contact["type"], ca_status)
    s = f.get("signins") or {}
    perms = f.get("app_permissions") or []
    high_risk = sorted({p["permission"] for p in perms if p.get("high_risk")})
    creds = f.get("credentials")
    live = [c for c in creds or [] if c.get("status") != "expired"]
    expiries = [c["days_to_expiry"] for c in live if c.get("days_to_expiry") is not None]
    owners = (f.get("sp_owners") or []) + (f.get("app_owners") or [])
    row = {
        "object_id": sp.get("id"), "app_id": sp.get("appId") or "",
        "display_name": sp.get("displayName") or "", "principal_type": principal_type(label),
        "microsoft_managed": microsoft, "agent_status": status, "likelihood": score,
        "priority": prio,
        "signals": "|".join(c for c in SIGNAL_CODES if hit[c] and c not in SEVERITY),
        "exposures": "|".join(c for c in SIGNAL_CODES if hit[c] and c in SEVERITY),
        **{f"sig_{c}": hit[c] for c in SIGNAL_CODES},
        "contact_name": contact["name"], "contact_upn": contact["upn"],
        "contact_type": contact["type"], "owner_count": len(owners),
        "created_datetime": sp.get("createdDateTime") or "",
        "created_by_app_id": sp.get("createdByAppId") or "",
        "last_sign_in": s.get("last_sign_in") or "", "signins_30d": s.get("total", 0),
        "active_days_30d": s.get("active_days", 0), "max_daily_signins": s.get("max_daily", 0),
        "distinct_resources_30d": len(s.get("resources") or []),
        "ai_signins_30d": s.get("ai_signins", 0),
        "top_resources": "|".join((s.get("resources") or [])[:5]),
        "app_permission_count": len(perms),
        "top_permissions": "|".join(([p for p in high_risk]
                                     + sorted({p["permission"] for p in perms} - set(high_risk)))[:5]),
        "high_risk_permissions": "|".join(high_risk),
        "privileged_roles": "|".join(r["role"] for r in f.get("roles") or [] if r.get("is_privileged")),
        "credential_types": "|".join(sorted({c["type"] for c in live})) if creds is not None else "unknown",
        "next_credential_expiry_days": min(e for e in expiries if e >= 0) if any(e >= 0 for e in expiries) else "",
        "expired_credentials": sum(1 for c in creds or [] if c.get("status") == "expired"),
        "migration_wave": f.get("wave") or "",
        "ca_status": ca_status,
        "evidence": "; ".join(f"{code}: {text}" for code, text in why.items()),
    }
    return row


def permission_category(name: str) -> str:
    if name in set(settings.t("mail_send_permissions")):
        return "mail"
    if name in set(settings.t("broad_files_write_permissions")):
        return "files_write"
    if name.startswith(tuple(settings.t("calendar_teams_permission_prefixes"))):
        return "calendar_teams"
    if name.startswith(("Directory.", "RoleManagement.", "Application.", "AppRoleAssignment.",
                        "Policy.", "User.", "Group.")):
        return "directory"
    if name.startswith(("Sites.", "Files.")):
        return "files_read"
    if name.startswith("Mail."):
        return "mail"
    return "other"


def signal_catalog() -> list[dict[str, Any]]:
    weights = settings.t("likelihood_weights")
    return [{"code": c, "label": label, "kind": kind,
             "weight": weights.get(c, "") if kind == "likelihood" else "",
             "severity": sev} for c, label, kind, sev in SIGNALS]
