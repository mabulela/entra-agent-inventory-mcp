"""Runtime settings.

Two layers:
  * Environment variables: deployment settings (transport, auth, limits). For local
    work they can come from a .env file (see load_dotenv); real environment
    variables always win.
  * Optional JSON file (CONFIG_FILE): tenant-specific tuning for the
    heuristics, so nobody edits code to retune scoring. See
    config/config.example.json for every key.

Confidence markers:
  [ML] verified on Microsoft Learn, [F] seen in a test tenant, [A] a design choice of
  this project, [U] unverified - confirm in your tenant.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def load_dotenv(path: str | Path) -> list[str]:
    """Read KEY=VALUE lines from a local .env file into os.environ, for local development.

    Only keys that aren't already set are filled, so real environment variables (and
    container settings) always win. Empty values are skipped, comments and blank lines
    ignored, surrounding quotes removed. ENV_FILE overrides the path; ENV_FILE="" turns
    loading off (the tests do this). Returns the keys it set.
    """
    p = Path(path)
    if not p.is_file():
        return []
    loaded = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key and value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def env_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# --- Tunable defaults (override via CONFIG_FILE) ----------------------------

DEFAULT_TUNING: dict[str, Any] = {
    # [U] Substrings of a sign-in's resourceDisplayName that indicate a model
    # endpoint. Check what your tenant's logs actually show and adjust.
    "ai_resource_hints": [
        "openai", "cognitive services", "azure ai", "machine learning", "foundry",
    ],
    # [A] Display-name / tag pattern suggesting an agent workload.
    "agent_name_pattern": r"(agent|bot|copilot|assistant|gpt|llm|openai|\brag\b|\bai[-_ ]|[-_ ]ai\b)",
    # [A] appIds of apps that provision agent workloads in your tenant.
    "agent_creator_app_ids": [],
    # Tenants owning Microsoft first-party apps; excluded from candidate scoring.
    "microsoft_owner_tenants": [
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        "72f988bf-86f1-41af-91ab-2d7cd011db47",
    ],
    # [A] Credentials expiring within this many days are flagged, so the
    # identity can be migrated instead of rotated.
    "credential_expiry_warning_days": 30,
    # [A] Application permissions treated as high risk in the access footprint.
    "high_risk_app_permissions": [
        "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
        "Application.ReadWrite.OwnedBy", "User.ReadWrite.All", "Group.ReadWrite.All",
        "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Sites.FullControl.All",
        "Sites.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
    ],
    # [A] Audit activity keywords and the severity they map to (first match wins).
    "sensitive_activity_keywords": [
        ["credential", "high"], ["secret", "high"], ["certificate", "high"],
        ["federated", "high"], ["key", "high"], ["owner", "high"],
        ["app role", "high"], ["permission", "high"], ["consent", "high"],
        ["grant", "high"], ["disable", "medium"], ["enable", "medium"],
        ["delete", "medium"], ["update", "low"],
    ],
    # [A] Cutover readiness: maximum acceptable failure rate on the new identity.
    "cutover_max_failure_rate": 0.02,

    # --- Scoring (classify_principal + assess_principals) ------------------------------
    # [A] Agent-likelihood signal weights. The scale runs from 0 to their sum (21 by default).
    "likelihood_weights": {
        "created_by_agent_platform": 3, "connects_to_mcp": 3, "ai_resource_access": 3, "uses_ai_gateway": 3,
        "agent_like_name": 2, "agent_marker": 2, "bot_framework_redirect": 2, "high_volume": 1,
        "multi_resource": 1, "federated_credential": 1,
    },
    # Service principal tags that make a legacy (non-Agent ID) identity a confirmed agent,
    # whatever its score. Case-insensitive; a trailing * matches a prefix. Copilot Studio
    # sets both on the service principals of its legacy agents [ML].
    "confirmed_agent_tags": ["AgentCreatedBy:CopilotStudio", "power-virtual-agents-*"],
    # Hosts of the Bot Framework token service; a redirect URI on one of them (or a
    # subdomain, such as europe.token.botframework.com) fires bot_framework_redirect [ML].
    "bot_framework_redirect_hosts": ["token.botframework.com"],
    # [A] Likelihood at or above this counts as a "likely agent" (decided: 6).
    "likely_threshold": 6,
    # [A] Signals that put an identity scoring below the threshold into "review" instead of
    # "ok". It stays "unlikely"; a person just looks at it.
    "review_unlikely_signals": ["agent_like_name"],
    "high_volume_daily_signins": 50,
    "multi_resource_daily": 3,
    # MCP servers registered in Entra: their appIds or resource display names.
    # The connects_to_mcp signal stays off until you list them here.
    "mcp_server_app_ids": [],
    "mcp_server_resource_names": [],
    # [A] AI gateways (for example Azure API Management) that agents sign in to with Entra
    # tokens. Behind a gateway, model and MCP calls are made by the gateway's own identity,
    # so ai_resource_access and connects_to_mcp can't see them; this signal can.
    # Application (client) IDs of the gateway's app registrations, and/or exact resource names.
    "ai_gateway_app_ids": [],
    "ai_gateway_resource_names": [],
    # Optional custom security attribute marking agents, e.g.
    # {"set": "AgentGovernance", "attribute": "IsAgent"}. Needs
    # CustomSecAttributeAssignment.Read.All [U]; ignored when empty.
    "agent_security_attribute": {"set": "", "attribute": ""},
    # [A] Permission groups behind the exposure signals.
    "mail_send_permissions": ["Mail.Send", "full_access_as_app"],
    "broad_files_write_permissions": ["Sites.ReadWrite.All", "Files.ReadWrite.All",
                                      "Sites.FullControl.All", "Sites.Manage.All"],
    "calendar_teams_permission_prefixes": ["Calendars.", "Chat.", "ChannelMessage.",
                                           "OnlineMeetings.", "Team", "Channel"],
    # Resource apps whose application-permission grants are read tenant-wide:
    # Microsoft Graph, Office 365 Exchange Online, Office 365 SharePoint Online.
    "permission_resource_app_ids": [
        "00000003-0000-0000-c000-000000000000",
        "00000002-0000-0ff1-ce00-000000000000",
        "00000003-0000-0ff1-ce00-000000000000",
    ],
    # Maximum identities per assess_principals call.
    "assess_max_principals": 25,
    # list_ownerless_agents checks at most this many agent identities when Graph refuses
    # the 'no owners' filter and the server has to check owners itself.
    "agent_list_scan_limit": 5000,
}


@dataclass
class Settings:
    graph_root: str = "https://graph.microsoft.com"
    max_lookback_days: int = 30          # Entra P1/P2 sign-in and audit retention
    max_signin_events: int = 5000
    graph_concurrency: int = 5

    # Transport
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_hosts: list[str] = field(default_factory=list)

    # Inbound auth (HTTP only)
    auth_mode: str = "none"              # none | api_key | entra
    api_key: str = ""
    allow_unauthenticated: bool = False
    auth_tenant_id: str = ""
    auth_audience: list[str] = field(default_factory=list)
    resource_url: str = ""
    required_role: str = ""
    sweep_role: str = ""            # role for tenant-wide lists, e.g. list_ownerless_agents (MCP_TENANT_WIDE_ROLE)

    # Audit
    audit_file: str = ""

    tuning: dict[str, Any] = field(default_factory=lambda: json.loads(json.dumps(DEFAULT_TUNING)))

    @property
    def graph_scope(self) -> str:
        return f"{self.graph_root}/.default"

    @property
    def agent_name_re(self) -> re.Pattern[str]:
        return re.compile(self.tuning["agent_name_pattern"], re.IGNORECASE)

    def t(self, key: str) -> Any:
        return self.tuning[key]

    @property
    def high_risk_permissions(self) -> set[str]:
        """Every permission flagged high-risk: the general list plus the ones that drive the
        Mail.Send and broad-files-write exposures, so the flag and the exposures never disagree."""
        return (set(self.tuning["high_risk_app_permissions"]) | set(self.tuning["mail_send_permissions"])
                | set(self.tuning["broad_files_write_permissions"]))


def _merge_tuning(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    unknown = set(override) - set(base) - {"_comment"}
    if unknown:
        raise ValueError(f"Unknown keys in CONFIG_FILE: {sorted(unknown)}")
    merged = dict(base)
    for key, value in override.items():
        if key == "_comment":
            continue
        if isinstance(base.get(key), dict) and isinstance(value, dict):
            merged[key] = {**base[key], **value}
        else:
            merged[key] = value
    re.compile(merged["agent_name_pattern"])  # fail fast on a bad pattern
    # Every likelihood signal has a weight, so the weights' keys are the valid codes here;
    # a misspelt code would otherwise silently never match.
    bad = set(merged["review_unlikely_signals"]) - set(merged["likelihood_weights"])
    if bad:
        raise ValueError(f"review_unlikely_signals: not likelihood signals: {sorted(bad)}")
    return merged


def load_settings() -> Settings:
    env_file = os.environ.get("ENV_FILE", ".env")
    if env_file:
        load_dotenv(env_file)
    s = Settings(
        graph_root=os.environ.get("GRAPH_ROOT", "https://graph.microsoft.com").rstrip("/"),
        max_signin_events=int(os.environ.get("MAX_SIGNIN_EVENTS", "5000")),
        graph_concurrency=int(os.environ.get("GRAPH_CONCURRENCY", "5")),
        transport=os.environ.get("MCP_TRANSPORT", "stdio"),
        host=os.environ.get("MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("MCP_PORT", "8000")),
        allowed_hosts=env_list("MCP_ALLOWED_HOSTS"),
        api_key=os.environ.get("MCP_API_KEY", ""),
        allow_unauthenticated=env_bool("MCP_ALLOW_UNAUTHENTICATED"),
        auth_tenant_id=os.environ.get("MCP_AUTH_TENANT_ID", ""),
        auth_audience=env_list("MCP_AUTH_AUDIENCE"),
        resource_url=os.environ.get("MCP_RESOURCE_URL", ""),
        required_role=os.environ.get("MCP_REQUIRED_ROLE", ""),
        sweep_role=os.environ.get("MCP_TENANT_WIDE_ROLE", os.environ.get("MCP_SWEEP_ROLE", "")),
        audit_file=os.environ.get("AUDIT_LOG_FILE", ""),
    )
    mode = os.environ.get("MCP_AUTH_MODE", "").strip().lower()
    s.auth_mode = mode or ("api_key" if s.api_key else "none")
    if s.auth_mode not in ("none", "api_key", "entra"):
        raise ValueError("MCP_AUTH_MODE must be none, api_key or entra")

    config_file = os.environ.get("CONFIG_FILE")
    if config_file:
        override = json.loads(Path(config_file).read_text(encoding="utf-8"))
        s.tuning = _merge_tuning(s.tuning, override)
    else:
        # Backwards compatibility with v1 environment variables.
        if os.environ.get("AI_RESOURCE_HINTS"):
            s.tuning["ai_resource_hints"] = env_list("AI_RESOURCE_HINTS")
        if os.environ.get("AGENT_NAME_PATTERN"):
            s.tuning["agent_name_pattern"] = os.environ["AGENT_NAME_PATTERN"]
        if os.environ.get("AGENT_CREATOR_APP_IDS"):
            s.tuning["agent_creator_app_ids"] = env_list("AGENT_CREATOR_APP_IDS")
    return s


settings = load_settings()
