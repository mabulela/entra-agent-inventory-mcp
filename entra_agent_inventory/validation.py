"""Input validation. Everything that reaches an OData filter or URL path goes
through here first, so the model can't inject its own query."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .config import settings

GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class InvalidInput(ValueError):
    """Raised for caller mistakes only, so internal errors aren't mislabelled."""


def check_guid(value: str, field: str) -> str:
    value = (value or "").strip() if isinstance(value, str) else ""
    if not GUID_RE.match(value):
        raise InvalidInput(f"{field} must be an Entra object ID (GUID), got {value!r}")
    return value.lower()


def clamp_days(days: int) -> int:
    return max(1, min(int(days), settings.max_lookback_days))


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(int(value), high))


def since(days: int) -> str:
    start = datetime.now(timezone.utc) - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")
