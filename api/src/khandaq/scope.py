"""The scope lock — pure evaluation of a run request against an engagement's scope and RoE.

This is the control that keeps Khandaq inside the boundary the operator is authorised to test
(docs/architecture/04-engagement-scope-and-authz.md). ``evaluate`` is a pure function (no I/O) so it
is exhaustively unit-tested; the API calls it on the run path (spec 005) and on the pre-flight
``scope-check`` route (spec 002). Default deny: anything not explicitly allowed is rejected.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_WEEKDAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None


def _host_of(spec: dict) -> str | None:
    if spec.get("host"):
        return str(spec["host"])
    url = spec.get("url") or spec.get("base_url")
    return urlsplit(url).hostname if url else None


def _host_matches(pattern: str, host: str) -> bool:
    """Exact match, or a leading-wildcard like ``*.prod.example`` matching any subdomain."""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".prod.example"
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


def _match_allow(target_type: str, entries: list[dict], spec: dict) -> Decision:
    """Does the target match an allow entry for its type? Distinct reasons for the common misses."""
    if target_type in ("llm_endpoint", "agent"):
        host = _host_of(spec)
        host_entries = [e for e in entries if e.get("host") == host]
        if not host_entries:
            return Decision(False, f"host '{host}' is not in the allow-list")
        model = spec.get("model")
        path = spec.get("path")
        for e in host_entries:
            models = e.get("models")
            if models and model is not None and model not in models:
                continue
            paths = e.get("paths")
            if paths and path is not None and path not in paths:
                continue
            return Decision(True)
        return Decision(False, f"model '{model}' is not permitted for host '{host}'")

    if target_type == "mcp_server":
        url = spec.get("url")
        if any(e.get("url") == url for e in entries):
            return Decision(True)
        return Decision(False, f"MCP server '{url}' is not in the allow-list")

    if target_type in ("model_artifact", "dataset"):
        digest = spec.get("digest")
        location = spec.get("location")
        for e in entries:
            if digest is not None and e.get("digest") == digest:
                return Decision(True)
            if location is not None and e.get("location") == location:
                return Decision(True)
        return Decision(False, f"{target_type} '{digest or location}' is not in the allow-list")

    return Decision(False, f"unknown target type '{target_type}'")


def _match_deny(deny: list[dict], spec: dict) -> Decision:
    host = _host_of(spec)
    url = spec.get("url")
    digest = spec.get("digest")
    for d in deny:
        if "host" in d and host and _host_matches(str(d["host"]), host):
            return Decision(False, f"host '{host}' matches a deny rule")
        if "url" in d and url and d["url"] == url:
            return Decision(False, f"'{url}' matches a deny rule")
        if "digest" in d and digest and d["digest"] == digest:
            return Decision(False, "artifact digest matches a deny rule")
    return Decision(True)


def _expand_days(token: str) -> set[int]:
    token = token.strip().lower()
    if "-" in token:
        a, b = token.split("-", 1)
        start, end = _WEEKDAYS[a[:3]], _WEEKDAYS[b[:3]]
        if start <= end:
            return set(range(start, end + 1))
        return set(range(start, 7)) | set(range(0, end + 1))
    return {_WEEKDAYS[part[:3]] for part in token.split(",") if part}


def _within_windows(windows: list[str], now: dt.datetime) -> bool:
    """True if ``now`` is in any window. Window form: 'Days HH:MM-HH:MM [TZ]' (TZ defaults UTC)."""
    if not windows:
        return True
    for window in windows:
        parts = window.split()
        if len(parts) < 2:
            continue
        days = _expand_days(parts[0])
        start_s, end_s = parts[1].split("-", 1)
        try:
            tz = ZoneInfo(parts[2]) if len(parts) > 2 else ZoneInfo("UTC")
        except (ZoneInfoNotFoundError, KeyError):
            tz = ZoneInfo("UTC")
        local = now.astimezone(tz)
        start = dt.time.fromisoformat(start_s)
        end = dt.time.fromisoformat(end_s)
        t = local.time()
        if start <= end:
            in_time = start <= t <= end
            day_ok = local.weekday() in days
        else:  # window spans midnight
            in_time = t >= start or t <= end
            day_ok = local.weekday() in days or (t <= end and (local.weekday() - 1) % 7 in days)
        if day_ok and in_time:
            return True
    return False


def evaluate(
    *,
    allow: dict,
    deny: list[dict],
    roe: dict,
    target_type: str,
    target_spec: dict,
    params: dict,
    now: dt.datetime,
) -> Decision:
    """Evaluate one run request. Order: allow-list → deny-list → RoE window → rate → techniques."""
    entries = allow.get(target_type)
    if not entries:
        return Decision(False, f"no allow rule for target type '{target_type}'")

    matched = _match_allow(target_type, entries, target_spec)
    if not matched.allowed:
        return matched

    denied = _match_deny(deny or [], target_spec)
    if not denied.allowed:
        return denied

    if not _within_windows(roe.get("windows") or [], now):
        return Decision(False, "outside the permitted time window")

    limit = roe.get("max_requests_per_minute")
    requested = params.get("rate_per_minute")
    if limit is not None and requested is not None and requested > limit:
        return Decision(False, f"requested rate {requested}/min exceeds the limit of {limit}/min")

    prohibited = set(roe.get("prohibited_techniques") or [])
    using = set(params.get("techniques") or [])
    clash = prohibited & using
    if clash:
        tech = sorted(clash)[0]
        return Decision(False, f"technique '{tech}' is prohibited by the rules of engagement")

    return Decision(True)
