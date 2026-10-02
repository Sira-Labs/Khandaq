"""The scope lock — pure evaluation of a run request against an engagement's scope and RoE.

This is the control that keeps Khandaq inside the boundary the operator is authorised to test
(docs/architecture/04-engagement-scope-and-authz.md). ``evaluate`` is a pure function (no I/O) so it
is exhaustively unit-tested; the API calls it on the run path (spec 005) and on the pre-flight
``scope-check`` route (spec 002). Default deny: anything not explicitly allowed is rejected — and so
is anything the lock cannot read unambiguously.

Hardening (code review, 2026-10-02): every host-bearing field of a target is resolved the way a
client would connect to it (``host``, ``url``, ``base_url``, ``endpoint``), and a spec naming two
different hosts is refused, so the lock can never check one field while an adapter connects to
another. Hosts are compared normalised (case, trailing dot, IDNA). Model and path restrictions
require the value to be present. Run params cannot override the target. RoE values are validated;
a scope or request that cannot be evaluated denies instead of raising.
"""

from __future__ import annotations

import datetime as dt
import math
import posixpath
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_DAY_NAMES = {
    "mon": 0, "monday": 0, "tue": 1, "tuesday": 1, "wed": 2, "wednesday": 2,
    "thu": 3, "thursday": 3, "fri": 4, "friday": 4, "sat": 5, "saturday": 5,
    "sun": 6, "sunday": 6,
}  # fmt: skip
_TARGET_TYPES = ("llm_endpoint", "agent", "mcp_server", "model_artifact", "dataset")
_URL_FIELDS = ("url", "base_url", "endpoint")
# Run params may tune a tool, never redirect it: these would let a run reach something the lock did
# not check.
_OVERRIDE_PARAMS = frozenset({"host", "url", "base_url", "api_base", "endpoint", "target", "model"})
_ALLOW_KEYS = {
    "llm_endpoint": {"host", "models", "paths"},
    "agent": {"host", "models", "paths"},
    "mcp_server": {"url"},
    "model_artifact": {"digest", "location"},
    "dataset": {"digest", "location"},
}
_DENY_KEYS = {"host", "url", "digest"}
_ROE_KEYS = {"windows", "max_requests_per_minute", "prohibited_techniques"}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None


class ScopeError(ValueError):
    """A target spec, scope rule or run request the lock cannot evaluate unambiguously."""


# --- normalisation ---------------------------------------------------------------------------


def normalise_host(raw: object) -> str:
    """Resolve a host the way a client would: drop port and userinfo, lowercase, strip the trailing
    dot, IDNA-encode. ``"Evil.Example.:443"`` and ``"x@evil.example"`` both give ``evil.example``.
    """
    text = str(raw).strip()
    if not text:
        raise ScopeError("empty host")
    hostname = urlsplit(text if "://" in text else f"//{text}").hostname
    if not hostname:
        raise ScopeError(f"cannot read a host from {text!r}")
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError(f"invalid host {text!r}") from exc


@dataclass(frozen=True)
class _Endpoint:
    host: str | None
    path: str | None
    model: str | None
    urls: tuple[str, ...]


def _endpoint(spec: dict) -> _Endpoint:
    """Canonical view of an llm_endpoint/agent spec; refuses specs that name two hosts or paths."""
    hosts: set[str] = set()
    paths: set[str] = set()
    urls: list[str] = []
    if spec.get("host"):
        hosts.add(normalise_host(spec["host"]))
    for field in _URL_FIELDS:
        value = spec.get(field)
        if not value:
            continue
        parts = urlsplit(str(value))
        if not parts.scheme or not parts.hostname:
            raise ScopeError(f"'{field}' must be an absolute URL, got {value!r}")
        hosts.add(normalise_host(parts.hostname))
        urls.append(str(value))
        if parts.path:
            paths.add(parts.path)
    if spec.get("path"):
        paths.add(str(spec["path"]))
    if len(hosts) > 1:
        raise ScopeError(f"target names more than one host: {', '.join(sorted(hosts))}")
    if len(paths) > 1:
        raise ScopeError(f"target names more than one path: {', '.join(sorted(paths))}")
    model = spec.get("model")
    return _Endpoint(
        host=next(iter(hosts), None),
        path=next(iter(paths), None),
        model=None if model is None else str(model),
        urls=tuple(urls),
    )


def _host_matches(pattern: str, host: str) -> bool:
    """Exact match, or a leading-wildcard like ``*.prod.example`` matching any subdomain."""
    if pattern.startswith("*."):
        suffix = normalise_host(pattern[2:])
        return host == suffix or host.endswith("." + suffix)
    return host == normalise_host(pattern)


# --- allow / deny ----------------------------------------------------------------------------


def _match_allow(target_type: str, entries: list[dict], spec: dict) -> Decision:
    """Does the target match an allow entry for its type? Distinct reasons for the common misses."""
    if target_type in ("llm_endpoint", "agent"):
        target = _endpoint(spec)
        if target.host is None:
            return Decision(False, "target names no host")
        host_entries = [e for e in entries if normalise_host(e["host"]) == target.host]
        if not host_entries:
            return Decision(False, f"host '{target.host}' is not in the allow-list")
        reason = ""
        for e in host_entries:
            models = e.get("models")
            if models and (target.model is None or target.model not in models):
                reason = (
                    f"model '{target.model}' is not permitted for host '{target.host}'"
                    if target.model is not None
                    else f"host '{target.host}' allows only models {models}; the target names none"
                )
                continue
            paths = e.get("paths")
            if paths and (target.path is None or target.path not in paths):
                reason = (
                    f"path '{target.path}' is not permitted for host '{target.host}'"
                    if target.path is not None
                    else f"host '{target.host}' allows only paths {paths}; the target names none"
                )
                continue
            return Decision(True)
        return Decision(False, reason)

    if target_type == "mcp_server":
        url = spec.get("url")
        if url and any(e.get("url") == url for e in entries):
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


def _deny_path(raw: str | None) -> str:
    """Canonical form of a path for deny matching only. Deliberately broad, so that any spelling a
    server might resolve to a denied path matches it: percent-escapes are decoded (repeatedly, to
    undo double encoding), backslashes count as separators, empty and dot segments are resolved,
    and case is folded. Over-matching only ever refuses a run; under-matching would let one through.
    Returns '' for the root."""
    path = raw or "/"
    for _ in range(5):  # bounded: each pass only shortens the string or leaves it unchanged
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    path = path.replace("\\", "/")
    path = posixpath.normpath("/" + path.lstrip("/"))
    path = path.lstrip("/")  # normpath keeps a leading '//'
    return ("/" + path).rstrip("/").casefold() if path not in ("", ".") else ""


def _path_covered(rule_path: str, target_path: str | None) -> bool:
    """A denied URL covers its path and everything below it ('/admin' covers '/admin/x'); a URL
    with no path covers the whole host. Both sides are canonicalised with ``_deny_path``, so
    '/x/../admin', '//admin', '/%61dmin' and 'admin' are all '/admin'. Fails closed: when in
    doubt, the rule applies."""
    rule = _deny_path(rule_path)
    if not rule:
        return True
    target = _deny_path(target_path)
    return target == rule or target.startswith(rule + "/")


def _match_deny(deny: list[dict], target_type: str, spec: dict) -> Decision:
    host: str | None = None
    path: str | None = None
    if target_type in ("llm_endpoint", "agent"):
        target = _endpoint(spec)
        host, path = target.host, target.path
    elif target_type == "mcp_server" and spec.get("url"):
        parts = urlsplit(str(spec["url"]))
        host = normalise_host(parts.hostname) if parts.hostname else None
        path = parts.path or None
    digest = spec.get("digest")
    for d in deny:
        if "host" in d and host and _host_matches(str(d["host"]), host):
            return Decision(False, f"host '{host}' matches a deny rule")
        if "url" in d and host:
            # Compare canonically (host normalised like every other host, path by segment): a raw
            # string compare let 'https://GW.acme.test:443/admin' slip past a rule for '/admin'.
            rule = urlsplit(str(d["url"]))
            if (
                rule.hostname
                and normalise_host(rule.hostname) == host
                and _path_covered(rule.path, path)
            ):
                return Decision(False, f"'{d['url']}' matches a deny rule")
        if "digest" in d and digest and d["digest"] == digest:
            return Decision(False, "artifact digest matches a deny rule")
    return Decision(True)


# --- rules of engagement -----------------------------------------------------------------------


def _days(token: str) -> set[int]:
    """'Mon-Fri', 'Sat,Sun', 'Mon-Wed,Fri' (ranges may wrap: 'Fri-Mon')."""
    days: set[int] = set()
    for part in token.lower().split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (p.strip() for p in part.split("-", 1))
            if a not in _DAY_NAMES or b not in _DAY_NAMES:
                raise ScopeError(f"unknown day in {token!r}")
            start, end = _DAY_NAMES[a], _DAY_NAMES[b]
            span = range(start, end + 1) if start <= end else [*range(start, 7), *range(0, end + 1)]
            days.update(span)
        elif part in _DAY_NAMES:
            days.add(_DAY_NAMES[part])
        else:
            raise ScopeError(f"unknown day {part!r}")
    if not days:
        raise ScopeError(f"no days in {token!r}")
    return days


def _window(window: object) -> tuple[set[int], dt.time, dt.time, ZoneInfo]:
    """Parse 'Days HH:MM-HH:MM [Zone]' (zone defaults to UTC; an unknown zone is an error)."""
    if not isinstance(window, str):
        raise ScopeError(f"window must be text, got {window!r}")
    parts = window.split()
    if len(parts) not in (2, 3) or "-" not in parts[1]:
        raise ScopeError(f"window must look like 'Mon-Fri 09:00-18:00 Europe/Zurich': {window!r}")
    start_s, end_s = parts[1].split("-", 1)
    try:
        start, end = dt.time.fromisoformat(start_s), dt.time.fromisoformat(end_s)
    except ValueError as exc:
        raise ScopeError(f"bad time in window {window!r}") from exc
    try:
        zone = ZoneInfo(parts[2]) if len(parts) == 3 else ZoneInfo("UTC")
    except (ZoneInfoNotFoundError, ValueError) as exc:
        # Never fall back to UTC: a mistyped zone would silently shift the authorised hours.
        raise ScopeError(f"unknown time zone in window {window!r}") from exc
    return _days(parts[0]), start, end, zone


def _within_windows(windows: list, now: dt.datetime) -> bool:
    """True if ``now`` falls in any window (an empty list means no time restriction)."""
    for window in windows:
        days, start, end, zone = _window(window)
        local = now.astimezone(zone)
        t, weekday = local.time(), local.weekday()
        if start <= end:
            if weekday in days and start <= t <= end:
                return True
        # Crossing midnight: the evening belongs to a listed day, the early morning to the day after
        # one. (Allowing the listed day's own early morning would open the previous night's tail.)
        elif (t >= start and weekday in days) or (t <= end and (weekday - 1) % 7 in days):
            return True
    return not windows


def _non_negative_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScopeError(f"{name} must be a finite number, got {value!r}")
    try:
        finite = math.isfinite(value)
    except OverflowError:  # a huge JSON integer cannot become a float
        finite = False
    if not finite:
        raise ScopeError(f"{name} must be a finite number, got {value!r}")
    if value < 0:
        raise ScopeError(f"{name} must not be negative")
    return float(value)


def _text_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScopeError(f"{name} must be a list of strings, got {value!r}")
    return value


# --- evaluation --------------------------------------------------------------------------------


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
    """Evaluate one run request. Order: allow-list → deny-list → RoE window → rate → techniques.

    Never raises: a scope or request the lock cannot read unambiguously is a rejection with the
    reason, so the run path records and audits it like any other refusal.
    """
    try:
        return _evaluate(allow, deny, roe, target_type, target_spec, params, now)
    # ScopeError is a ValueError; ArithmeticError covers overflow from absurd numbers.
    except (ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        return Decision(False, f"cannot evaluate scope: {exc}")


def _evaluate(
    allow: dict,
    deny: list[dict],
    roe: dict,
    target_type: str,
    target_spec: dict,
    params: dict,
    now: dt.datetime,
) -> Decision:
    overrides = sorted(_OVERRIDE_PARAMS & set(params))
    if overrides:
        return Decision(False, f"run params may not override the target ('{overrides[0]}')")

    entries = allow.get(target_type)
    if not entries:
        return Decision(False, f"no allow rule for target type '{target_type}'")

    matched = _match_allow(target_type, entries, target_spec)
    if not matched.allowed:
        return matched

    denied = _match_deny(deny or [], target_type, target_spec)
    if not denied.allowed:
        return denied

    if not _within_windows(roe.get("windows") or [], now):
        return Decision(False, "outside the permitted time window")

    limit = roe.get("max_requests_per_minute")
    if limit is not None:
        cap = _non_negative_number(limit, "max_requests_per_minute")
        if params.get("rate_per_minute") is None:
            return Decision(
                False, f"the rules of engagement cap the rate at {limit}/min: set rate_per_minute"
            )
        rate = _non_negative_number(params["rate_per_minute"], "rate_per_minute")
        if rate > cap:
            return Decision(
                False,
                f"requested rate {params['rate_per_minute']}/min exceeds the limit of {limit}/min",
            )

    prohibited = set(_text_list(roe.get("prohibited_techniques") or [], "prohibited_techniques"))
    using = set(_text_list(params.get("techniques") or [], "techniques"))
    clash = prohibited & using
    if clash:
        tech = sorted(clash)[0]
        return Decision(False, f"technique '{tech}' is prohibited by the rules of engagement")

    return Decision(True)


# --- validation at write time (PUT /scope, POST /targets) ---------------------------------------


def validate_scope(allow: dict, deny: list, roe: dict) -> list[str]:
    """Problems with a scope document, or an empty list. Unknown keys are errors: a typo such as
    ``model`` for ``models`` would otherwise silently drop a restriction."""
    errors: list[str] = []
    for target_type, entries in allow.items():
        if target_type not in _TARGET_TYPES:
            errors.append(f"allow: unknown target type '{target_type}'")
            continue
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            errors.append(f"allow.{target_type}: must be a list of rules")
            continue
        for i, entry in enumerate(entries):
            where = f"allow.{target_type}[{i}]"
            unknown = set(entry) - _ALLOW_KEYS[target_type]
            if unknown:
                errors.append(f"{where}: unknown keys {sorted(unknown)}")
            try:
                if target_type in ("llm_endpoint", "agent"):
                    if not entry.get("host"):
                        errors.append(f"{where}: 'host' is required")
                    else:
                        normalise_host(entry["host"])
                    for key in ("models", "paths"):
                        if key in entry:
                            _text_list(entry[key], key)
                elif target_type == "mcp_server" and not isinstance(entry.get("url"), str):
                    errors.append(f"{where}: 'url' is required")
                elif target_type in ("model_artifact", "dataset") and not (
                    entry.get("digest") or entry.get("location")
                ):
                    errors.append(f"{where}: 'digest' or 'location' is required")
            except ScopeError as exc:
                errors.append(f"{where}: {exc}")
    for i, rule in enumerate(deny):
        where = f"deny[{i}]"
        if not isinstance(rule, dict) or not (_DENY_KEYS & set(rule)):
            errors.append(f"{where}: must name a 'host', 'url' or 'digest'")
            continue
        unknown = set(rule) - _DENY_KEYS
        if unknown:
            errors.append(f"{where}: unknown keys {sorted(unknown)}")
        if "host" in rule:
            pattern = str(rule["host"])
            try:
                normalise_host(pattern[2:] if pattern.startswith("*.") else pattern)
            except ScopeError as exc:
                errors.append(f"{where}: {exc}")
        if "url" in rule:
            parts = urlsplit(str(rule["url"]))
            if not parts.scheme or not parts.hostname:
                errors.append(f"{where}: 'url' must be an absolute URL")
    unknown = set(roe) - _ROE_KEYS
    if unknown:
        errors.append(f"roe: unknown keys {sorted(unknown)}")
    try:
        windows = roe.get("windows") or []
        if not isinstance(windows, list):
            raise ScopeError("windows must be a list")
        for window in windows:
            _window(window)
        if roe.get("max_requests_per_minute") is not None:
            _non_negative_number(roe["max_requests_per_minute"], "max_requests_per_minute")
        _text_list(roe.get("prohibited_techniques") or [], "prohibited_techniques")
    except ScopeError as exc:
        errors.append(f"roe: {exc}")
    return errors


def validate_target(target_type: str, spec: dict) -> str | None:
    """Why a target spec cannot be scope-checked, or ``None`` if it can."""
    try:
        if target_type in ("llm_endpoint", "agent"):
            if _endpoint(spec).host is None:
                return "an llm_endpoint/agent target needs a 'host' or 'url'"
        elif target_type == "mcp_server":
            parts = urlsplit(str(spec.get("url", "")))
            if not parts.scheme or not parts.hostname:
                return "an mcp_server target needs an absolute 'url'"
        elif target_type in ("model_artifact", "dataset") and not (
            spec.get("digest") or spec.get("location")
        ):
            return f"a {target_type} target needs a 'digest' or 'location'"
    except ScopeError as exc:
        return str(exc)
    return None
