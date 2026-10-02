"""Unit tests for the pure scope evaluator (no database). Acceptance table from spec 002."""

from __future__ import annotations

import datetime as dt

from khandaq.scope import evaluate

UTC = dt.UTC

# A weekday inside and a weekend outside a Mon-Fri 09:00-18:00 window.
WEEKDAY_NOON = dt.datetime(2026, 10, 2, 12, 0, tzinfo=UTC)  # Friday
SUNDAY_NOON = dt.datetime(2026, 10, 4, 12, 0, tzinfo=UTC)  # Sunday

ALLOW = {
    "llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}],
    "mcp_server": [{"url": "https://tools.acme.test/mcp"}],
}


def _eval(**kw):
    base = dict(allow=ALLOW, deny=[], roe={}, params={}, now=WEEKDAY_NOON)
    base.update(kw)
    return evaluate(**base)


def test_in_scope_llm_endpoint_allowed():
    d = _eval(
        target_type="llm_endpoint", target_spec={"host": "gw.acme.test", "model": "assistant-v3"}
    )
    assert d.allowed and d.reason is None


def test_unknown_host_rejected():
    d = _eval(
        target_type="llm_endpoint", target_spec={"host": "evil.test", "model": "assistant-v3"}
    )
    assert not d.allowed and "not in the allow-list" in d.reason


def test_wrong_model_rejected_with_distinct_reason():
    d = _eval(target_type="llm_endpoint", target_spec={"host": "gw.acme.test", "model": "gpt-9"})
    assert not d.allowed and "model 'gpt-9' is not permitted" in d.reason


def test_denied_host_rejected():
    d = evaluate(
        allow=ALLOW,
        deny=[{"host": "gw.acme.test"}],
        roe={},
        target_type="llm_endpoint",
        target_spec={"host": "gw.acme.test", "model": "assistant-v3"},
        params={},
        now=WEEKDAY_NOON,
    )
    assert not d.allowed and "deny rule" in d.reason


def test_wildcard_deny_matches_subdomain():
    d = evaluate(
        allow={"llm_endpoint": [{"host": "api.prod.acme.com"}]},
        deny=[{"host": "*.prod.acme.com"}],
        roe={},
        target_type="llm_endpoint",
        target_spec={"host": "api.prod.acme.com"},
        params={},
        now=WEEKDAY_NOON,
    )
    assert not d.allowed and "deny rule" in d.reason


def test_out_of_window_rejected():
    d = _eval(
        target_type="llm_endpoint",
        target_spec={"host": "gw.acme.test", "model": "assistant-v3"},
        roe={"windows": ["Mon-Fri 09:00-18:00 UTC"]},
        now=SUNDAY_NOON,
    )
    assert not d.allowed and "time window" in d.reason


def test_in_window_allowed():
    d = _eval(
        target_type="llm_endpoint",
        target_spec={"host": "gw.acme.test", "model": "assistant-v3"},
        roe={"windows": ["Mon-Fri 09:00-18:00 UTC"]},
        now=WEEKDAY_NOON,
    )
    assert d.allowed


def test_over_rate_rejected():
    d = _eval(
        target_type="llm_endpoint",
        target_spec={"host": "gw.acme.test", "model": "assistant-v3"},
        roe={"max_requests_per_minute": 60},
        params={"rate_per_minute": 120},
    )
    assert not d.allowed and "exceeds the limit" in d.reason


def test_prohibited_technique_rejected():
    d = _eval(
        target_type="llm_endpoint",
        target_spec={"host": "gw.acme.test", "model": "assistant-v3"},
        roe={"prohibited_techniques": ["data-exfiltration"]},
        params={"techniques": ["data-exfiltration"]},
    )
    assert not d.allowed and "prohibited" in d.reason


def test_default_deny_for_type_without_allow_rules():
    d = _eval(target_type="model_artifact", target_spec={"digest": "sha256:abc"})
    assert not d.allowed and "no allow rule for target type" in d.reason


def test_mcp_server_allowed_and_unknown_rejected():
    ok = _eval(target_type="mcp_server", target_spec={"url": "https://tools.acme.test/mcp"})
    assert ok.allowed
    bad = _eval(target_type="mcp_server", target_spec={"url": "https://evil.test/mcp"})
    assert not bad.allowed and "not in the allow-list" in bad.reason
