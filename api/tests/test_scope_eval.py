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


# --- review hardening: every bypass found in the 2026-10-02 code review is a negative test ------

from khandaq.scope import validate_scope, validate_target  # noqa: E402

SAT_0100 = dt.datetime(2026, 10, 3, 1, 0, tzinfo=UTC)  # Saturday 01:00
SAT_2300 = dt.datetime(2026, 10, 3, 23, 0, tzinfo=UTC)  # Saturday 23:00
SUN_0100 = dt.datetime(2026, 10, 4, 1, 0, tzinfo=UTC)  # Sunday 01:00
THURSDAY_NOON = dt.datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
OK_SPEC = {"host": "gw.acme.test", "model": "assistant-v3"}


def test_host_and_base_url_naming_different_hosts_is_refused():
    # The lock used to check `host` while an adapter could connect to `base_url`.
    d = _eval(
        target_type="llm_endpoint",
        target_spec={**OK_SPEC, "base_url": "https://victim.example/v1"},
        deny=[{"host": "victim.example"}],
    )
    assert not d.allowed and "more than one host" in d.reason


def test_url_only_target_is_checked_by_its_url_host():
    d = _eval(
        target_type="llm_endpoint",
        target_spec={"url": "https://evil.test/v1", "model": "assistant-v3"},
    )
    assert not d.allowed and "not in the allow-list" in d.reason


def test_model_restriction_requires_a_model():
    d = _eval(target_type="llm_endpoint", target_spec={"host": "gw.acme.test"})
    assert not d.allowed and "allows only models" in d.reason


def test_path_restriction_applies_to_the_url_path():
    allow = {"llm_endpoint": [{"host": "gw.acme.test", "paths": ["/v1/chat/completions"]}]}
    bad = _eval(
        allow=allow,
        target_type="llm_endpoint",
        target_spec={"url": "https://gw.acme.test/admin/delete"},
    )
    assert not bad.allowed and "path '/admin/delete'" in bad.reason
    ok = _eval(
        allow=allow,
        target_type="llm_endpoint",
        target_spec={"url": "https://gw.acme.test/v1/chat/completions"},
    )
    assert ok.allowed


def test_hosts_are_normalised_before_matching():
    ok = _eval(target_type="llm_endpoint", target_spec={**OK_SPEC, "host": "GW.ACME.TEST."})
    assert ok.allowed
    allow = {"llm_endpoint": [{"host": "api.prod.acme.com"}]}
    denied = _eval(
        allow=allow,
        deny=[{"host": "*.prod.acme.com"}],
        target_type="llm_endpoint",
        target_spec={"host": "api.prod.acme.com."},  # trailing dot used to dodge the deny rule
    )
    assert not denied.allowed and "deny rule" in denied.reason


def test_userinfo_in_host_resolves_to_the_real_host():
    d = _eval(
        target_type="llm_endpoint",
        target_spec={"host": "gw.acme.test@evil.test", "model": "assistant-v3"},
    )
    assert not d.allowed and "'evil.test'" in d.reason


def test_run_params_cannot_override_the_target():
    for key, value in (("base_url", "https://victim.example"), ("model", "other")):
        d = _eval(target_type="llm_endpoint", target_spec=OK_SPEC, params={key: value})
        assert not d.allowed and "may not override the target" in d.reason


def test_techniques_must_be_a_list():
    # A string used to become a set of characters and dodge the prohibited list.
    d = _eval(
        target_type="llm_endpoint",
        target_spec=OK_SPEC,
        roe={"prohibited_techniques": ["data-exfiltration"]},
        params={"techniques": "data-exfiltration"},
    )
    assert not d.allowed and "techniques must be a list" in d.reason


def test_rate_must_be_declared_numeric_and_finite():
    roe = {"max_requests_per_minute": 60}
    for params, needle in (
        ({}, "set rate_per_minute"),
        ({"rate_per_minute": "1000"}, "finite number"),  # used to raise TypeError (a 500)
        ({"rate_per_minute": float("nan")}, "finite number"),  # used to pass the comparison
    ):
        d = _eval(target_type="llm_endpoint", target_spec=OK_SPEC, roe=roe, params=params)
        assert not d.allowed and needle in d.reason, params
    ok = _eval(
        target_type="llm_endpoint", target_spec=OK_SPEC, roe=roe, params={"rate_per_minute": 30}
    )
    assert ok.allowed


def test_midnight_window_does_not_open_the_previous_night():
    roe = {"windows": ["Sat 22:00-02:00 UTC"]}
    for now, expected in ((SAT_0100, False), (SAT_2300, True), (SUN_0100, True)):
        d = _eval(target_type="llm_endpoint", target_spec=OK_SPEC, roe=roe, now=now)
        assert d.allowed is expected, now


def test_unknown_zone_or_day_denies_instead_of_guessing():
    for window in ("Mon-Sun 00:00-23:59 Europe/Zurch", "Weekdays 09:00-17:00"):
        d = _eval(target_type="llm_endpoint", target_spec=OK_SPEC, roe={"windows": [window]})
        assert not d.allowed and "cannot evaluate scope" in d.reason, window


def test_day_lists_mix_ranges_and_single_days():
    roe = {"windows": ["Mon-Wed,Fri 09:00-18:00 UTC"]}
    assert _eval(target_type="llm_endpoint", target_spec=OK_SPEC, roe=roe).allowed  # Friday
    thursday = _eval(target_type="llm_endpoint", target_spec=OK_SPEC, roe=roe, now=THURSDAY_NOON)
    assert not thursday.allowed


def test_validate_scope_rejects_typos_and_bad_rules():
    assert (
        validate_scope(ALLOW, [{"host": "*.evil.test"}], {"windows": ["Mon-Fri 09:00-18:00"]}) == []
    )
    errors = validate_scope(
        {"llm_endpoint": [{"host": "gw.acme.test", "model": ["x"]}]},  # 'model' typo for 'models'
        [{"hots": "evil.test"}],
        {"windows": ["Mon-Fri 09:00-18:00 Mars/Olympus"], "max_requests_per_minute": "60"},
    )
    joined = " | ".join(errors)
    assert "unknown keys ['model']" in joined
    assert "deny[0]" in joined
    assert "unknown time zone" in joined


def test_validate_target_refuses_ambiguous_specs():
    assert validate_target("llm_endpoint", OK_SPEC) is None
    assert "more than one host" in validate_target(
        "llm_endpoint", {"host": "gw.acme.test", "url": "https://other.test/v1"}
    )
    assert validate_target("llm_endpoint", {"model": "x"}) is not None
