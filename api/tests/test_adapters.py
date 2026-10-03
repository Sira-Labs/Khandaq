"""Unit tests for the adapter layer (spec 005): no database, no containers."""

from __future__ import annotations

from khandaq.adapters import build_run_request, get_manifest
from khandaq.adapters.manifest import AdapterManifest


def test_manifest_problems_detects_bad_manifests():
    good = AdapterManifest(
        name="garak",
        version="0.17.0",
        phases=["03-scanning"],
        severity_table={"fail": "high"},
        image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
    )
    assert good.problems() == []

    floating = AdapterManifest(
        name="x",
        version="",
        phases=[],
        severity_table={},
        image=None,
    )
    probs = floating.problems()
    assert any("version" in p for p in probs)
    assert any("phase" in p for p in probs)
    assert any("severity_table" in p for p in probs)
    assert any("image" in p for p in probs)

    bad_sev = AdapterManifest(
        name="x",
        version="1.0",
        phases=["p"],
        severity_table={"fail": "spicy"},
        builtin=True,
    )
    assert any("unknown severities" in p for p in bad_sev.problems())


def test_echo_manifest_is_registered_and_valid():
    echo = get_manifest("echo")
    assert echo is not None and echo.builtin
    assert echo.problems() == []


def test_run_request_carries_exactly_one_target():
    req = build_run_request(
        "run_1", "eng_1", "llm_endpoint", {"host": "gw.acme.test", "model": "m"}, {"p": 1}
    )
    # Exactly one target, and it is the one provided — an adapter can see no other.
    assert set(req.keys()) == {"run_id", "engagement_id", "target", "params"}
    assert req["target"] == {"type": "llm_endpoint", "spec": {"host": "gw.acme.test", "model": "m"}}
