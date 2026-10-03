"""Spec 020 §6: an adapter's own framework ids must be in the core table's entry for that family.

The wrappers keep their dicts (the tool-side view, baked into released images); the core table is
what the API applies at ingest. This test fails when the two drift apart."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import khandaq_core as kc
import pytest

ADAPTERS = Path(__file__).resolve().parents[2] / "adapters"


def _wrapper(name: str):
    path = ADAPTERS / name / "wrap.py"
    spec = importlib.util.spec_from_file_location(f"khandaq_drift_{name}", path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses in a wrapper resolve their module by name
    spec.loader.exec_module(module)
    return module


def _table(rule_id: str) -> set[tuple[str, str]]:
    finding = {
        "schema": "khandaq.finding/2",
        "engagement_id": "eng_1",
        "run_id": "run_1",
        "rule_id": rule_id,
        "severity": "low",
        "source": {"tool": rule_id.split(".", 1)[0], "version": "0"},
        "target_ref": "tgt_1",
        "locations": [],
        "x-khandaq": {"phase": "03-scanning", "mappings": [], "evidence": []},
    }
    return {
        (m["framework"], m["id"]) for m in json.loads(kc.framework_mappings(json.dumps(finding)))
    }


def _families() -> list[tuple[str, list[tuple[str, str]]]]:
    garak, pyrit, promptfoo = _wrapper("garak"), _wrapper("pyrit"), _wrapper("promptfoo")
    cases = [(f"garak.{k}.someprobe", v) for k, v in garak.PROBE_FRAMEWORKS.items()]
    cases += [(f"pyrit.{k}", v) for k, v in pyrit.STRATEGY_FRAMEWORKS.items()]
    cases.append(("pyrit.a_strategy_nobody_curated", pyrit.DEFAULT_FRAMEWORKS))
    cases += [(f"promptfoo.{k}:x", v[1]) for k, v in promptfoo.PLUGIN_FAMILY.items()]
    cases.append(("promptfoo.a-plugin-nobody-curated", promptfoo.DEFAULT_FAMILY[1]))
    mcp = _wrapper("mcp-scanner")
    cases += [(f"mcp-scanner.{k}", v) for k, v in mcp.THREAT_FRAMEWORKS.items()]
    return cases


@pytest.mark.parametrize(("rule_id", "ids"), _families(), ids=lambda v: str(v)[:40])
def test_every_wrapper_id_is_in_the_core_table(rule_id, ids):
    missing = set(ids) - _table(rule_id)
    assert not missing, f"{rule_id}: the wrapper emits {sorted(missing)} the core table lacks"


def test_every_echo_id_is_in_the_core_table():
    from khandaq.adapters import EchoRunner

    out = EchoRunner().run({"run_id": "run_1", "engagement_id": "eng_1", "target": {}})
    for f in out["findings"]:
        ids = {(m["framework"], m["id"]) for m in f["x-khandaq"]["mappings"]}
        assert ids <= _table(f["rule_id"]), f["rule_id"]


def test_an_uncurated_mcp_scanner_threat_is_unmapped():
    """Spec 025: no mcp-scanner default, as for garak; the table names only what it curated."""
    for rule in ("mcp-scanner.credential-harvesting", "mcp-scanner"):
        assert _table(rule) == {("unmapped", rule)}


def test_the_drift_guard_notices_a_missing_id():
    assert not {("atlas", "AML.T9999")} <= _table("garak.promptinject.x")
