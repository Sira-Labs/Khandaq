"""Smoke tests for the khandaq_core PyO3 wheel (spec 003)."""

import json

import khandaq_core as kc


def _finding(tool="garak", rule="garak.promptinject.hijack", severity="high", target="tgt_1",
             mappings=(("owasp-llm-2026", "LLM01"),), evidence=()):
    return {
        "schema": "khandaq.finding/1",
        "engagement_id": "eng_1",
        "run_id": "run_1",
        "rule_id": rule,
        "severity": severity,
        "source": {"tool": tool, "version": "1.0"},
        "target_ref": target,
        "locations": [{"logicalLocations": [{"fullyQualifiedName": "endpoint"}]}],
        "x-khandaq": {"phase": "04-prompt-injection",
                      "mappings": [{"framework": f, "id": i} for f, i in mappings],
                      "evidence": list(evidence)},
    }


def test_version_present():
    assert kc.__version__


def test_validate_and_fingerprint_roundtrip():
    f = _finding()
    assert kc.validate_finding(json.dumps(f)) is True
    fp = kc.fingerprint(json.dumps(f))
    assert fp.startswith("sha256:")


def test_validate_rejects_bad_finding():
    bad = _finding()
    bad["severity"] = "spicy"
    try:
        kc.validate_finding(json.dumps(bad))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad severity")


def test_dedup_merges_cross_tool():
    a = _finding(tool="garak", rule="garak.x", severity="medium", evidence=["ev_a"])
    b = _finding(tool="pyrit", rule="pyrit.y", severity="high", evidence=["ev_b"])
    out = json.loads(kc.dedup(json.dumps([a, b])))
    assert out["duplicates"] == 1
    assert len(out["canonical"]) == 1
    assert out["canonical"][0]["severity"] == "high"
    assert out["canonical"][0]["x-khandaq"]["evidence"] == ["ev_a", "ev_b"]


def test_framework_mappings_and_navigator():
    f = _finding(mappings=(("atlas", "AML.T0051"),))
    layer = json.loads(kc.navigator(json.dumps([f])))
    assert layer["domain"] == "atlas"
    assert layer["techniques"][0]["techniqueID"] == "AML.T0051"


def _h(n: int) -> str:
    return f"sha256:{n:064x}"


def test_ledger_append_verify_and_tamper():
    import khandaq_core as kc
    chain = []
    for h in [_h(1), _h(2), _h(3)]:
        prev = json.dumps(chain[-1]) if chain else None
        chain.append(json.loads(kc.ledger_append(prev, h)))
    assert chain[0]["seq"] == 1 and chain[0]["prev_hash"] is None
    v = json.loads(kc.ledger_verify(json.dumps(chain)))
    assert v["ok"] is True and v["count"] == 3
    assert kc.ledger_root(json.dumps(chain)) == chain[-1]["entry_hash"]
    # tamper
    chain[1]["evidence_hash"] = _h(99)
    v2 = json.loads(kc.ledger_verify(json.dumps(chain)))
    assert v2["ok"] is False and v2["broken_at"] == 2


def test_ledger_append_refuses_malformed_hashes():
    import pytest

    for bad in ["sha256:a", _h(1).upper(), "", "md5:" + "0" * 64]:
        with pytest.raises(ValueError, match="64 lowercase hex"):
            kc.ledger_append(None, bad)


def test_ledger_verify_against_a_pin_detects_truncation():
    import pytest

    chain = []
    for n in (1, 2, 3):
        prev = json.dumps(chain[-1]) if chain else None
        chain.append(json.loads(kc.ledger_append(prev, _h(n))))
    root = chain[-1]["entry_hash"]
    truncated = json.dumps(chain[:2])
    assert json.loads(kc.ledger_verify(truncated))["ok"] is True  # unpinned: undetectable
    pinned = json.loads(kc.ledger_verify(truncated, root, 3))
    assert pinned["ok"] is False and "shorter" in pinned["reason"]
    assert json.loads(kc.ledger_verify(json.dumps(chain), root, 3))["ok"] is True
    with pytest.raises(ValueError, match="together"):
        kc.ledger_verify(truncated, root)


def test_severity_must_be_lowercase_and_extra_fields_survive():
    import pytest

    with pytest.raises(ValueError, match="severity"):
        kc.validate_finding(json.dumps(_finding(severity="HIGH")))
    f = _finding()
    f["message"] = {"text": "synthetic"}
    out = json.loads(kc.dedup(json.dumps([f])))
    assert out["canonical"][0]["message"] == {"text": "synthetic"}
