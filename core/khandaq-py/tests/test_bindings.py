"""Smoke tests for the khandaq_core PyO3 wheel (spec 003)."""

import hashlib
import json

import khandaq_core as kc


def _finding(tool="garak", rule="garak.promptinject.hijack", severity="high", target="tgt_1",
             mappings=(("owasp-llm-2026", "LLM01"),), evidence=()):
    return {
        "schema": "khandaq.finding/2",
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


def test_dedup_merges_the_same_issue():
    a = _finding(severity="medium", evidence=["ev_a"])
    b = _finding(severity="high", evidence=["ev_b"], mappings=(("atlas", "AML.T0051"),))
    out = json.loads(kc.dedup(json.dumps([a, b])))
    assert out["duplicates"] == 1
    assert len(out["canonical"]) == 1
    assert out["canonical"][0]["severity"] == "high"
    assert out["canonical"][0]["x-khandaq"]["evidence"] == ["ev_a", "ev_b"]
    assert out["canonical"][0]["schema"] == "khandaq.finding/2"


def test_equal_mappings_are_not_identity():
    # ADR-0013: two tools' rules with the same mappings are different findings unless the
    # equivalence table names them as one weakness.
    a = _finding(tool="garak", rule="garak.x")
    b = _finding(tool="pyrit", rule="pyrit.y")
    assert kc.fingerprint(json.dumps(a)) != kc.fingerprint(json.dumps(b))
    assert len(json.loads(kc.dedup(json.dumps([a, b])))["canonical"]) == 2


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


def test_ledger_writes_format_2_and_binds_evidence_metadata():
    record = {
        "id": "ev_1",
        "engagement_id": "eng_1",
        "run_id": "run_1",
        "kind": "transcript",
        "object_key": "eng_1/run_1/e1.json",
        "sha256": _h(1),
        "bytes": 42,
        "redacted": False,
    }
    bound = kc.evidence_record_hash(json.dumps(record))
    # The recipe, as an external verifier would recompute it (ADR-0014).
    canonical = json.dumps(
        dict(record, schema="khandaq.evidence/2"), sort_keys=True, separators=(",", ":")
    )
    assert bound == "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    moved = dict(record, object_key="eng_1/run_2/e1.json")
    assert kc.evidence_record_hash(json.dumps(moved)) != bound
    for bad in (dict(record, extra=1), {k: v for k, v in record.items() if k != "kind"}):
        try:
            kc.evidence_record_hash(json.dumps(bad))
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {bad}")

    entry = json.loads(kc.ledger_append(None, bound))
    assert entry["format"] == 2
    assert json.loads(kc.ledger_verify(json.dumps([entry])))["ok"] is True
    entry["format"] = 1  # a format-2 entry cannot be re-read as format 1
    assert json.loads(kc.ledger_verify(json.dumps([entry])))["ok"] is False


def test_merge_mappings_and_mapping_table():
    # Spec 020: the tool's ids are kept, the table adds the frameworks the tool does not name.
    f = _finding(rule="garak.promptinject.hijackhatehumansmini")
    merged = {(m["framework"], m["id"]) for m in json.loads(kc.merge_mappings(json.dumps(f)))}
    assert ("owasp-llm-2026", "LLM01") in merged
    assert ("nist-ai-rmf", "MEASURE-2.7") in merged
    bare = _finding(rule="nobody.mapped.this", mappings=())
    assert json.loads(kc.merge_mappings(json.dumps(bare))) == [
        {"framework": "unmapped", "id": "nobody.mapped.this"}
    ]
    table = json.loads(kc.mapping_table())
    assert table["schema"] == "khandaq.mappings/1"
    assert table["versions"]["atlas"] and table["sources"]["atlas"].startswith("https://")
