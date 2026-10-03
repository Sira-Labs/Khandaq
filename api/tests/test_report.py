"""Integration tests for the engagement report (spec 011) and its re-verification (spec 013)."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
SCOPE = {
    "allow": {"llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}]},
    "deny": [],
    "roe": {},
}


@pytest.fixture(scope="module")
def eng():
    from khandaq import migrate

    engine = create_engine(TEST_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def client(eng):
    from khandaq import main
    from khandaq.deps import get_session

    def _get_session():
        with Session(eng) as s:
            try:
                yield s
            except Exception:
                s.rollback()
                raise

    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app)


def _engagement_with_findings(client, name="report"):
    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    tid = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "gw.acme.test", "model": "assistant-v3"}},
        headers=OWNER,
    ).json()["id"]
    client.put(f"/api/engagements/{eng_id}/scope", json=SCOPE, headers=OWNER)
    client.post(
        f"/api/engagements/{eng_id}/activate", json={"authorisation_ref": "SOW-1"}, headers=OWNER
    )
    _run_echo(client, eng_id, tid)
    return eng_id


def _run_echo(client, eng_id, tid=None):
    if tid is None:
        tid = client.get(f"/api/engagements/{eng_id}/targets", headers=OWNER).json()[0]["id"]
    r = client.post(
        f"/api/engagements/{eng_id}/runs", json={"adapter": "echo", "target_id": tid}, headers=OWNER
    )
    assert r.status_code in (200, 201), r.text


def test_report_json(client):
    eng_id = _engagement_with_findings(client)
    r = client.get(f"/api/engagements/{eng_id}/report", headers=OWNER)
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["total"] == 2
    assert body["summary"]["by_severity"]["high"] == 1
    assert body["summary"]["by_severity"]["low"] == 1
    fw = body["summary"]["by_framework"]
    assert "owasp-llm-2026:LLM01" in fw and "owasp-llm-2026:LLM02" in fw
    assert body["evidence"]["root"] is not None
    assert body["evidence"]["verify"]["ok"] is True


def test_report_html_escaped(client):
    eng_id = _engagement_with_findings(client)
    r = client.get(f"/api/engagements/{eng_id}/report.html", headers=OWNER)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Khandaq engagement report" in r.text
    assert "<script>" not in r.text  # any untrusted text would be escaped, not raw


def test_report_navigator(client):
    eng_id = _engagement_with_findings(client)
    r = client.get(f"/api/engagements/{eng_id}/report/navigator", headers=OWNER)
    assert r.status_code == 200
    layer = r.json()
    assert layer["domain"] == "atlas"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "AML.T0051" in ids


# --- spec 013: pinned root + count, audited exports, re-verification ---------------------------


def _pin(client, eng_id):
    return client.get(f"/api/engagements/{eng_id}/report", headers=OWNER).json()["evidence"]


def _verify(client, eng_id, body, headers=OWNER):
    return client.post(f"/api/engagements/{eng_id}/report/verify", json=body, headers=headers)


def _exports(eng, eng_id):
    from khandaq import models as m

    with Session(eng) as s:
        return [
            a.detail
            for a in s.scalars(
                select(m.AuditLog)
                .where(m.AuditLog.engagement_id == eng_id, m.AuditLog.action == "report.exported")
                .order_by(m.AuditLog.at)
            )
        ]


def test_report_pins_root_and_count(client):
    eng_id = _engagement_with_findings(client, "pin")
    ledger = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()
    ev = _pin(client, eng_id)
    assert ev["count"] == len(ledger["entries"]) >= 1
    assert ev["root"] == ledger["entries"][-1]["entry_hash"] == ledger["root"]

    page = client.get(f"/api/engagements/{eng_id}/report.html", headers=OWNER).text
    assert ev["root"] in page
    assert f"over {ev['count']} entr" in page


def test_report_empty_chain_pins_nothing(client):
    eng_id = client.post("/api/engagements", json={"name": "empty"}, headers=OWNER).json()["id"]
    ev = _pin(client, eng_id)
    assert ev["root"] is None and ev["count"] == 0
    page = client.get(f"/api/engagements/{eng_id}/report.html", headers=OWNER).text
    assert "over 0 entries" in page


def test_report_export_is_audited(client, eng):
    eng_id = _engagement_with_findings(client, "audited")
    ev = _pin(client, eng_id)
    client.get(f"/api/engagements/{eng_id}/report.html", headers=OWNER)
    client.get(f"/api/engagements/{eng_id}/report/navigator", headers=OWNER)  # pins nothing
    assert _exports(eng, eng_id) == [
        {"format": "json", "root": ev["root"], "count": ev["count"]},
        {"format": "html", "root": ev["root"], "count": ev["count"]},
    ]


def test_report_verify_roundtrip(client):
    eng_id = _engagement_with_findings(client, "roundtrip")
    ev = _pin(client, eng_id)

    r = _verify(client, eng_id, ev)  # the evidence block as exported, verify block included
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["issued"] is True
    assert body["appended_since"] == 0
    assert body["pinned"] == {"root": ev["root"], "count": ev["count"]}
    assert body["current"] == body["pinned"]
    assert body["verify"]["ok"] is True

    _run_echo(client, eng_id)  # more evidence appended after the report was issued
    later = _verify(client, eng_id, {"root": ev["root"], "count": ev["count"]}).json()
    assert later["ok"] is True and later["issued"] is True
    assert later["appended_since"] > 0
    assert later["current"]["count"] == ev["count"] + later["appended_since"]
    assert later["current"]["root"] != ev["root"]


def test_report_verify_wrong_root(client):
    eng_id = _engagement_with_findings(client, "wrong-root")
    ev = _pin(client, eng_id)
    forged = "sha256:" + "ab" * 32
    body = _verify(client, eng_id, {"root": forged, "count": ev["count"]}).json()
    assert body["ok"] is False and body["issued"] is False
    assert body["appended_since"] is None
    assert body["verify"]["broken_at"] == ev["count"]  # seq is 1-based: the entry at the pin
    assert "pinned root" in body["verify"]["reason"]


def test_report_verify_pin_longer_than_chain(client):
    eng_id = _engagement_with_findings(client, "truncated")
    ev = _pin(client, eng_id)
    body = _verify(client, eng_id, {"root": ev["root"], "count": ev["count"] + 1}).json()
    assert body["ok"] is False
    assert "entries were removed" in body["verify"]["reason"]


def test_report_verify_detects_tampering(client, eng):
    from khandaq import models as m

    eng_id = _engagement_with_findings(client, "tampered")
    ev = _pin(client, eng_id)
    assert ev["count"] >= 1
    with Session(eng) as s:
        # The table is append-only; an owner who disables the trigger can still rewrite a row,
        # and the pinned verification must show it (as the spec 004 tamper test does).
        s.execute(
            text("ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_update_delete")
        )
        s.execute(
            update(m.LedgerEntry)
            .where(m.LedgerEntry.engagement_id == eng_id, m.LedgerEntry.seq == 1)
            .values(entry_hash="sha256:" + "0" * 64)
        )
        s.execute(text("ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_no_update_delete"))
        s.commit()

    body = _verify(client, eng_id, ev).json()
    assert body["ok"] is False and body["issued"] is True  # issued, but no longer intact
    assert body["verify"]["broken_at"] == 1


def test_report_verify_empty_pin(client):
    eng_id = _engagement_with_findings(client, "empty-pin")
    body = _verify(client, eng_id, {"root": None, "count": 0}).json()
    assert body["ok"] is True
    assert body["appended_since"] == body["current"]["count"] >= 1
    assert body["issued"] is False  # this engagement never exported an empty report


@pytest.mark.parametrize(
    "pin",
    [
        {"root": "sha256:xyz", "count": 1},
        {"root": "SHA256:" + "a" * 64, "count": 1},
        {"root": "sha256:" + "A" * 64, "count": 1},
        {"root": "sha256:" + "a" * 64, "count": -1},
        {"root": "sha256:" + "a" * 64, "count": 0},
        {"root": None, "count": 1},
        {"root": "sha256:" + "a" * 64, "count": "1"},
        {"root": "sha256:" + "a" * 64, "count": 1.0},
        {"root": "sha256:" + "a" * 64, "count": 2**63},
        {"root": "sha256:" + "a" * 64},
        {"count": 0},
    ],
)
def test_report_verify_rejects_malformed(client, pin):
    eng_id = client.post("/api/engagements", json={"name": "malformed"}, headers=OWNER).json()["id"]
    assert _verify(client, eng_id, pin).status_code == 422


def test_report_verify_authz(client, eng):
    from khandaq import models as m

    eng_id = _engagement_with_findings(client, "authz")
    ev = _pin(client, eng_id)
    with Session(eng) as s:
        viewer = m.User(email="report-viewer@test", org_role="member")
        s.add(viewer)
        s.flush()
        s.add(m.EngagementMember(engagement_id=eng_id, user_id=viewer.id, role="viewer"))
        s.commit()

    outsider = {"X-Khandaq-Dev-User": "report-outsider@test"}
    assert _verify(client, eng_id, ev, headers=outsider).status_code == 403
    viewer_hdr = {"X-Khandaq-Dev-User": "report-viewer@test"}
    r = _verify(client, eng_id, ev, headers=viewer_hdr)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert _verify(client, "eng_missing", ev).status_code == 404


def test_report_verify_writes_no_audit(client, eng):
    eng_id = _engagement_with_findings(client, "read-only")
    ev = _pin(client, eng_id)
    from khandaq import models as m

    def count_audit():
        with Session(eng) as s:
            return len(
                s.scalars(select(m.AuditLog.id).where(m.AuditLog.engagement_id == eng_id)).all()
            )

    before = count_audit()
    _verify(client, eng_id, ev)
    assert count_audit() == before


def test_report_verify_closed_engagement(client):
    eng_id = _engagement_with_findings(client, "closed")
    ev = _pin(client, eng_id)
    assert client.post(f"/api/engagements/{eng_id}/close", headers=OWNER).status_code == 200
    body = _verify(client, eng_id, ev).json()
    assert body["ok"] is True and body["issued"] is True and body["appended_since"] == 0
