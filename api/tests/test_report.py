"""Integration tests for the engagement report (spec 011)."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
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
def client():
    from khandaq import main, migrate
    from khandaq.deps import get_session

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)

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
    eng.dispose()


def _engagement_with_findings(client):
    eng_id = client.post("/api/engagements", json={"name": "report"}, headers=OWNER).json()["id"]
    tid = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "gw.acme.test", "model": "assistant-v3"}},
        headers=OWNER,
    ).json()["id"]
    client.put(f"/api/engagements/{eng_id}/scope", json=SCOPE, headers=OWNER)
    client.post(
        f"/api/engagements/{eng_id}/activate", json={"authorisation_ref": "SOW-1"}, headers=OWNER
    )
    client.post(
        f"/api/engagements/{eng_id}/runs", json={"adapter": "echo", "target_id": tid}, headers=OWNER
    )
    return eng_id


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
