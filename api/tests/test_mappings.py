"""Spec 020: the core framework table is applied to every finding at ingest."""

from __future__ import annotations

import json
import os

import khandaq_core as kc
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
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
def env():
    from khandaq import main, migrate
    from khandaq.deps import get_session

    engine = create_engine(TEST_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)

    def _get_session():
        with Session(engine) as s:
            try:
                yield s
            except Exception:
                s.rollback()
                raise

    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app), engine
    engine.dispose()


def _echo_engagement(client, name: str) -> str:
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
    r = client.post(
        f"/api/engagements/{eng_id}/runs", json={"adapter": "echo", "target_id": tid}, headers=OWNER
    )
    assert r.status_code == 201 and r.json()["state"] == "succeeded", r.text
    return eng_id


def _stored(engine, eng_id: str):
    from khandaq.models import Finding

    with Session(engine) as s:
        return list(
            s.scalars(
                select(Finding).where(Finding.engagement_id == eng_id, Finding.canonical.is_(True))
            )
        )


def _ids(body: dict) -> set[tuple[str, str]]:
    return {(m["framework"], m["id"]) for m in body["x-khandaq"]["mappings"]}


def test_an_echo_run_stores_the_tables_ids_without_moving_fingerprints(env):
    client, engine = env
    eng_id = _echo_engagement(client, "map-echo")
    by_rule = {f.rule_id: f for f in _stored(engine, eng_id)}
    assert set(by_rule) == {"echo.inject", "echo.leak"}

    inject = by_rule["echo.inject"]
    assert {("nist-ai-rmf", "MEASURE-2.7"), ("owasp-llm-2025", "LLM01")} <= _ids(inject.body)
    assert ("owasp-llm-2026", "LLM01") in _ids(inject.body)  # the adapter's own id is kept
    assert {("nist-ai-rmf", "MEASURE-2.10"), ("atlas", "AML.T0057")} <= _ids(
        by_rule["echo.leak"].body
    )
    # ADR-0013: identity ignores mappings, so the enriched finding keeps its fingerprint.
    for f in by_rule.values():
        bare = json.loads(json.dumps(f.body))
        bare["x-khandaq"]["mappings"] = []
        assert kc.fingerprint(json.dumps(bare)) == f.fingerprint


def test_an_unmapped_rule_is_marked_not_dropped(env, monkeypatch):
    from khandaq.adapters import EchoRunner

    original = EchoRunner.run

    def unknown_rule(self, request):
        out = original(self, request)
        for f in out["findings"]:
            if f["rule_id"] == "echo.leak":
                f["rule_id"] = "echo-lab.unheard-of"
                f["x-khandaq"]["mappings"] = []
        return out

    monkeypatch.setattr(EchoRunner, "run", unknown_rule)
    client, engine = env
    eng_id = _echo_engagement(client, "map-unmapped")
    [unknown] = [f for f in _stored(engine, eng_id) if f.rule_id == "echo-lab.unheard-of"]
    assert _ids(unknown.body) == {("unmapped", "echo-lab.unheard-of")}
    report = client.get(f"/api/engagements/{eng_id}/report", headers=OWNER).json()
    assert report["summary"]["by_framework"]["unmapped:echo-lab.unheard-of"] == 1


def test_the_report_names_the_table_versions(env):
    client, _ = env
    eng_id = _echo_engagement(client, "map-report")
    report = client.get(f"/api/engagements/{eng_id}/report", headers=OWNER).json()
    tables = report["mapping_tables"]
    assert tables["versions"]["atlas"] and tables["versions"]["nist-ai-rmf"] == "1.0"
    assert tables["sources"]["atlas"].startswith("https://")
    assert "nist-ai-rmf:MEASURE-2.7" in report["summary"]["by_framework"]

    page = client.get(f"/api/engagements/{eng_id}/report.html", headers=OWNER).text
    assert f"atlas {tables['versions']['atlas']}" in page
    assert "Framework tables:" in page
