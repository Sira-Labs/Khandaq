"""Spec 021: a deployment overlay for the framework mapping table."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from khandaq.mapping_overlay import MAX_OVERLAY_BYTES, MappingOverlayError, load_overlay
from khandaq.settings import Settings

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
SCOPE = {
    "allow": {"llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}]},
    "deny": [],
    "roe": {},
}
OVERLAY = {
    "schema": "khandaq.mappings/1",
    "versions": {"acme-ctl": "2026.1"},
    "sources": {"acme-ctl": "https://controls.acme.example/"},
    "rules": {
        "echo.leak": {
            "mappings": [{"framework": "acme-ctl", "id": "CTL-7"}],
            "rationale": "our data-handling control",
        }
    },
}


def _write(tmp_path, content) -> str:
    path = tmp_path / "acme-mappings.json"
    path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    return str(path)


def test_no_path_means_no_overlay():
    assert load_overlay("") is None


def test_a_valid_overlay_loads_with_its_fingerprint(tmp_path):
    overlay = load_overlay(_write(tmp_path, OVERLAY))
    assert overlay is not None and overlay.name == "acme-mappings.json"
    assert overlay.sha256.startswith("sha256:") and len(overlay.sha256) == 71


@pytest.mark.parametrize("env", ["dev", "prod"])
@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (None, "cannot be read"),
        (b"x" * (MAX_OVERLAY_BYTES + 1), "larger than"),
        (b"{not json", "KHANDAQ_MAPPINGS_PATH"),
        ({**OVERLAY, "schema": "khandaq.mappings/9"}, "schema"),
        ({**OVERLAY, "versions": {"atlas": "v1999.01", "acme-ctl": "1"}}, "version"),
        ({**OVERLAY, "versions": {}}, "no version"),
    ],
)
def test_a_bad_overlay_stops_startup(tmp_path, env, content, reason):
    path = str(tmp_path / "missing.json") if content is None else _write(tmp_path, content)
    settings = Settings(env=env, mappings_path=path)
    with pytest.raises(MappingOverlayError, match=reason):
        settings.validate_runtime()


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


@pytest.fixture
def overlay_on(tmp_path):
    from khandaq import mapping_overlay
    from khandaq.settings import get_settings

    settings = get_settings()
    previous = settings.mappings_path
    settings.mappings_path = _write(tmp_path, OVERLAY)
    mapping_overlay._cached.cache_clear()
    yield settings.mappings_path
    settings.mappings_path = previous
    mapping_overlay._cached.cache_clear()


def _echo_run(client, name: str) -> str:
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


@needs_db
def test_an_overlay_maps_findings_and_is_named_in_the_report(env, overlay_on):
    from khandaq.models import Finding

    client, engine = env
    eng_id = _echo_run(client, "overlay-on")
    with Session(engine) as s:
        leak = s.scalars(
            select(Finding).where(Finding.engagement_id == eng_id, Finding.rule_id == "echo.leak")
        ).one()
    ids = {(m["framework"], m["id"]) for m in leak.body["x-khandaq"]["mappings"]}
    # The overlay replaced the built-in echo.leak entry; the adapter's own id is still kept.
    assert ("acme-ctl", "CTL-7") in ids and ("owasp-llm-2026", "LLM02") in ids
    assert ("nist-ai-rmf", "MEASURE-2.10") not in ids

    report = client.get(f"/api/engagements/{eng_id}/report", headers=OWNER).json()
    tables = report["mapping_tables"]
    assert tables["versions"]["acme-ctl"] == "2026.1"
    assert tables["overlay"]["name"] == "acme-mappings.json"
    assert tables["overlay"]["sha256"] == load_overlay(overlay_on).sha256
    page = client.get(f"/api/engagements/{eng_id}/report.html", headers=OWNER).text
    assert "overlay acme-mappings.json (sha256:" in page


@needs_db
def test_without_an_overlay_the_report_says_so(env):
    client, _ = env
    eng_id = _echo_run(client, "overlay-off")
    report = client.get(f"/api/engagements/{eng_id}/report", headers=OWNER).json()
    assert report["mapping_tables"]["overlay"] is None
