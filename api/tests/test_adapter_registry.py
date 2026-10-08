"""The adapter registry, the adapter list and the request-rate refusal (spec 027).

The unit tests need nothing; the integration tests need PostgreSQL (KHANDAQ_TEST_DATABASE_URL) and
skip otherwise.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from khandaq.adapters import all_manifests, get_manifest
from khandaq.runs import adapter_refusal

REPO = Path(__file__).resolve().parents[2]
TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")
OWNER = {"X-Khandaq-Dev-User": "rate-owner@test"}
TARGET = {"url": "https://gw.acme.test/v1/chat/completions", "model": "assistant-v3"}


# --- registry ------------------------------------------------------------------------------------


@pytest.mark.parametrize("manifest", [m for m in all_manifests() if not m.builtin], ids=str)
def test_container_manifests_match_their_adapter_yaml(manifest):
    # The registry is what the worker runs; adapter.yaml is what CI validates and the release
    # builds. A version or image bumped in one place only would run the wrong tool.
    disk = yaml.safe_load((REPO / "adapters" / manifest.name / "adapter.yaml").read_text())
    assert manifest.version == str(disk["version"])
    assert manifest.image == disk["image"]
    assert manifest.entrypoint == disk["entrypoint"]
    assert manifest.phases == disk["phases"]
    assert manifest.frameworks == disk["frameworks"]
    assert manifest.severity_table == disk["severity_table"]
    assert manifest.resources == disk["resources"]
    assert manifest.paces_requests == disk.get("paces_requests", False)
    assert manifest.problems() == []


def test_garak_is_a_registered_container_adapter():
    garak = get_manifest("garak")
    assert garak is not None and not garak.builtin
    assert garak.image == "ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0"


@pytest.mark.parametrize(
    ("adapter", "roe", "refused"),
    [
        ("garak", {"max_requests_per_minute": 60}, True),
        ("garak", {}, False),
        ("garak", None, False),
        ("garak", {"max_requests_per_minute": 0}, True),  # a zero cap is still a cap
        ("echo", {"max_requests_per_minute": 60}, False),  # echo sends nothing to the target
    ],
)
def test_adapter_refusal_for_a_rate_cap(adapter, roe, refused):
    reason = adapter_refusal(get_manifest(adapter), roe)
    assert (reason is not None) is refused
    if refused:
        assert "request-rate limit" in reason


# --- integration ---------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ctx():
    from khandaq import main, migrate
    from khandaq.deps import get_session

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)

    def _get_session():
        with Session(eng) as s:
            yield s

    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app), eng
    eng.dispose()


def _engagement(client, roe: dict) -> tuple[str, str]:
    eng_id = client.post("/api/engagements", json={"name": "rate"}, headers=OWNER).json()["id"]
    target_id = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": TARGET},
        headers=OWNER,
    ).json()["id"]
    scope = {
        "allow": {"llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}]},
        "deny": [],
        "roe": roe,
    }
    assert client.put(f"/api/engagements/{eng_id}/scope", json=scope, headers=OWNER).is_success
    r = client.post(
        f"/api/engagements/{eng_id}/activate", json={"authorisation_ref": "SOW-1"}, headers=OWNER
    )
    assert r.status_code == 200, r.text
    return eng_id, target_id


@needs_db
def test_the_adapter_list(ctx):
    client, _ = ctx
    r = client.get("/api/adapters", headers=OWNER)
    assert r.status_code == 200
    by_name = {a["name"]: a for a in r.json()}
    assert {"echo", "garak"} <= set(by_name)
    assert by_name["garak"]["builtin"] is False and by_name["garak"]["paces_requests"] is False
    assert by_name["garak"]["version"] == "0.17.0"


@needs_db
def test_a_capped_engagement_refuses_garak_with_an_audit_entry(ctx):
    client, _ = ctx
    eng_id, target_id = _engagement(client, {"max_requests_per_minute": 60})
    params = {"rate_per_minute": 30}  # within the cap: the scope lock alone would allow it

    check = client.post(
        f"/api/engagements/{eng_id}/scope-check",
        json={"target_id": target_id, "params": params, "adapter": "garak"},
        headers=OWNER,
    ).json()
    assert check["allowed"] is False and "request-rate limit" in check["reason"]
    without_adapter = client.post(
        f"/api/engagements/{eng_id}/scope-check",
        json={"target_id": target_id, "params": params},
        headers=OWNER,
    ).json()
    assert without_adapter["allowed"] is True  # the scope itself allows it

    run = client.post(
        f"/api/engagements/{eng_id}/runs",
        json={"adapter": "garak", "target_id": target_id, "params": params},
        headers=OWNER,
    ).json()
    assert run["state"] == "rejected" and "request-rate limit" in run["reject_reason"]
    audit = client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER).json()
    rejected = [a for a in audit if a["action"] == "run.rejected"]
    assert rejected and rejected[-1]["detail"]["adapter"] == "garak"

    campaign = client.post(
        f"/api/engagements/{eng_id}/campaigns",
        json={
            "name": "nightly",
            "adapter": "garak",
            "target_id": target_id,
            "params": params,
            "interval_minutes": 1440,
        },
        headers=OWNER,
    )
    assert campaign.status_code == 422 and "request-rate limit" in campaign.text


@needs_db
def test_garak_queues_without_a_cap_and_is_rechecked_at_claim(ctx):
    from khandaq import runs
    from khandaq.models import Run, Scope

    client, eng = ctx
    eng_id, target_id = _engagement(client, {})
    run = client.post(
        f"/api/engagements/{eng_id}/runs",
        # A declared rate, so the claim's scope re-check passes and the adapter check decides.
        json={"adapter": "garak", "target_id": target_id, "params": {"rate_per_minute": 30}},
        headers=OWNER,
    ).json()
    assert run["state"] == "queued"

    # The scope gains a rate cap before a worker claims the run: the claim refuses it.
    with Session(eng) as s:
        row = s.get(Scope, eng_id)
        row.roe = {"max_requests_per_minute": 60}
        s.commit()
    with Session(eng) as s:
        assert runs.claim_next_run(s) is None
    with Session(eng) as s:
        claimed = s.scalars(select(Run).where(Run.id == run["id"])).one()
        assert claimed.state == "rejected" and "request-rate limit" in claimed.reject_reason
