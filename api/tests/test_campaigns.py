"""Campaigns: scheduled re-runs and their diffs (spec 016, ADR-0017). Postgres; the container is a
fake runner returning chosen findings, so no Docker daemon is needed. Synthetic data only."""

from __future__ import annotations

import datetime as dt
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from khandaq.adapters.manifest import AdapterManifest

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
TARGET = {"host": "gw.acme.test", "base_url": "https://gw.acme.test/v1", "model": "assistant-v3"}
SCOPE = {
    "allow": {"llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}]},
    "deny": [],
    "roe": {},
}
CONTAINER = AdapterManifest(
    name="garak",
    version="0.17.0",
    phases=["03-scanning"],
    severity_table={"high": "high"},
    image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
)


class ProbeRunner:
    """Returns one finding per probe name it is given (each a distinct fingerprint)."""

    def __init__(self, probes: list[str], error: Exception | None = None) -> None:
        self.probes = probes
        self.error = error

    def run(self, request: dict) -> dict:
        if self.error is not None:
            raise self.error
        return {
            "evidence": [],
            "findings": [
                {
                    "schema": "khandaq.finding/2",
                    "engagement_id": request["engagement_id"],
                    "run_id": request["run_id"],
                    "rule_id": f"garak.{probe}",
                    "title": f"probe {probe}",
                    "severity": "high",
                    "source": {"tool": "garak", "version": "0.17.0"},
                    "locations": [{"logicalLocations": [{"fullyQualifiedName": probe}]}],
                    "x-khandaq": {"phase": "04-prompt-injection", "mappings": []},
                }
                for probe in self.probes
            ],
        }


@pytest.fixture(scope="module")
def env():
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
    yield TestClient(app), eng
    eng.dispose()


@pytest.fixture(autouse=True)
def container_adapter(monkeypatch):
    from khandaq import campaigns, runs

    real = runs.get_manifest

    def lookup(name):
        return CONTAINER if name == "garak" else real(name)

    monkeypatch.setattr(runs, "get_manifest", lookup)
    monkeypatch.setattr(campaigns, "get_manifest", lookup)


def _engagement(client, name: str, activate: bool = True) -> tuple[str, str]:
    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    tid = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": TARGET},
        headers=OWNER,
    ).json()["id"]
    client.put(f"/api/engagements/{eng_id}/scope", json=SCOPE, headers=OWNER)
    if activate:
        client.post(
            f"/api/engagements/{eng_id}/activate",
            json={"authorisation_ref": "SOW-1"},
            headers=OWNER,
        )
    return eng_id, tid


def _create(client, eng_id, tid, headers=OWNER, **overrides):
    body = {
        "name": "weekly injection",
        "adapter": "garak",
        "target_id": tid,
        "interval_minutes": 60,
    }
    body.update(overrides)
    return client.post(f"/api/engagements/{eng_id}/campaigns", json=body, headers=headers)


def _audit(db, eng_id: str, action: str) -> list[dict]:
    with db.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT detail FROM audit_log WHERE engagement_id = :e AND action = :a "
                    "ORDER BY at, id"
                ),
                {"e": eng_id, "a": action},
            ).scalars()
        )


def _make_due(db, campaign_id: str) -> None:
    with db.begin() as conn:
        conn.execute(
            text("UPDATE campaigns SET next_run_at = now() - interval '1 minute' WHERE id = :c"),
            {"c": campaign_id},
        )


def _schedule(db) -> int:
    from khandaq.campaigns import schedule_due

    with Session(db) as s:
        return schedule_due(s)


def _cycle(db, campaign_id: str, probes: list[str], error: Exception | None = None) -> None:
    """One campaign window: make it due, schedule it, let the worker execute it."""
    from khandaq import worker

    _make_due(db, campaign_id)
    assert _schedule(db) >= 1
    worker.drain(db, runner=ProbeRunner(probes, error))


def _add_member(db, eng_id: str, email: str, role: str) -> dict:
    from khandaq import models as m

    with Session(db) as s:
        user = m.User(email=email, org_role="member")
        s.add(user)
        s.flush()
        s.add(m.EngagementMember(engagement_id=eng_id, user_id=user.id, role=role))
        s.commit()
    return {"X-Khandaq-Dev-User": email}


# --- create ----------------------------------------------------------------------------------


def test_create_validates_and_audits(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-create")
    other_eng, other_tid = _engagement(client, "cmp-create-other")

    assert _create(client, eng_id, tid, adapter="nope").status_code == 422
    assert _create(client, eng_id, other_tid).status_code == 404
    r = _create(client, eng_id, tid, interval_minutes=5)
    assert r.status_code == 422 and "at least 60" in r.json()["detail"]
    assert _create(client, eng_id, tid, interval_minutes="60").status_code == 422  # strict int

    r = _create(client, eng_id, tid)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["enabled"] is True and body["interval_minutes"] == 60
    next_run = dt.datetime.fromisoformat(body["next_run_at"])
    assert abs((next_run - dt.datetime.now(dt.UTC)).total_seconds()) < 60
    [created] = _audit(db, eng_id, "campaign.created")
    assert created["campaign_id"] == body["id"] and created["adapter"] == "garak"

    future = (dt.datetime.now(dt.UTC) + dt.timedelta(days=2)).isoformat()
    later = _create(client, eng_id, tid, start_at=future).json()
    assert dt.datetime.fromisoformat(later["next_run_at"]) > dt.datetime.now(dt.UTC)


def test_create_refuses_a_draft_engagement_and_an_out_of_scope_template(env):
    client, db = env
    draft, draft_tid = _engagement(client, "cmp-draft", activate=False)
    assert _create(client, draft, draft_tid).status_code == 409

    eng_id, tid = _engagement(client, "cmp-scope")
    r = _create(client, eng_id, tid, params={"model": "other-model"})
    assert r.status_code == 422 and r.json()["detail"].startswith("out of scope")
    [rejected] = _audit(db, eng_id, "campaign.rejected")
    assert rejected["adapter"] == "garak" and rejected["reason"]
    assert client.get(f"/api/engagements/{eng_id}/campaigns", headers=OWNER).json() == []


# --- schedule --------------------------------------------------------------------------------


def test_a_due_campaign_gets_one_run_and_moves_on(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-due")
    campaign = _create(client, eng_id, tid).json()

    assert _schedule(db) >= 1
    runs = client.get(
        f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/runs", headers=OWNER
    ).json()
    assert [(r["state"], r["campaign_id"]) for r in runs] == [("queued", campaign["id"])]
    [scheduled] = _audit(db, eng_id, "campaign.run_scheduled")
    assert scheduled == {"campaign_id": campaign["id"], "run_id": runs[0]["id"]}
    after = client.get(f"/api/engagements/{eng_id}/campaigns/{campaign['id']}", headers=OWNER)
    moved = dt.datetime.fromisoformat(after.json()["next_run_at"]) - dt.datetime.now(dt.UTC)
    assert dt.timedelta(minutes=58) < moved <= dt.timedelta(minutes=60)

    # Not due again yet; and once due, a run still in flight means no second run.
    assert _schedule(db) == 0
    _make_due(db, campaign["id"])
    _schedule(db)
    assert (
        len(
            client.get(
                f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/runs", headers=OWNER
            ).json()
        )
        == 1
    )
    assert _audit(db, eng_id, "campaign.run_scheduled")[-1]["skipped"].startswith(
        "the previous run"
    )


def test_a_disabled_campaign_is_not_scheduled(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-disabled")
    campaign = _create(client, eng_id, tid).json()
    client.patch(
        f"/api/engagements/{eng_id}/campaigns/{campaign['id']}",
        json={"enabled": False},
        headers=OWNER,
    )
    _schedule(db)
    assert (
        client.get(
            f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/runs", headers=OWNER
        ).json()
        == []
    )


def test_two_workers_never_schedule_the_same_window(env):
    from khandaq.campaigns import schedule_due
    from khandaq.models import Campaign

    client, db = env
    eng_id, tid = _engagement(client, "cmp-concurrent")
    campaign = _create(client, eng_id, tid).json()
    with Session(db) as holder:
        # Worker A holds the campaign row (as if mid-schedule); worker B skips it.
        holder.query(Campaign).filter_by(id=campaign["id"]).with_for_update().one()
        with Session(db) as other:
            schedule_due(other)
        holder.rollback()
    assert (
        client.get(
            f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/runs", headers=OWNER
        ).json()
        == []
    )
    _schedule(db)
    assert (
        len(
            client.get(
                f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/runs", headers=OWNER
            ).json()
        )
        == 1
    )


def test_a_campaign_run_out_of_scope_is_rejected_and_audited(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-narrowed")
    campaign = _create(client, eng_id, tid).json()
    narrowed = {**SCOPE, "deny": [{"host": "gw.acme.test"}]}
    assert (
        client.put(f"/api/engagements/{eng_id}/scope", json=narrowed, headers=OWNER).status_code
        == 200
    )

    _schedule(db)
    [run] = client.get(
        f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/runs", headers=OWNER
    ).json()
    assert run["state"] == "rejected"
    scheduled = _audit(db, eng_id, "campaign.run_scheduled")[-1]
    assert scheduled["run_id"] == run["id"] and scheduled["rejected"]
    assert _audit(db, eng_id, "run.rejected")[-1]["campaign_id"] == campaign["id"]


def test_a_builtin_campaign_is_executed_by_the_worker(env):
    from khandaq import worker

    client, db = env
    eng_id, tid = _engagement(client, "cmp-echo")
    campaign = _create(client, eng_id, tid, adapter="echo").json()
    _schedule(db)
    worker.drain(db)
    [run] = client.get(
        f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/runs", headers=OWNER
    ).json()
    assert run["state"] == "succeeded"
    [diff] = client.get(
        f"/api/engagements/{eng_id}/campaigns/{campaign['id']}/diffs", headers=OWNER
    ).json()
    assert diff["baseline"] is True and diff["findings_count"] == 2


# --- diff ------------------------------------------------------------------------------------


def test_diff_sequence_baseline_new_resolved_regressed_unchanged(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-diff")
    cid = _create(client, eng_id, tid).json()["id"]

    def latest():
        return client.get(f"/api/engagements/{eng_id}/campaigns/{cid}/diffs", headers=OWNER).json()[
            0
        ]

    def rules(entries):
        return [e["rule_id"] for e in entries]

    _cycle(db, cid, ["a", "b"])
    d = latest()
    assert d["baseline"] is True and d["findings_count"] == 2 and d["worsened"] is False

    _cycle(db, cid, ["a", "b", "c"])
    d = latest()
    assert (rules(d["new"]), d["regressed"], d["resolved"]) == (["garak.c"], [], [])
    assert d["unchanged_count"] == 2 and d["worsened"] is True
    assert d["new"][0]["title"] == "probe c" and d["new"][0]["finding_id"].startswith("fnd_")

    _cycle(db, cid, ["a", "c"])
    d = latest()
    assert (d["new"], d["regressed"], rules(d["resolved"])) == ([], [], ["garak.b"])
    assert d["worsened"] is False

    _cycle(db, cid, ["a", "b", "c"])
    d = latest()
    assert (d["new"], rules(d["regressed"]), d["resolved"]) == ([], ["garak.b"], [])
    assert d["worsened"] is True

    _cycle(db, cid, ["a", "b", "c"])
    d = latest()
    assert (d["new"], d["regressed"], d["resolved"], d["unchanged_count"]) == ([], [], [], 3)
    assert d["worsened"] is False

    diffs = _audit(db, eng_id, "campaign.diff")
    assert [x["worsened"] for x in diffs] == [False, True, False, True, False]
    assert (
        len(
            client.get(
                f"/api/engagements/{eng_id}/campaigns/{cid}/diffs?limit=2", headers=OWNER
            ).json()
        )
        == 2
    )


def test_a_failed_campaign_run_gets_no_diff_and_keeps_the_baseline(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-failed")
    cid = _create(client, eng_id, tid).json()["id"]
    _cycle(db, cid, ["a"], error=RuntimeError("tool crashed"))
    assert (
        client.get(f"/api/engagements/{eng_id}/campaigns/{cid}/diffs", headers=OWNER).json() == []
    )
    _cycle(db, cid, ["a"])
    [d] = client.get(f"/api/engagements/{eng_id}/campaigns/{cid}/diffs", headers=OWNER).json()
    assert d["baseline"] is True


def test_diffs_are_append_only(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-append-only")
    cid = _create(client, eng_id, tid).json()["id"]
    _cycle(db, cid, ["a"])
    with db.connect() as conn:
        for statement in (
            "UPDATE campaign_diffs SET worsened = true",
            "DELETE FROM campaign_diffs",
        ):
            with pytest.raises(DBAPIError, match="append-only"):
                conn.execute(text(statement))
            conn.rollback()


# --- update and authz ------------------------------------------------------------------------


def test_update_is_audited_and_bounded(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-update")
    cid = _create(client, eng_id, tid).json()["id"]
    url = f"/api/engagements/{eng_id}/campaigns/{cid}"

    r = client.patch(url, json={"enabled": False, "interval_minutes": 120}, headers=OWNER)
    assert (
        r.status_code == 200
        and r.json()["enabled"] is False
        and r.json()["interval_minutes"] == 120
    )
    [updated] = _audit(db, eng_id, "campaign.updated")
    assert updated["before"]["enabled"] is True and updated["after"]["interval_minutes"] == 120
    assert client.patch(url, json={"interval_minutes": 10}, headers=OWNER).status_code == 422
    client.patch(url, json={"enabled": False}, headers=OWNER)  # no change, no audit entry
    assert len(_audit(db, eng_id, "campaign.updated")) == 1

    client.post(f"/api/engagements/{eng_id}/close", headers=OWNER)
    assert client.patch(url, json={"enabled": True}, headers=OWNER).status_code == 409


def test_campaign_authz(env):
    client, db = env
    eng_id, tid = _engagement(client, "cmp-authz")
    cid = _create(client, eng_id, tid).json()["id"]
    viewer = _add_member(db, eng_id, "cmp-viewer@test", "viewer")
    operator = _add_member(db, eng_id, "cmp-operator@test", "operator")
    outsider = {"X-Khandaq-Dev-User": "cmp-outsider@test"}
    base = f"/api/engagements/{eng_id}/campaigns"

    assert client.get(base, headers=viewer).status_code == 200
    assert client.get(f"{base}/{cid}/diffs", headers=viewer).status_code == 200
    assert _create(client, eng_id, tid, headers=viewer).status_code == 403
    assert client.patch(f"{base}/{cid}", json={"enabled": False}, headers=viewer).status_code == 403
    assert _create(client, eng_id, tid, headers=operator).status_code == 201
    assert client.get(base, headers=outsider).status_code == 403

    other_eng, _ = _engagement(client, "cmp-authz-other")
    assert (
        client.get(f"/api/engagements/{other_eng}/campaigns/{cid}", headers=OWNER).status_code
        == 404
    )
    assert (
        client.get(f"/api/engagements/{other_eng}/campaigns/{cid}/diffs", headers=OWNER).status_code
        == 404
    )
