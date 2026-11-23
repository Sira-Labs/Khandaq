"""Offline runs on stored content (spec 035): the scope lock decides the model and the dataset,
content must be stored, and the worker hands the runner exactly the verified bytes.

API and worker tests against Postgres with a recording runner; the ART image itself is covered by
``adapters/art/tests``. All content is synthetic bytes.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
OCTET = {"Content-Type": "application/octet-stream"}
EVIDENCE_KEY = "synthetic-test-evidence-key-0123456789"
MODEL = b"synthetic model bytes \x00\x01 " * 40
DATA = b"synthetic,evaluation,rows\n" * 30
OTHER = b"another synthetic dataset\n" * 30
LLM = {"base_url": "https://gw.acme.test/v1/chat/completions", "model": "assistant-v3"}


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class RecordingRunner:
    """Stands in for DockerRunner: records what each run was handed."""

    def __init__(self) -> None:
        self.calls: list[tuple[dict, dict | None]] = []

    def run(self, request: dict, credential: str | None = None, inputs: dict | None = None):
        self.calls.append((request, inputs))
        content = b'{"khandaq":"completion","results":0}\n'
        return {
            "evidence": [
                {
                    "local_id": "art-results.jsonl",
                    "kind": "report",
                    "object_key": "{engagement_id}/{run_id}/art-results.jsonl".format(**request),
                    "sha256": _digest(content),
                    "bytes": len(content),
                    "redacted": False,
                    "content": content,
                }
            ],
            "findings": [],
        }


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    from khandaq import main, migrate
    from khandaq.deps import get_session
    from khandaq.settings import get_settings

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

    settings = get_settings()
    names = ("evidence_dir", "evidence_key", "object_store_url")
    previous = {name: getattr(settings, name) for name in names}
    settings.evidence_dir = str(tmp_path_factory.mktemp("evidence"))
    settings.evidence_key = EVIDENCE_KEY
    settings.object_store_url = ""
    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app), eng, settings
    for name, value in previous.items():
        setattr(settings, name, value)
    eng.dispose()


def _target(client, eng_id: str, target_type: str, spec: dict) -> str:
    r = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": target_type, "spec": spec},
        headers=OWNER,
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _upload(client, eng_id: str, target_id: str, content: bytes) -> None:
    r = client.put(
        f"/api/engagements/{eng_id}/targets/{target_id}/artefact",
        content=content,
        headers={**OWNER, **OCTET},
    )
    assert r.status_code == 201, r.text


def _engagement(
    client,
    name: str,
    *,
    allow_dataset: bool = True,
    upload_model: bool = True,
    upload_dataset: bool = True,
    roe: dict | None = None,
) -> dict:
    """An active engagement with a model, a dataset, a second dataset that is in no allow rule,
    and an LLM endpoint."""
    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    ids = {
        "eng": eng_id,
        "model": _target(client, eng_id, "model_artifact", {"digest": _digest(MODEL)}),
        "dataset": _target(client, eng_id, "dataset", {"digest": _digest(DATA)}),
        "unlisted": _target(client, eng_id, "dataset", {"digest": _digest(OTHER)}),
        "llm": _target(client, eng_id, "llm_endpoint", LLM),
    }
    if upload_model:
        _upload(client, eng_id, ids["model"], MODEL)
    if upload_dataset:
        _upload(client, eng_id, ids["dataset"], DATA)
    _upload(client, eng_id, ids["unlisted"], OTHER)
    allow: dict = {
        "model_artifact": [{"digest": _digest(MODEL)}],
        "llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}],
    }
    if allow_dataset:
        allow["dataset"] = [{"digest": _digest(DATA)}]
    scope = {"allow": allow, "deny": [], "roe": roe or {}}
    assert (
        client.put(f"/api/engagements/{eng_id}/scope", json=scope, headers=OWNER).status_code < 300
    )
    r = client.post(
        f"/api/engagements/{eng_id}/activate", json={"authorisation_ref": "SOW-1"}, headers=OWNER
    )
    assert r.status_code == 200, r.text
    return ids


def _run(client, ids: dict, adapter: str = "art", target: str = "model", **params) -> dict:
    r = client.post(
        f"/api/engagements/{ids['eng']}/runs",
        json={"adapter": adapter, "target_id": ids[target], "params": params},
        headers=OWNER,
    )
    assert r.status_code in (200, 201), r.text
    return r.json()


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


def _claim_and_execute(db, run_id: str, runner) -> str:
    """As the worker does it, for this run only (other tests' runs may be queued too)."""
    from khandaq import models as m
    from khandaq import runs

    with Session(db) as session:
        run = session.get(m.Run, run_id)
        engagement = session.get(m.Engagement, run.engagement_id)
        target = session.get(m.Target, run.target_id)
        manifest = runs.get_manifest(run.adapter)
        reason = runs.run_refusal(session, engagement, target, manifest, run.params or {})
        if reason is not None:
            runs._reject(session, run, reason, None, at="claim")
            session.commit()
            return "rejected"
        runs._start(session, run, target, manifest, None, by="worker")
        session.commit()
        return runs.execute_run(session, run_id, runner=runner).state


def test_an_offline_run_is_queued_when_both_targets_are_in_scope_and_stored(env):
    client, db, _ = env
    ids = _engagement(client, "ok")
    run = _run(client, ids, dataset_target_id=ids["dataset"])
    assert run["state"] == "queued", run
    assert _audit(db, ids["eng"], "run.rejected") == []


@pytest.mark.parametrize(
    ("setup", "params", "reason"),
    [
        ({}, {}, "dataset: 'dataset_target_id' must name a dataset target"),
        ({}, {"dataset_target_id": "tgt_unknown"}, "must name a dataset target"),
        ({}, {"dataset_target_id": 7}, "must name a dataset target"),
        ({}, {"dataset_target_id": "@model"}, "must name a dataset target"),  # not a dataset
        ({}, {"dataset_target_id": "@llm"}, "must name a dataset target"),
        ({}, {"dataset_target_id": "@foreign"}, "must name a dataset target"),
        # In the engagement, stored, but in no allow rule: the scope lock refuses it.
        ({}, {"dataset_target_id": "@unlisted"}, "dataset: dataset"),
        ({"allow_dataset": False}, {"dataset_target_id": "@dataset"}, "dataset: no allow rule"),
        ({"upload_model": False}, {"dataset_target_id": "@dataset"}, "model: no content is stored"),
        (
            {"upload_dataset": False},
            {"dataset_target_id": "@dataset"},
            "dataset: no content is stored",
        ),
    ],
)
def test_an_offline_run_needs_both_targets_in_scope_and_stored(env, setup, params, reason):
    client, db, _ = env
    foreign = _engagement(client, "someone else's")
    ids = _engagement(client, "refusals", **setup)
    ids["foreign"] = foreign["dataset"]
    params = {
        key: ids[value[1:]] if isinstance(value, str) and value.startswith("@") else value
        for key, value in params.items()
    }
    run = _run(client, ids, **params)
    assert run["state"] == "rejected", run
    assert reason in run["reject_reason"], run["reject_reason"]
    rejected = _audit(db, ids["eng"], "run.rejected")
    assert len(rejected) == 1 and rejected[0]["run_id"] == run["id"]
    assert reason in rejected[0]["reason"]
    assert _audit(db, ids["eng"], "run.queued") == []


def test_adapters_must_fit_their_target(env):
    client, db, _ = env
    ids = _engagement(client, "fit")
    # An offline adapter on a network target, and network adapters on stored content.
    on_llm = _run(client, ids, adapter="art", target="llm", dataset_target_id=ids["dataset"])
    assert on_llm["state"] == "rejected"
    assert "runs on a model_artifact target, not a llm_endpoint" in on_llm["reject_reason"]
    for adapter in ("garak", "mcp-scanner"):
        on_model = _run(client, ids, adapter=adapter, target="model")
        assert on_model["state"] == "rejected", on_model
        assert "needs a network target, not a model_artifact" in on_model["reject_reason"]
    # garak on its own kind of target is untouched by this.
    assert _run(client, ids, adapter="garak", target="llm")["state"] == "queued"
    assert len(_audit(db, ids["eng"], "run.rejected")) == 3


def test_a_rate_cap_does_not_refuse_an_adapter_that_sends_nothing(env):
    client, _, _ = env
    ids = _engagement(client, "capped", roe={"max_requests_per_minute": 30})
    run = _run(client, ids, dataset_target_id=ids["dataset"], rate_per_minute=10)
    assert run["state"] == "queued", run


def test_the_worker_hands_over_the_verified_contents_and_audits_their_digests(env):
    client, db, _ = env
    ids = _engagement(client, "handover")
    run = _run(client, ids, dataset_target_id=ids["dataset"], samples=50)
    runner = RecordingRunner()
    assert _claim_and_execute(db, run["id"], runner) == "succeeded"

    ((request, inputs),) = runner.calls
    assert inputs == {"model": MODEL, "dataset": DATA}
    assert request["target"] == {"type": "model_artifact", "spec": {"digest": _digest(MODEL)}}
    assert request["params"] == {"dataset_target_id": ids["dataset"], "samples": 50}
    assert request["inputs"] == {
        "dataset": {"sha256": _digest(DATA), "bytes": len(DATA)},
        "model": {"sha256": _digest(MODEL), "bytes": len(MODEL)},
    }
    assert MODEL[:20].decode("latin-1") not in str(request)  # digests, never the bytes
    started = [d for d in _audit(db, ids["eng"], "run.started") if d["run_id"] == run["id"]]
    assert started[0]["inputs"] == {"model": _digest(MODEL), "dataset": _digest(DATA)}
    assert started[0]["credential"] == "none"  # nothing to hold a credential for


def test_the_claim_checks_the_dataset_again(env):
    """Queued while everything was in order; by the time a worker takes it the dataset's content
    record is gone. The same checks run again at the claim, and nothing is started."""
    client, db, _ = env
    ids = _engagement(client, "claim")
    run = _run(client, ids, dataset_target_id=ids["dataset"])
    assert run["state"] == "queued"
    with db.begin() as conn:
        conn.execute(
            text("DELETE FROM target_artefacts WHERE target_id = :t"), {"t": ids["dataset"]}
        )
    runner = RecordingRunner()
    assert _claim_and_execute(db, run["id"], runner) == "rejected"
    assert runner.calls == []
    rejected = _audit(db, ids["eng"], "run.rejected")
    assert (
        rejected[-1]["at"] == "claim" and "dataset: no content is stored" in rejected[-1]["reason"]
    )


@pytest.mark.parametrize("which", ["model", "dataset"])
def test_tampered_content_fails_the_run_before_the_runner(env, which):
    client, db, settings = env
    ids = _engagement(client, f"tamper {which}")
    run = _run(client, ids, dataset_target_id=ids["dataset"])
    with db.connect() as conn:
        key = conn.execute(
            text("SELECT object_key FROM target_artefacts WHERE target_id = :t"),
            {"t": ids[which]},
        ).scalar_one()
    path = Path(settings.evidence_dir) / key
    blob = path.read_bytes()
    os.chmod(path, 0o640)
    path.write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))

    runner = RecordingRunner()
    assert _claim_and_execute(db, run["id"], runner) == "failed"
    assert runner.calls == []  # no container for content that is not what was authorised
    failed = [d for d in _audit(db, ids["eng"], "run.failed") if d["run_id"] == run["id"]]
    assert "stored content unusable" in failed[0]["error"]
