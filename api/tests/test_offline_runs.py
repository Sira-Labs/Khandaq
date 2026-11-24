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
MODEL_AT, DATA_AT = "s3://sow-bucket/model.skops", "s3://sow-bucket/eval.npz"
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
        # The allowed locations, but another digest (and that digest's content).
        "model_by_location": _target(
            client, eng_id, "model_artifact", {"digest": _digest(OTHER), "location": MODEL_AT}
        ),
        "dataset_by_location": _target(
            client, eng_id, "dataset", {"digest": _digest(OTHER), "location": DATA_AT}
        ),
    }
    _upload(client, eng_id, ids["model_by_location"], OTHER)
    _upload(client, eng_id, ids["dataset_by_location"], OTHER)
    if upload_model:
        _upload(client, eng_id, ids["model"], MODEL)
    if upload_dataset:
        _upload(client, eng_id, ids["dataset"], DATA)
    _upload(client, eng_id, ids["unlisted"], OTHER)
    allow: dict = {
        "model_artifact": [{"digest": _digest(MODEL), "location": MODEL_AT}],
        "llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}],
    }
    if allow_dataset:
        allow["dataset"] = [{"digest": _digest(DATA), "location": DATA_AT}]
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
    """The worker's own sequence for this run: ``claim_next_run``, then ``execute_run``. Runs
    that other tests left queued are taken out of the way first, so the claim finds this one."""
    from khandaq import runs

    with db.begin() as conn:
        conn.execute(
            text("UPDATE runs SET state = 'failed' WHERE state = 'queued' AND id <> :r"),
            {"r": run_id},
        )
    with Session(db) as session:
        claimed = runs.claim_next_run(session)
        if claimed is None:
            return "rejected"
        assert claimed == run_id
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


def test_under_a_rate_cap_an_offline_run_declares_a_rate_like_any_other(env):
    """The scope lock is unchanged: under a cap it wants a declared rate from every run, also
    from one that sends nothing. With one, the cap does not stand in the way."""
    client, _, _ = env
    ids = _engagement(client, "capped", roe={"max_requests_per_minute": 30})
    without = _run(client, ids, dataset_target_id=ids["dataset"])
    assert without["state"] == "rejected" and "rate_per_minute" in without["reject_reason"]
    run = _run(client, ids, dataset_target_id=ids["dataset"], rate_per_minute=10)
    assert run["state"] == "queued", run


@pytest.mark.parametrize("which", ["model", "dataset"])
def test_content_allowed_only_by_its_location_is_not_run(env, which):
    """The lock lets a model or dataset in by `location` as well as by digest, and Khandaq never
    fetches a location. A target that carries an allowed location and some other digest must not
    bring that digest's content into a run: content runs only when a rule names its digest."""
    client, db, _ = env
    ids = _engagement(client, f"by location {which}")
    ids[which] = ids[f"{which}_by_location"]  # in scope for the lock, by its location alone
    run = _run(client, ids, dataset_target_id=ids["dataset"])
    assert run["state"] == "rejected", run
    assert f"{which}: " in run["reject_reason"] and "names its digest" in run["reject_reason"]
    assert _audit(db, ids["eng"], "run.rejected")[-1]["run_id"] == run["id"]


def test_the_builtin_adapter_still_runs_on_any_target_in_scope(env):
    client, _, _ = env
    ids = _engagement(client, "echo")
    assert _run(client, ids, adapter="echo", target="model")["state"] in ("queued", "succeeded")


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


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("DELETE FROM target_artefacts WHERE target_id = :t", "dataset: no content is stored"),
        ("UPDATE scopes SET allow = allow - 'dataset' WHERE engagement_id = :e", "dataset: "),
    ],
)
def test_the_claim_checks_the_dataset_again(env, change, reason):
    """Queued while everything was in order; by the time a worker takes it the dataset's content
    record is gone, or the scope no longer allows the dataset. The worker's claim runs the same
    checks again, and nothing is started."""
    client, db, _ = env
    ids = _engagement(client, "claim")
    run = _run(client, ids, dataset_target_id=ids["dataset"])
    assert run["state"] == "queued"
    with db.begin() as conn:
        conn.execute(text(change), {"t": ids["dataset"], "e": ids["eng"]})
    runner = RecordingRunner()
    assert _claim_and_execute(db, run["id"], runner) == "rejected"
    assert runner.calls == []
    rejected = _audit(db, ids["eng"], "run.rejected")
    assert rejected[-1]["at"] == "claim" and reason in rejected[-1]["reason"]
    assert _audit(db, ids["eng"], "run.started") == []


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
