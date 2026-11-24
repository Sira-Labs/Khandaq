"""The adapter registry, the adapter list, the request-rate refusal (spec 027) and forwarder
pacing (spec 032).

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
    assert manifest.forwarder_paced == disk.get("forwarder_paced", False)
    assert manifest.accepts_credential == disk.get("accepts_credential", False)
    assert manifest.offline == disk.get("offline", False)
    assert manifest.problems() == []


def test_garak_is_a_registered_container_adapter():
    garak = get_manifest("garak")
    assert garak is not None and not garak.builtin
    assert garak.image == "ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0"


def test_mcp_scanner_is_a_registered_container_adapter():
    scanner = get_manifest("mcp-scanner")
    assert scanner is not None and not scanner.builtin
    assert scanner.image == "ghcr.io/sira-labs/khandaq-adapter-mcp-scanner:4.8.5"
    # No rate cap it could hold; the target's credential is its bearer token (spec 031).
    assert scanner.paces_requests is False and scanner.accepts_credential is True


def test_art_is_a_registered_offline_adapter():
    """Spec 035: ART runs on stored content in a container without network. It sends nothing,
    so there is no request rate it could exceed, and it takes no credential."""
    art = get_manifest("art")
    assert art is not None and not art.builtin and art.offline is True
    assert art.image == "ghcr.io/sira-labs/khandaq-adapter-art:1.20.1"
    assert art.paces_requests is True and art.accepts_credential is False
    assert [m.name for m in all_manifests() if m.offline] == ["art"]


CAP = {"max_requests_per_minute": 60}


@pytest.mark.parametrize(
    ("adapter", "roe", "params", "refused"),
    [
        # garak is paced by the run's forwarder at the declared rate (spec 032).
        ("garak", CAP, {"rate_per_minute": 30}, None),
        ("garak", CAP, {"rate_per_minute": 0.5}, None),
        ("garak", CAP, {"rate_per_minute": 0}, "above 0"),  # nothing could be sent
        ("garak", {"max_requests_per_minute": 0}, {"rate_per_minute": 0}, "above 0"),
        ("garak", CAP, {}, "request-rate limit"),  # no declared rate, nothing to hold
        ("garak", CAP, None, "request-rate limit"),
        ("garak", {}, {}, None),
        ("garak", None, {"rate_per_minute": 30}, None),
        # A declared rate is kept without a cap too, so it has to be one the forwarder can hold.
        ("garak", {}, {"rate_per_minute": 0}, "above 0"),
        ("garak", {}, {"rate_per_minute": "30"}, "above 0"),
        ("garak", {}, {"rate_per_minute": True}, "above 0"),
        ("garak", {}, {"rate_per_minute": 10**400}, "above 0"),
        # Positive and finite, but 60 / rate is not: no turn would ever be let through.
        ("garak", {}, {"rate_per_minute": 1e-308}, "above 0"),
        ("garak", CAP, {"rate_per_minute": 1e-308}, "above 0"),
        # mcp-scanner is not paced by anything.
        ("mcp-scanner", CAP, {"rate_per_minute": 30}, "request-rate limit"),
        ("mcp-scanner", {}, {"rate_per_minute": 0}, None),
        ("echo", CAP, {"rate_per_minute": 30}, None),  # echo sends nothing to the target
    ],
)
def test_adapter_refusal_for_a_rate_cap(adapter, roe, params, refused):
    reason = adapter_refusal(get_manifest(adapter), roe, params)
    if refused is None:
        assert reason is None
    else:
        assert reason is not None and refused in reason


def test_only_garak_is_paced_by_the_forwarder():
    assert [m.name for m in all_manifests() if m.forwarder_paced] == ["garak"]
    assert get_manifest("garak").paces_requests is False  # it still holds no rate itself


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
    assert {"echo", "garak", "mcp-scanner"} <= set(by_name)
    assert by_name["mcp-scanner"]["version"] == "4.8.5"
    assert by_name["mcp-scanner"]["accepts_credential"] is True
    assert by_name["garak"]["builtin"] is False and by_name["garak"]["paces_requests"] is False
    assert by_name["garak"]["forwarder_paced"] is True
    assert by_name["mcp-scanner"]["forwarder_paced"] is False
    # The built-in echo adapter takes no credential (spec 028).
    assert by_name["garak"]["accepts_credential"] is True
    assert by_name["echo"]["accepts_credential"] is False
    assert by_name["garak"]["version"] == "0.17.0"


@needs_db
def test_a_capped_engagement_refuses_an_unpaced_adapter_with_an_audit_entry(ctx):
    client, _ = ctx
    eng_id, target_id = _engagement(client, {"max_requests_per_minute": 60})
    params = {"rate_per_minute": 30}  # within the cap: the scope lock alone would allow it

    check = client.post(
        f"/api/engagements/{eng_id}/scope-check",
        json={"target_id": target_id, "params": params, "adapter": "mcp-scanner"},
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
        json={"adapter": "mcp-scanner", "target_id": target_id, "params": params},
        headers=OWNER,
    ).json()
    assert run["state"] == "rejected" and "request-rate limit" in run["reject_reason"]
    audit = client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER).json()
    rejected = [a for a in audit if a["action"] == "run.rejected"]
    assert rejected and rejected[-1]["detail"]["adapter"] == "mcp-scanner"

    campaign = client.post(
        f"/api/engagements/{eng_id}/campaigns",
        json={
            "name": "nightly",
            "adapter": "mcp-scanner",
            "target_id": target_id,
            "params": params,
            "interval_minutes": 1440,
        },
        headers=OWNER,
    )
    assert campaign.status_code == 422 and "request-rate limit" in campaign.text


@needs_db
def test_an_unpaced_adapter_queues_without_a_cap_and_is_rechecked_at_claim(ctx):
    from khandaq import runs
    from khandaq.models import Run, Scope

    client, eng = ctx
    eng_id, target_id = _engagement(client, {})
    run = client.post(
        f"/api/engagements/{eng_id}/runs",
        # A declared rate, so the claim's scope re-check passes and the adapter check decides.
        json={"adapter": "mcp-scanner", "target_id": target_id, "params": {"rate_per_minute": 30}},
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


# --- forwarder pacing (spec 032) ------------------------------------------------------------------


def _garak_run(client, eng_id: str, target_id: str, rate: object) -> dict:
    return client.post(
        f"/api/engagements/{eng_id}/runs",
        json={"adapter": "garak", "target_id": target_id, "params": {"rate_per_minute": rate}},
        headers=OWNER,
    ).json()


def _state(eng, run_id: str) -> str:
    from khandaq.models import Run

    with Session(eng) as s:
        return s.scalars(select(Run.state).where(Run.id == run_id)).one()


def _finish(eng, run_id: str) -> None:
    """End a running run the way a recorded outcome would, without executing an adapter."""
    from khandaq.models import Run

    with Session(eng) as s:
        s.get(Run, run_id).state = "failed"
        s.commit()


def _claim(eng) -> str | None:
    from khandaq import runs

    with Session(eng) as s:
        return runs.claim_next_run(s)


@needs_db
def test_a_capped_engagement_runs_garak_paced_and_audits_the_rate(ctx):
    client, eng = ctx
    eng_id, target_id = _engagement(client, {"max_requests_per_minute": 60})

    check = client.post(
        f"/api/engagements/{eng_id}/scope-check",
        json={"target_id": target_id, "params": {"rate_per_minute": 30}, "adapter": "garak"},
        headers=OWNER,
    ).json()
    assert check == {"allowed": True, "reason": None}

    campaign = client.post(
        f"/api/engagements/{eng_id}/campaigns",
        json={
            "name": "nightly",
            "adapter": "garak",
            "target_id": target_id,
            "params": {"rate_per_minute": 30},
            "interval_minutes": 1440,
            "enabled": False,
        },
        headers=OWNER,
    )
    assert campaign.status_code in (200, 201), campaign.text

    run = _garak_run(client, eng_id, target_id, 30)
    assert run["state"] == "queued"
    assert _claim(eng) == run["id"]
    audit = client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER).json()
    [started] = [a for a in audit if a["action"] == "run.started"]
    assert started["detail"]["run_id"] == run["id"]
    assert started["detail"]["paced_per_minute"] == 30
    _finish(eng, run["id"])


@needs_db
def test_the_scope_lock_still_decides_before_pacing(ctx):
    """Pacing allows nothing the scope lock refuses (no rate, a rate above the cap); a zero rate,
    which the scope lock accepts, is refused by the adapter check."""
    client, _ = ctx
    eng_id, target_id = _engagement(client, {"max_requests_per_minute": 60})
    for params, why in (
        ({}, "set rate_per_minute"),
        ({"rate_per_minute": 61}, "exceeds the limit"),
        ({"rate_per_minute": 0}, "above 0"),
    ):
        run = client.post(
            f"/api/engagements/{eng_id}/runs",
            json={"adapter": "garak", "target_id": target_id, "params": params},
            headers=OWNER,
        ).json()
        assert run["state"] == "rejected" and why in run["reject_reason"], run
    audit = client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER).json()
    assert [a["action"] for a in audit].count("run.rejected") == 3


@needs_db
def test_an_unpaced_run_records_no_pace(ctx):
    client, eng = ctx
    eng_id, target_id = _engagement(client, {})
    run = client.post(
        f"/api/engagements/{eng_id}/runs",
        json={"adapter": "garak", "target_id": target_id, "params": {}},
        headers=OWNER,
    ).json()
    assert _claim(eng) == run["id"]
    audit = client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER).json()
    [started] = [a for a in audit if a["action"] == "run.started"]
    assert "paced_per_minute" not in started["detail"]
    _finish(eng, run["id"])


@needs_db
def test_paced_runs_of_a_capped_engagement_run_one_at_a_time(ctx):
    client, eng = ctx
    capped, capped_target = _engagement(client, {"max_requests_per_minute": 60})
    other, other_target = _engagement(client, {"max_requests_per_minute": 60})
    first = _garak_run(client, capped, capped_target, 60)
    second = _garak_run(client, capped, capped_target, 60)
    elsewhere = _garak_run(client, other, other_target, 60)

    assert _claim(eng) == first["id"]
    # The second run of the same engagement waits; the queue behind it is not blocked.
    assert _claim(eng) == elsewhere["id"]
    assert _claim(eng) is None
    assert _state(eng, second["id"]) == "queued"  # waiting, not rejected

    _finish(eng, first["id"])
    assert _claim(eng) == second["id"]
    _finish(eng, second["id"])
    _finish(eng, elsewhere["id"])


@needs_db
def test_two_workers_cannot_both_start_a_paced_run(ctx, monkeypatch):
    """Two workers can each pick one of two queued runs before either has started, so the query's
    own filter sees nothing running. The check under the engagement lock still lets only one
    start."""
    from sqlalchemy import false

    from khandaq import runs

    client, eng = ctx
    eng_id, target_id = _engagement(client, {"max_requests_per_minute": 60})
    first = _garak_run(client, eng_id, target_id, 60)
    second = _garak_run(client, eng_id, target_id, 60)

    # As the second worker saw it: the filter in the query did not hold its run back.
    monkeypatch.setattr(runs, "_waits_for_paced_run", lambda paced: false())
    assert _claim(eng) == first["id"]
    # A run of another engagement, queued behind the one that has to wait, is not hidden by it.
    other, other_target = _engagement(client, {"max_requests_per_minute": 60})
    elsewhere = _garak_run(client, other, other_target, 60)
    assert _claim(eng) == elsewhere["id"]
    assert _claim(eng) is None
    assert _state(eng, second["id"]) == "queued"  # waiting, not rejected, and not started
    _finish(eng, elsewhere["id"])
    _finish(eng, first["id"])
    assert _claim(eng) == second["id"]
    _finish(eng, second["id"])


def _waits_for_advisory_lock(eng, holder: Session, seconds: float = 5.0) -> bool:
    """Whether another session comes to wait for an advisory lock that ``holder`` holds."""
    import time

    pid = holder.execute(text("SELECT pg_backend_pid()")).scalar_one()
    deadline = time.monotonic() + seconds
    with eng.connect() as conn:
        while time.monotonic() < deadline:
            blocked = conn.execute(
                text(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted "
                    "AND :pid = ANY (pg_blocking_pids(pid))"
                ),
                {"pid": pid},
            ).scalar_one()
            conn.rollback()
            if blocked:
                return True
            time.sleep(0.02)
    return False


@needs_db
def test_the_engagement_lock_makes_a_second_worker_wait_for_the_first(ctx, monkeypatch):
    """Real contention: one worker is in mid-claim (holds the engagement lock and its run's row,
    not yet committed) while another claims the engagement's second run. The second must wait for
    the lock and then see the first as running; without the lock it would start its run at once."""
    import threading

    from sqlalchemy import false

    from khandaq import runs
    from khandaq.ledger import lock_engagement

    client, eng = ctx
    eng_id, target_id = _engagement(client, {"max_requests_per_minute": 60})
    first = _garak_run(client, eng_id, target_id, 60)
    second = _garak_run(client, eng_id, target_id, 60)
    monkeypatch.setattr(runs, "_waits_for_paced_run", lambda paced: false())
    result: list[str | None] = []

    with Session(eng) as holder:
        holder.execute(text("SELECT id FROM runs WHERE id = :id FOR UPDATE"), {"id": first["id"]})
        lock_engagement(holder, eng_id)
        other = threading.Thread(target=lambda: result.append(_claim(eng)))
        other.start()
        try:
            # Not "the thread has not returned yet", which is also true before it reached the
            # claim: the database itself must report a session waiting for the advisory lock.
            waiting = _waits_for_advisory_lock(eng, holder)
            holder.execute(
                text("UPDATE runs SET state = 'running' WHERE id = :id"), {"id": first["id"]}
            )
        finally:
            holder.commit()  # releases the lock whatever happened, so the worker can end
            other.join(timeout=10)
    started = result[0] if result else "still claiming"
    if started == second["id"]:  # leave no running run behind for the tests that follow
        _finish(eng, second["id"])
    assert waiting and started is None
    assert _state(eng, second["id"]) == "queued"
    _finish(eng, first["id"])
    assert _claim(eng) == second["id"]
    _finish(eng, second["id"])


@needs_db
def test_what_changed_while_the_claim_waited_for_the_lock_is_decided_again(ctx, monkeypatch):
    """A paced run passes the scope check, then waits for the engagement lock. If the rules
    changed during the wait (a window closed, the cap went down) the run is not started on the
    earlier answer: the check runs again under the lock, and the run is rejected and audited."""
    from khandaq import runs

    client, eng = ctx
    eng_id, target_id = _engagement(client, {"max_requests_per_minute": 60})
    run = _garak_run(client, eng_id, target_id, 30)
    assert run["state"] == "queued"
    real_lock = runs.lock_engagement

    def lock_after_a_wait(session, engagement_id):
        with eng.begin() as conn:  # committed by someone else while this claim waited
            conn.execute(
                text(
                    "UPDATE scopes SET roe = jsonb_set(roe, '{max_requests_per_minute}', '10') "
                    "WHERE engagement_id = :e"
                ),
                {"e": engagement_id},
            )
        return real_lock(session, engagement_id)

    monkeypatch.setattr(runs, "lock_engagement", lock_after_a_wait)
    assert _claim(eng) is None
    assert _state(eng, run["id"]) == "rejected"
    audit = client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER).json()
    [rejected] = [a for a in audit if a["action"] == "run.rejected"]
    assert rejected["detail"]["run_id"] == run["id"] and rejected["detail"]["at"] == "claim"
    assert not [a for a in audit if a["action"] == "run.started"]


@needs_db
def test_uncapped_paced_runs_are_not_held_back(ctx):
    client, eng = ctx
    eng_id, target_id = _engagement(client, {})
    first = _garak_run(client, eng_id, target_id, 60)
    second = _garak_run(client, eng_id, target_id, 60)
    assert _claim(eng) == first["id"]
    assert _claim(eng) == second["id"]
    _finish(eng, first["id"])
    _finish(eng, second["id"])
