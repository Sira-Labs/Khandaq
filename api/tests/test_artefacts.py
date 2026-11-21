"""Artefact intake for model and dataset targets (spec 034).

API tests against Postgres: an upload is stored only when its SHA-256 is the target's digest,
owner only, encrypted, write-once and audited; and it is read back only after it matches that
digest again. All content here is synthetic bytes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from khandaq import artefacts
from khandaq.artefacts import ArtefactError

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")

DEV = "X-Khandaq-Dev-User"
OWNER = {DEV: "owner@test"}
EVIDENCE_KEY = "synthetic-test-evidence-key-0123456789"
MODEL = b"synthetic model bytes \x00\x01\x02 " * 64
DATA = b"synthetic,evaluation,rows\n" * 32
OCTET = {"Content-Type": "application/octet-stream"}


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    if not TEST_URL:
        pytest.skip("KHANDAQ_TEST_DATABASE_URL not set")
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
    names = ("evidence_dir", "evidence_key", "object_store_url", "artefact_max_mb")
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


def _engagement(client, name: str, specs: list[tuple[str, dict]] | None = None) -> tuple[str, list]:
    """A draft engagement with a model target and a dataset target named by digest."""
    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    if specs is None:
        specs = [
            ("model_artifact", {"digest": _digest(MODEL)}),
            ("dataset", {"digest": _digest(DATA)}),
        ]
    targets = []
    for target_type, spec in specs:
        r = client.post(
            f"/api/engagements/{eng_id}/targets",
            json={"type": target_type, "spec": spec},
            headers=OWNER,
        )
        assert r.status_code == 201, r.text
        targets.append(r.json()["id"])
    return eng_id, targets


def _url(eng_id: str, tid: str) -> str:
    return f"/api/engagements/{eng_id}/targets/{tid}/artefact"


def _put(client, eng_id: str, tid: str, content: bytes, headers=OWNER):
    return client.put(_url(eng_id, tid), content=content, headers={**headers, **OCTET})


def _member(db, eng_id: str, email: str, role: str) -> dict:
    from khandaq import models as m

    with Session(db) as s:
        user = m.User(email=email, org_role="member")
        s.add(user)
        s.flush()
        s.add(m.EngagementMember(engagement_id=eng_id, user_id=user.id, role=role))
        s.commit()
    return {"X-Khandaq-Dev-User": email}


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


def _rows(db, tid: str) -> list:
    with db.connect() as conn:
        return list(
            conn.execute(
                text("SELECT sha256, bytes, object_key FROM target_artefacts WHERE target_id = :t"),
                {"t": tid},
            )
        )


def _files(settings) -> list[Path]:
    return [p for p in Path(settings.evidence_dir).rglob("*") if p.is_file()]


def _target(db, tid: str):
    from khandaq import models as m

    with Session(db) as s:
        target = s.get(m.Target, tid)
        s.expunge(target)
        return target


# --- storing --------------------------------------------------------------------------------------


def test_an_owner_stores_content_that_matches_the_digest(env):
    client, db, _ = env
    eng_id, (model, data) = _engagement(client, "store")

    r = _put(client, eng_id, model, MODEL)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["target_id"] == model
    assert body["sha256"] == _digest(MODEL)
    assert body["bytes"] == len(MODEL)
    assert dt.datetime.fromisoformat(body["stored_at"]).tzinfo is not None

    assert _put(client, eng_id, data, DATA).status_code == 201
    assert _rows(db, model)[0][:2] == (_digest(MODEL), len(MODEL))
    assert _audit(db, eng_id, "target.artefact_stored") == [
        {
            "target_id": model,
            "type": "model_artifact",
            "sha256": _digest(MODEL),
            "bytes": len(MODEL),
        },
        {"target_id": data, "type": "dataset", "sha256": _digest(DATA), "bytes": len(DATA)},
    ]
    assert client.get(_url(eng_id, model), headers=OWNER).json() == body


def test_the_same_upload_twice_is_accepted_and_audited_once(env):
    client, db, _ = env
    eng_id, (model, _) = _engagement(client, "twice")
    first = _put(client, eng_id, model, MODEL)
    second = _put(client, eng_id, model, MODEL)
    assert (first.status_code, second.status_code) == (201, 200)
    assert second.json() == first.json()
    assert len(_rows(db, model)) == 1
    assert len(_audit(db, eng_id, "target.artefact_stored")) == 1


def test_content_with_another_digest_is_refused_and_audited(env):
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "mismatch")
    before = len(_files(settings))
    other = MODEL + b"one byte more"

    r = _put(client, eng_id, model, other)
    assert r.status_code == 422
    assert _digest(other) in r.json()["detail"] and _digest(MODEL) in r.json()["detail"]
    assert _rows(db, model) == []
    assert len(_files(settings)) == before
    assert _audit(db, eng_id, "target.artefact_stored") == []
    assert _audit(db, eng_id, "target.artefact_rejected") == [
        {
            "target_id": model,
            "type": "model_artifact",
            "expected": _digest(MODEL),
            "received": _digest(other),
            "bytes": len(other),
        }
    ]
    # The dataset's bytes are not the model's content either, whatever the client meant.
    assert _put(client, eng_id, model, DATA).status_code == 422
    assert client.get(_url(eng_id, model), headers=OWNER).status_code == 404


def test_only_the_owner_uploads_and_every_member_reads_the_status(env):
    client, db, _ = env
    eng_id, (model, _) = _engagement(client, "roles")
    members = {role: _member(db, eng_id, f"{role}@roles.test", role) for role in ROLES}
    outsider = {"X-Khandaq-Dev-User": "outsider@roles.test"}

    for headers in (*members.values(), outsider):
        assert _put(client, eng_id, model, MODEL, headers=headers).status_code == 403
    assert _rows(db, model) == []

    assert _put(client, eng_id, model, MODEL).status_code == 201
    for headers in members.values():
        assert client.get(_url(eng_id, model), headers=headers).status_code == 200
    assert client.get(_url(eng_id, model), headers=outsider).status_code == 403


ROLES = ("operator", "analyst", "viewer")


@pytest.mark.parametrize(
    ("target_type", "spec"),
    [
        ("llm_endpoint", {"base_url": "https://gw.acme.test/v1/chat/completions"}),
        ("mcp_server", {"url": "https://tools.acme.test/mcp"}),
        ("model_artifact", {"location": "registry.acme.test/models/assistant:3"}),
        ("dataset", {"digest": "sha256:abc"}),
        ("model_artifact", {"digest": _digest(MODEL).upper()}),
        ("model_artifact", {"digest": "md5:" + "0" * 32}),
        ("dataset", {"digest": _digest(MODEL) + "00"}),
    ],
)
def test_targets_that_cannot_hold_content_are_refused(env, target_type, spec):
    client, db, settings = env
    eng_id, (tid,) = _engagement(client, "unfit", [(target_type, spec)])
    before = len(_files(settings))
    r = _put(client, eng_id, tid, MODEL)
    assert r.status_code == 409, r.text
    assert _rows(db, tid) == []
    assert len(_files(settings)) == before
    assert _audit(db, eng_id, "target.artefact_stored") == []


def test_a_closed_engagement_refuses_an_upload(env):
    client, db, _ = env
    eng_id, (model, data) = _engagement(client, "closed")
    assert _put(client, eng_id, model, MODEL).status_code == 201
    assert client.post(f"/api/engagements/{eng_id}/close", headers=OWNER).status_code == 200

    assert _put(client, eng_id, data, DATA).status_code == 409
    assert _rows(db, data) == []
    # What was stored stays, as the engagement's evidence does.
    assert client.get(_url(eng_id, model), headers=OWNER).status_code == 200


def test_empty_and_oversized_bodies_are_refused(env, monkeypatch):
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "sizes")
    assert _put(client, eng_id, model, b"").status_code == 422

    monkeypatch.setattr(settings, "artefact_max_mb", 1)
    big = b"\x00" * (1024 * 1024 + 1)
    eng_big, (tid,) = _engagement(client, "big", [("model_artifact", {"digest": _digest(big)})])
    assert _put(client, eng_big, tid, big).status_code == 413

    # Without a Content-Length the limit is enforced while the body arrives.
    def chunks():
        for _ in range(5):
            yield b"\x00" * (256 * 1024)
        yield b"\x00"

    r = client.put(_url(eng_big, tid), content=chunks(), headers={**OWNER, **OCTET})
    assert r.status_code == 413
    assert _rows(db, tid) == [] and _rows(db, model) == []
    assert _audit(db, eng_big, "target.artefact_rejected") == []

    exact = b"\x01" * (1024 * 1024)
    eng_fit, (fit,) = _engagement(client, "fits", [("dataset", {"digest": _digest(exact)})])
    assert _put(client, eng_fit, fit, exact).status_code == 201


def test_target_reads_show_the_flag_and_the_size(env):
    client, _, _ = env
    eng_id, (model, data) = _engagement(client, "flags")
    assert _put(client, eng_id, model, MODEL).status_code == 201

    r = client.get(f"/api/engagements/{eng_id}/targets", headers=OWNER)
    shown = {t["id"]: t for t in r.json()}
    assert (shown[model]["has_artefact"], shown[model]["artefact_bytes"]) == (True, len(MODEL))
    assert (shown[data]["has_artefact"], shown[data]["artefact_bytes"]) == (False, None)
    assert MODEL[:16] not in r.content


def test_another_engagements_target_is_not_found(env):
    client, db, _ = env
    eng_a, (model_a, _) = _engagement(client, "mine")
    eng_b, _ = _engagement(client, "theirs")
    assert _put(client, eng_b, model_a, MODEL).status_code == 404
    assert client.get(_url(eng_b, model_a), headers=OWNER).status_code == 404
    assert _put(client, eng_a, "tgt_unknown", MODEL).status_code == 404
    assert _rows(db, model_a) == []


def test_the_stored_object_is_encrypted(env):
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "sealed")
    assert _put(client, eng_id, model, MODEL).status_code == 201
    key = _rows(db, model)[0][2]
    assert key == f"artefacts/{eng_id}/{model}/{_digest(MODEL).removeprefix('sha256:')}"
    blob = (Path(settings.evidence_dir) / key).read_bytes()
    assert MODEL[:32] not in blob and len(blob) > len(MODEL)


# --- reading back ---------------------------------------------------------------------------------


def test_read_artefact_returns_the_verified_bytes(env):
    client, db, settings = env
    eng_id, (model, data) = _engagement(client, "read")
    assert _put(client, eng_id, model, MODEL).status_code == 201
    assert _put(client, eng_id, data, DATA).status_code == 201
    with Session(db) as s:
        assert artefacts.read_artefact(s, _target(db, model), settings) == MODEL
        assert artefacts.read_artefact(s, _target(db, data), settings) == DATA


def test_read_artefact_refuses_tampered_moved_and_missing_content(env):
    client, db, settings = env
    eng_id, (model, data) = _engagement(client, "tamper")
    other = b"another synthetic model " * 64
    eng_o, (model_o,) = _engagement(
        client, "other", [("model_artifact", {"digest": _digest(other)})]
    )

    with Session(db) as s:
        with pytest.raises(ArtefactError) as missing:
            artefacts.read_artefact(s, _target(db, model), settings)
        assert missing.value.status == 404

    assert _put(client, eng_id, model, MODEL).status_code == 201
    assert _put(client, eng_o, model_o, other).status_code == 201
    path = Path(settings.evidence_dir) / _rows(db, model)[0][2]
    path_o = Path(settings.evidence_dir) / _rows(db, model_o)[0][2]
    original = path.read_bytes()

    def replace(blob: bytes) -> None:
        if path.exists():
            os.chmod(path, 0o640)
        path.write_bytes(blob)

    def refused() -> int:
        with Session(db) as s, pytest.raises(ArtefactError) as exc:
            artefacts.read_artefact(s, _target(db, model), settings)
        return exc.value.status

    replace(original[:-1] + bytes([original[-1] ^ 1]))  # one flipped bit
    assert refused() == 409
    replace(path_o.read_bytes())  # another target's envelope, moved here
    assert refused() == 409
    # The same bytes, stored for the same digest under another engagement's target: only the
    # binding of the envelope to its key tells them apart, and it must.
    eng_twin, (twin, _) = _engagement(client, "twin")
    assert _put(client, eng_twin, twin, MODEL).status_code == 201
    replace((Path(settings.evidence_dir) / _rows(db, twin)[0][2]).read_bytes())
    assert refused() == 409
    replace(MODEL)  # the right bytes, but not encrypted: not what Khandaq stored
    assert refused() == 409
    path.unlink()
    assert refused() == 404

    # A target whose digest was changed behind the row no longer reads the old content.
    replace(original)
    with db.begin() as conn:
        conn.execute(
            text(
                "UPDATE targets SET spec = jsonb_set(spec, '{digest}', "
                "to_jsonb(CAST(:d AS text))) WHERE id = :t"
            ),
            {"d": _digest(other), "t": model},
        )
    assert refused() == 409


def test_an_object_left_by_a_failed_commit_is_accepted_on_retry(env):
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "retry")
    assert _put(client, eng_id, model, MODEL).status_code == 201
    with db.begin() as conn:  # as if the object was written and the commit then failed
        conn.execute(text("DELETE FROM target_artefacts WHERE target_id = :t"), {"t": model})

    assert _put(client, eng_id, model, MODEL).status_code == 201
    with Session(db) as s:
        assert artefacts.read_artefact(s, _target(db, model), settings) == MODEL


def test_an_object_that_is_not_the_content_blocks_the_upload(env):
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "squat")
    key = artefacts.object_key(eng_id, model, _digest(MODEL))
    path = Path(settings.evidence_dir) / key
    path.parent.mkdir(parents=True)
    path.write_bytes(b"something else is already here")

    assert _put(client, eng_id, model, MODEL).status_code == 409
    assert _rows(db, model) == []
    assert path.read_bytes() == b"something else is already here"  # never overwritten


def test_the_right_bytes_in_plaintext_at_the_key_are_not_accepted_as_stored(env):
    """Whoever can write to the store could put the content there unencrypted. Evidence from
    before spec 014 may be plaintext; content never is, so this is not "already stored"."""
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "plain")
    path = Path(settings.evidence_dir) / artefacts.object_key(eng_id, model, _digest(MODEL))
    path.parent.mkdir(parents=True)
    path.write_bytes(MODEL)

    assert _put(client, eng_id, model, MODEL).status_code == 409
    assert _rows(db, model) == []
    assert _audit(db, eng_id, "target.artefact_stored") == []
    assert client.get(_url(eng_id, model), headers=OWNER).status_code == 404


def test_a_store_that_fails_is_a_503_and_records_nothing(env, monkeypatch):
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "diskfull")

    class Broken:
        def put_new(self, object_key: str, blob: bytes) -> None:
            raise OSError(28, "No space left on device")

        def get(self, object_key: str) -> bytes:
            raise OSError(5, "Input/output error")

    monkeypatch.setattr(artefacts, "store_from_settings", lambda s: Broken())
    assert _put(client, eng_id, model, MODEL).status_code == 503
    assert _rows(db, model) == []
    assert _audit(db, eng_id, "target.artefact_stored") == []
    monkeypatch.undo()

    assert _put(client, eng_id, model, MODEL).status_code == 201
    monkeypatch.setattr(artefacts, "store_from_settings", lambda s: Broken())
    with Session(db) as s, pytest.raises(ArtefactError) as exc:
        artefacts.read_artefact(s, _target(db, model), settings)
    assert exc.value.status == 503


def test_an_owner_who_lost_the_role_while_uploading_stores_nothing(env, monkeypatch):
    """Authorisation is decided before the body is read, and a body can take minutes. It is
    decided again before anything is stored."""
    from khandaq.routers import artefacts as route

    client, db, _ = env
    eng_id, (model, _) = _engagement(client, "demoted")
    second = _member(db, eng_id, "second-owner@demoted.test", "owner")
    real_body = route._body

    def after_the_body(statement: str):
        async def body(request, limit):
            content = await real_body(request, limit)
            with db.begin() as conn:  # what an admin did while the upload was on its way
                conn.execute(text(statement), {"e": eng_id, "m": "second-owner@demoted.test"})
            return content

        return body

    demote = (
        "UPDATE engagement_members SET role = 'viewer' WHERE engagement_id = :e "
        "AND user_id = (SELECT id FROM users WHERE email = :m)"
    )
    monkeypatch.setattr(route, "_body", after_the_body(demote))
    assert _put(client, eng_id, model, MODEL, headers=second).status_code == 403
    assert _rows(db, model) == []

    with db.begin() as conn:
        conn.execute(text(demote.replace("'viewer'", "'owner'")), {"e": eng_id, "m": second[DEV]})
    disable = "UPDATE users SET disabled = true WHERE email = :m AND CAST(:e AS text) IS NOT NULL"
    monkeypatch.setattr(route, "_body", after_the_body(disable))
    assert _put(client, eng_id, model, MODEL, headers=second).status_code == 403
    assert _rows(db, model) == []
    assert _audit(db, eng_id, "target.artefact_stored") == []


def test_a_body_that_does_not_arrive_in_time_is_a_408(env, monkeypatch):
    import asyncio

    from khandaq.routers import artefacts as route

    client, db, _ = env
    eng_id, (model, _) = _engagement(client, "trickle")

    async def never(request, limit):
        await asyncio.sleep(3600)

    monkeypatch.setattr(route, "_body", never)
    monkeypatch.setattr(route, "UPLOAD_SECONDS", 0.05)
    assert _put(client, eng_id, model, MODEL).status_code == 408
    assert _rows(db, model) == []


def test_a_wrong_upload_is_refused_without_waiting_for_the_engagement_lock(env):
    """The digest is checked before the lock that sealing and closing take, so a large wrong
    upload cannot make them wait; only a matching one goes on to the lock."""
    from khandaq.ledger import lock_engagement

    client, db, _ = env
    eng_id, (model, _) = _engagement(client, "nolock")
    with Session(db) as busy:
        lock_engagement(busy, eng_id)  # a seal or a close is in progress
        done: dict = {}
        thread = threading.Thread(
            target=lambda: done.update(r=_put(client, eng_id, model, MODEL + b"!"))
        )
        thread.start()
        thread.join(timeout=5)
        waited = thread.is_alive()
        busy.rollback()
    thread.join(timeout=10)
    assert not waited and done["r"].status_code == 422


def test_no_evidence_key_is_a_503_and_stores_nothing(env, monkeypatch):
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "nokey")
    before = len(_files(settings))
    monkeypatch.setattr(settings, "evidence_key", "")
    assert _put(client, eng_id, model, MODEL).status_code == 503
    assert _rows(db, model) == []
    assert len(_files(settings)) == before
    assert _audit(db, eng_id, "target.artefact_stored") == []


def test_production_without_an_object_store_refuses_uploads(env, monkeypatch):
    """The API's own evidence directory is not the worker's: content stored there would be
    recorded and never usable. The test deployment (not prod) keeps the local store."""
    client, db, settings = env
    eng_id, (model, _) = _engagement(client, "nostore")
    before = len(_files(settings))
    monkeypatch.setattr(settings, "env", "prod")
    r = client.put(_url(eng_id, model), content=MODEL, headers=OCTET)
    assert r.status_code == 401  # prod has no dev login: nothing is read from an anonymous caller

    with Session(db) as s:
        from khandaq import models as m

        owner = s.scalar(text("SELECT id FROM users WHERE email = 'owner@test'"))
        with pytest.raises(ArtefactError) as exc:
            artefacts.store_artefact(
                s, s.get(m.Target, model), MODEL, actor=s.get(m.User, owner), settings=settings
            )
        assert exc.value.status == 503 and not exc.value.audited
    assert _rows(db, model) == []
    assert len(_files(settings)) == before


def test_an_upload_cannot_slip_in_behind_a_concurrent_close(env):
    from khandaq import models as m
    from khandaq.ledger import lock_engagement

    client, db, _ = env
    eng_id, (model, _) = _engagement(client, "race")
    result: dict = {}

    def put() -> None:
        result["response"] = _put(client, eng_id, model, MODEL)

    with Session(db) as closing:
        lock_engagement(closing, eng_id)  # a close is in progress and holds the lock
        thread = threading.Thread(target=put)
        thread.start()
        thread.join(timeout=1.0)
        assert thread.is_alive(), "the upload must wait for the close, not run beside it"
        engagement = closing.get(m.Engagement, eng_id)
        engagement.state = "closed"
        engagement.closed_at = dt.datetime.now(dt.UTC)
        closing.commit()  # releases the lock
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert result["response"].status_code == 409
    assert _rows(db, model) == []
    assert _audit(db, eng_id, "target.artefact_stored") == []
