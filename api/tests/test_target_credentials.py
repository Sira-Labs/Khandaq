"""Per-run target credentials (spec 028, ADR-0019).

Unit tests for the value rules, the transport rule, the envelope binding and the redaction; then
API and worker tests against Postgres: owner-only write-only storage, audit, injection of the run's
own target's credential, and a sweep proving the key ends up in no record. Every key here is
synthetic.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import logging
import os
import re
import tarfile
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from khandaq import credential_values, scope, target_credentials
from khandaq.adapters.docker import CliResult, DockerRunner
from khandaq.credential_values import REDACTION, CredentialError, redact, redact_bytes
from khandaq.evidence_crypto import EvidenceDecryptError, Keyring

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
KEY_A = "synthetic-key-for-target-A-0123456789"
KEY_B = "synthetic/key+for=target:B-0123456789"  # every character a percent-encoder rewrites
CREDENTIAL_KEY = "synthetic-credential-envelope-key-0123456789"
EVIDENCE_KEY = "synthetic-test-evidence-key-0123456789"
SPEC_A = {"base_url": "https://gw.acme.test/v1/chat/completions", "model": "assistant-v3"}
SPEC_B = {"base_url": "https://gw.acme.test/v1/chat/completions", "model": "assistant-v4"}
SCOPE = {
    "allow": {
        "llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3", "assistant-v4"]}]
    },
    "deny": [],
    "roe": {},
}


# --- unit: value rules, transport rule, envelope binding, redaction -------------------------------


def test_a_stored_credential_round_trips_and_is_bound_to_its_target_and_version():
    ring = Keyring.from_secrets(CREDENTIAL_KEY)
    key = target_credentials._object_key("eng_1", "tgt_1", 1)
    blob = ring.encrypt(key, KEY_A.encode())
    assert KEY_A.encode() not in blob
    assert ring.decrypt(key, blob) == KEY_A.encode()
    with pytest.raises(EvidenceDecryptError):
        ring.decrypt(target_credentials._object_key("eng_1", "tgt_1", 2), blob)


def test_a_blob_moved_to_another_target_does_not_decrypt():
    ring = Keyring.from_secrets(CREDENTIAL_KEY)
    blob = ring.encrypt(target_credentials._object_key("eng_1", "tgt_1", 1), KEY_A.encode())
    for moved in (("eng_1", "tgt_2", 1), ("eng_2", "tgt_1", 1)):
        with pytest.raises(EvidenceDecryptError):
            ring.decrypt(target_credentials._object_key(*moved), blob)
    with pytest.raises(EvidenceDecryptError):  # and the evidence key never opens a credential
        Keyring.from_secrets(EVIDENCE_KEY).decrypt(
            target_credentials._object_key("eng_1", "tgt_1", 1), blob
        )


@pytest.mark.parametrize(
    "value",
    [
        "short7!",
        "a" * 7,
        "a" * 1025,
        "has a space in it",
        "line\nbreak-in-the-key",
        'quote"in-the-key',
        "dollar$in-the-key",
        "ünïcödé-in-the-key",
        None,
        12345678,
        ["synthetic-list-value"],
    ],
)
def test_value_rules_reject_bad_length_and_characters_without_echoing_the_value(value):
    with pytest.raises(CredentialError) as exc:
        credential_values.validate_value(value)
    assert exc.value.status == 422
    assert exc.value.detail == credential_values.VALUE_RULE
    if isinstance(value, str):
        assert value not in str(exc.value)


def test_value_rules_accept_bearer_keys_jwts_and_base64():
    for value in ("a" * 8, "a" * 1024, KEY_A, KEY_B, "eyJhbGciOi.eyJzdWIi.c2ln-_~", "QUJD+/8="):
        assert credential_values.validate_value(value) == value


@pytest.mark.parametrize(
    "spec, refused",
    [
        ({"base_url": "https://api.acme.test/v1", "model": "m"}, False),
        ({"base_url": "http://api.acme.test/v1", "model": "m"}, True),
        ({"base_url": "http://srv-captain--ollama:11434/v1", "model": "m"}, False),
        ({"base_url": "http://ollama/v1", "model": "m"}, False),
        ({"base_url": "http://10.0.0.5/v1", "model": "m"}, True),
        # One encrypted URL does not excuse a plain one on the same target.
        (
            {"base_url": "https://api.acme.test:8443/v1", "url": "http://api.acme.test:8443/v1"},
            True,
        ),
        ({"host": "api.acme.test", "model": "m"}, True),  # no URL: nothing a run could reach
    ],
)
def test_plain_http_to_a_dotted_host_is_refused_and_an_internal_name_is_allowed(spec, refused):
    problem = target_credentials.transport_problem("llm_endpoint", spec)
    assert (problem is not None) is refused


def test_the_transport_rule_reads_the_same_url_fields_as_the_scope_lock():
    assert target_credentials.URL_FIELDS == scope._URL_FIELDS
    assert target_credentials.transport_problem("mcp_server", {"url": "http://mcp.acme.test/x"})
    assert not target_credentials.transport_problem(
        "mcp_server", {"url": "https://mcp.acme.test/x"}
    )
    assert target_credentials.transport_problem("dataset", {"digest": "sha256:00"})


def test_redaction_removes_raw_and_percent_encoded_forms():
    upper = quote(KEY_B, safe="")
    forms = [
        KEY_B,
        upper,
        re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), upper),  # lower-case hex
        quote(KEY_B, safe="/:"),  # a partial encoder
        KEY_B.replace("/", "\\/"),  # a JSON serialiser that escapes the solidus
    ]
    for form in forms:
        text_ = f"Authorization: Bearer {form}; next"
        assert redact(text_, KEY_B) == f"Authorization: Bearer {REDACTION}; next", form
        assert redact_bytes(text_.encode(), KEY_B) == redact(text_, KEY_B).encode()
    twice = f"{KEY_A} and again {KEY_A}"
    assert redact(twice, KEY_A) == f"{REDACTION} and again {REDACTION}"
    assert redact("nothing here", KEY_A) == "nothing here"
    assert redact(f"keep {KEY_A}", None) == f"keep {KEY_A}"
    assert redact_bytes(b"\x00\xff" + KEY_A.encode() + b"\xfe", KEY_A) == (
        b"\x00\xff" + REDACTION.encode() + b"\xfe"
    )


def test_redaction_treats_the_key_as_text_not_as_a_pattern():
    key = "a.b+c.d+e.f+g"  # regex metacharacters must match themselves only
    assert redact("aXb+c.d+e.f+g", key) == "aXb+c.d+e.f+g"
    assert redact(f"<{key}>", key) == f"<{REDACTION}>"


# --- integration ---------------------------------


class RecordingRunner:
    """Stands in for DockerRunner: records what each run was handed."""

    def __init__(self) -> None:
        self.calls: list[tuple[dict, str | None]] = []

    def run(self, request: dict, credential: str | None = None) -> dict:
        self.calls.append((request, credential))
        content = b'{"entry_type":"eval"}\n'
        return {
            "evidence": [
                {
                    "local_id": "garak-report.jsonl",
                    "kind": "report",
                    "object_key": "{engagement_id}/{run_id}/garak-report.jsonl".format(**request),
                    "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                    "bytes": len(content),
                    "redacted": False,
                    "content": content,
                }
            ],
            "findings": [],
        }


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
    names = ("evidence_dir", "evidence_key", "object_store_url", "credential_key")
    previous = {name: getattr(settings, name) for name in names}
    settings.evidence_dir = str(tmp_path_factory.mktemp("evidence"))
    settings.evidence_key = EVIDENCE_KEY
    settings.object_store_url = ""
    settings.credential_key = CREDENTIAL_KEY
    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app), eng, settings
    for name, value in previous.items():
        setattr(settings, name, value)
    eng.dispose()


def _engagement(client, name: str, activate: bool = True) -> tuple[str, str, str]:
    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    targets = []
    for spec in (SPEC_A, SPEC_B):
        r = client.post(
            f"/api/engagements/{eng_id}/targets",
            json={"type": "llm_endpoint", "spec": spec},
            headers=OWNER,
        )
        assert r.status_code == 201, r.text
        targets.append(r.json()["id"])
    client.put(f"/api/engagements/{eng_id}/scope", json=SCOPE, headers=OWNER)
    if activate:
        r = client.post(
            f"/api/engagements/{eng_id}/activate",
            json={"authorisation_ref": "SOW-1"},
            headers=OWNER,
        )
        assert r.status_code == 200, r.text
    return eng_id, targets[0], targets[1]


def _put(client, eng_id: str, tid: str, value, headers=OWNER):
    return client.put(
        f"/api/engagements/{eng_id}/targets/{tid}/credential",
        json={"value": value},
        headers=headers,
    )


def _delete(client, eng_id: str, tid: str, headers=OWNER):
    return client.delete(f"/api/engagements/{eng_id}/targets/{tid}/credential", headers=headers)


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


def _stored(db, tid: str) -> list:
    with db.connect() as conn:
        return list(
            conn.execute(
                text("SELECT version, ciphertext FROM target_credentials WHERE target_id = :t"),
                {"t": tid},
            )
        )


def _queue(client, eng_id: str, tid: str, adapter: str = "garak") -> dict:
    r = client.post(
        f"/api/engagements/{eng_id}/runs",
        json={"adapter": adapter, "target_id": tid},
        headers=OWNER,
    )
    assert r.status_code == 201, r.text
    return r.json()


def _run(client, eng_id: str, run_id: str) -> dict:
    return client.get(f"/api/engagements/{eng_id}/runs/{run_id}", headers=OWNER).json()


def _started(db, eng_id: str, run_id: str) -> dict:
    [entry] = [d for d in _audit(db, eng_id, "run.started") if d["run_id"] == run_id]
    return entry


def test_only_the_owner_can_set_replace_or_clear_a_credential(env):
    client, db, _ = env
    eng_id, tid, _ = _engagement(client, "authz")
    other_eng, other_tid, _ = _engagement(client, "authz-other")
    assert _put(client, eng_id, tid, KEY_A).status_code == 200

    outsiders = [
        _member(db, eng_id, f"{role}@authz.test", role) for role in ("operator", "analyst")
    ]
    outsiders.append(_member(db, eng_id, "viewer@authz.test", "viewer"))
    outsiders.append(_member(db, other_eng, "owner@other.test", "owner"))  # owner elsewhere only
    for headers in outsiders:
        assert _put(client, eng_id, tid, KEY_B, headers).status_code in (403, 404)
        assert _delete(client, eng_id, tid, headers).status_code in (403, 404)
    [(version, _)] = _stored(db, tid)
    assert version == 1  # nobody else changed or removed it

    # A target of another engagement is not found through this one.
    assert _put(client, eng_id, other_tid, KEY_A).status_code == 404
    assert _delete(client, eng_id, other_tid).status_code == 404
    assert _stored(db, other_tid) == []

    replaced = _put(client, eng_id, tid, KEY_B)
    assert replaced.status_code == 200 and replaced.json()["version"] == 2
    assert _delete(client, eng_id, tid).status_code == 204
    assert _delete(client, eng_id, tid).status_code == 404
    assert _stored(db, tid) == []


def test_set_and_clear_are_audited_in_the_same_transaction_without_the_value(env, monkeypatch):
    client, db, _ = env
    eng_id, tid, tid_b = _engagement(client, "audited")

    r = _put(client, eng_id, tid, KEY_A)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["has_credential"] is True and body["version"] == 1 and body["updated_at"]
    assert KEY_A not in r.text
    assert _put(client, eng_id, tid, KEY_B).json()["version"] == 2
    assert _delete(client, eng_id, tid).status_code == 204

    assert _audit(db, eng_id, "target.credential_set") == [
        {"target_id": tid, "version": 1, "rotated": False},
        {"target_id": tid, "version": 2, "rotated": True},
    ]
    assert _audit(db, eng_id, "target.credential_cleared") == [
        {"target_id": tid, "reason": "removed by the owner"}
    ]

    # The envelope, not the key, is what was stored.
    _put(client, eng_id, tid, KEY_A)
    [(_, blob)] = _stored(db, tid)
    assert bytes(blob).startswith(b"KHQE") and KEY_A.encode() not in bytes(blob)

    # No audit entry, no credential: a failing audit write rolls the change back.
    def broken(*_args, **_kwargs):
        raise RuntimeError("audit log unavailable")

    monkeypatch.setattr(target_credentials.audit, "record", broken)
    with pytest.raises(RuntimeError):
        _put(client, eng_id, tid_b, KEY_B)
    assert _stored(db, tid_b) == []
    with pytest.raises(RuntimeError):
        _delete(client, eng_id, tid)
    assert len(_stored(db, tid)) == 1


def test_target_reads_show_the_flag_and_never_the_value(env):
    client, db, _ = env
    eng_id, tid, tid_b = _engagement(client, "reads")
    _put(client, eng_id, tid, KEY_A)
    viewer = _member(db, eng_id, "viewer@reads.test", "viewer")

    for headers in (OWNER, viewer):
        r = client.get(f"/api/engagements/{eng_id}/targets", headers=headers)
        assert r.status_code == 200
        by_id = {t["id"]: t for t in r.json()}
        assert by_id[tid]["has_credential"] is True and by_id[tid]["credential_updated_at"]
        assert by_id[tid_b]["has_credential"] is False
        assert by_id[tid_b]["credential_updated_at"] is None
        assert "credential_ref" not in by_id[tid] and KEY_A not in r.text
    # There is no route that reads a credential back.
    assert (
        client.get(f"/api/engagements/{eng_id}/targets/{tid}/credential", headers=OWNER).status_code
        == 405
    )


def test_credential_ref_in_a_target_create_is_refused(env):
    client, _, _ = env
    eng_id = client.post("/api/engagements", json={"name": "ref"}, headers=OWNER).json()["id"]
    for ref in (KEY_A, None):
        r = client.post(
            f"/api/engagements/{eng_id}/targets",
            json={"type": "llm_endpoint", "spec": SPEC_A, "credential_ref": ref},
            headers=OWNER,
        )
        assert r.status_code == 422
        assert "credential route" in r.text and KEY_A not in r.text
    assert client.get(f"/api/engagements/{eng_id}/targets", headers=OWNER).json() == []


def test_bad_values_and_plain_http_targets_are_refused_without_an_echo(env):
    client, db, _ = env
    eng_id, tid, _ = _engagement(client, "refused")
    bad = "not a valid key because of spaces"
    for body in ({"value": bad}, {"value": 12345678}, {"wrong": bad}, bad, [bad], None):
        r = client.put(
            f"/api/engagements/{eng_id}/targets/{tid}/credential", json=body, headers=OWNER
        )
        assert r.status_code == 422, r.text
        assert bad not in r.text
    assert _stored(db, tid) == []

    plain = client.post("/api/engagements", json={"name": "plain"}, headers=OWNER).json()["id"]
    plain_tid = client.post(
        f"/api/engagements/{plain}/targets",
        json={"type": "llm_endpoint", "spec": {**SPEC_A, "base_url": "http://gw.acme.test/v1"}},
        headers=OWNER,
    ).json()["id"]
    r = _put(client, plain, plain_tid, KEY_A)
    assert r.status_code == 422 and "https" in r.text and KEY_A not in r.text


def test_a_closed_engagement_refuses_changes_and_closing_deletes_credentials(env):
    client, db, _ = env
    eng_id, tid, tid_b = _engagement(client, "closing")
    _put(client, eng_id, tid, KEY_A)
    _put(client, eng_id, tid_b, KEY_B)
    untouched_eng, untouched_tid, _ = _engagement(client, "stays-open")
    _put(client, untouched_eng, untouched_tid, KEY_A)

    assert client.post(f"/api/engagements/{eng_id}/close", headers=OWNER).status_code == 200

    assert _stored(db, tid) == [] and _stored(db, tid_b) == []
    cleared = _audit(db, eng_id, "target.credential_cleared")
    assert sorted(c["target_id"] for c in cleared) == sorted([tid, tid_b])
    assert {c["reason"] for c in cleared} == {"engagement closed"}
    assert len(_stored(db, untouched_tid)) == 1  # only the closed engagement's
    assert _put(client, eng_id, tid, KEY_A).status_code == 409
    assert _delete(client, eng_id, tid).status_code == 404
    assert _stored(db, tid) == []


def test_a_draft_engagement_can_hold_a_credential(env):
    client, db, _ = env
    eng_id, tid, _ = _engagement(client, "draft", activate=False)
    assert _put(client, eng_id, tid, KEY_A).status_code == 200
    assert len(_stored(db, tid)) == 1


def test_the_feature_is_a_503_when_the_key_is_unset_and_runs_are_unchanged(env, monkeypatch):
    client, db, settings = env
    eng_id, tid, _ = _engagement(client, "off")
    monkeypatch.setattr(settings, "credential_key", "")

    r = _put(client, eng_id, tid, KEY_A)
    assert r.status_code == 503 and "not enabled" in r.text and KEY_A not in r.text
    assert _stored(db, tid) == []

    from khandaq import worker

    run = _queue(client, eng_id, tid)
    runner = RecordingRunner()
    worker.drain(db, runner=runner)
    assert _run(client, eng_id, run["id"])["state"] == "succeeded"
    assert _started(db, eng_id, run["id"])["credential"] == "none"
    assert [c for r_, c in runner.calls if r_["run_id"] == run["id"]] == [None]

    monkeypatch.setattr(settings, "credential_key", "too-short")
    assert _put(client, eng_id, tid, KEY_A).status_code == 503


def test_the_worker_injects_the_credential_of_the_runs_own_target_only(env):
    from khandaq import worker

    client, db, _ = env
    eng_id, tid_a, tid_b = _engagement(client, "own-target")
    _put(client, eng_id, tid_a, KEY_A)
    _put(client, eng_id, tid_b, KEY_B)
    run_b = _queue(client, eng_id, tid_b)
    run_a = _queue(client, eng_id, tid_a)
    runner = RecordingRunner()

    worker.drain(db, runner=runner)

    handed = {r["run_id"]: (r, c) for r, c in runner.calls}
    assert handed[run_b["id"]][1] == KEY_B
    assert handed[run_a["id"]][1] == KEY_A
    for request, credential in handed.values():
        # The request, which a runner or an adapter may log, never carries the key.
        assert credential not in json.dumps(request)
    assert _run(client, eng_id, run_a["id"])["state"] == "succeeded"


def test_run_started_records_injected_none_or_not_accepted(env):
    from khandaq import worker

    client, db, _ = env
    eng_id, keyed, unkeyed = _engagement(client, "recorded")
    _put(client, eng_id, keyed, KEY_A)
    runner = RecordingRunner()

    injected = _queue(client, eng_id, keyed)
    none = _queue(client, eng_id, unkeyed)
    worker.drain(db, runner=runner)
    # The built-in echo adapter declares no accepts_credential: it runs, without the key.
    not_accepted = _queue(client, eng_id, keyed, adapter="echo")

    assert _started(db, eng_id, injected["id"])["credential"] == "injected"
    assert _started(db, eng_id, none["id"])["credential"] == "none"
    assert _started(db, eng_id, not_accepted["id"])["credential"] == "not_accepted"
    assert not_accepted["state"] == "succeeded"
    handed = {r["run_id"]: c for r, c in runner.calls}
    assert handed[injected["id"]] == KEY_A and handed[none["id"]] is None


def test_an_undecryptable_credential_fails_the_run_and_never_falls_back_to_the_placeholder(
    env, monkeypatch
):
    from khandaq import worker

    client, db, settings = env
    eng_id, tid, _ = _engagement(client, "undecryptable")
    _put(client, eng_id, tid, KEY_A)
    run = _queue(client, eng_id, tid)
    # The key the credential was stored under is gone (rotated without the previous-keys list).
    monkeypatch.setattr(settings, "credential_key", "another-synthetic-envelope-key-0123456789")
    runner = RecordingRunner()

    worker.drain(db, runner=runner)

    failed = _run(client, eng_id, run["id"])
    assert failed["state"] == "failed"
    assert "cannot be decrypted" in failed["reject_reason"] and KEY_A not in failed["reject_reason"]
    assert [c for c in runner.calls if c[0]["run_id"] == run["id"]] == []  # nothing was launched

    # With the retired key listed, the same stored credential works again.
    monkeypatch.setattr(settings, "credential_previous_keys", CREDENTIAL_KEY)
    again = _queue(client, eng_id, tid)
    worker.drain(db, runner=runner)
    assert _run(client, eng_id, again["id"])["state"] == "succeeded"
    assert [c for r, c in runner.calls if r["run_id"] == again["id"]] == [KEY_A]


def test_a_credential_removed_after_the_run_started_fails_the_run(env):
    from khandaq.runs import claim_next_run, execute_run

    client, db, _ = env
    eng_id, tid, _ = _engagement(client, "removed")
    _put(client, eng_id, tid, KEY_A)
    run = _queue(client, eng_id, tid)
    runner = RecordingRunner()
    with Session(db) as session:
        assert claim_next_run(session) == run["id"]  # run.started recorded `injected`
        assert _delete(client, eng_id, tid).status_code == 204
        execute_run(session, run["id"], runner=runner)

    failed = _run(client, eng_id, run["id"])
    assert failed["state"] == "failed" and "removed" in failed["reject_reason"]
    assert runner.calls == []  # the audit said `injected`: it does not run without the key


def test_a_campaign_run_uses_the_credential(env):
    from khandaq import worker
    from khandaq.campaigns import schedule_due

    client, db, _ = env
    eng_id, tid, _ = _engagement(client, "campaign")
    _put(client, eng_id, tid, KEY_A)
    created = client.post(
        f"/api/engagements/{eng_id}/campaigns",
        json={"name": "weekly", "adapter": "garak", "target_id": tid, "interval_minutes": 60},
        headers=OWNER,
    )
    assert created.status_code == 201, created.text
    with db.begin() as conn:
        conn.execute(
            text("UPDATE campaigns SET next_run_at = now() - interval '1 minute' WHERE id = :c"),
            {"c": created.json()["id"]},
        )
    with Session(db) as session:
        assert schedule_due(session) >= 1
    runner = RecordingRunner()
    worker.drain(db, runner=runner)

    assert [c for r, c in runner.calls if r["engagement_id"] == eng_id] == [KEY_A]
    [started] = _audit(db, eng_id, "run.started")
    assert started["credential"] == "injected"


def test_the_deployment_summary_reports_enabled_without_the_key(env, monkeypatch):
    from khandaq.deployment import settings_summary

    _, _, settings = env
    summary = settings_summary(settings)
    assert summary["credentials_enabled"] is True
    assert CREDENTIAL_KEY not in json.dumps(summary)
    monkeypatch.setattr(settings, "credential_key", "")
    assert settings_summary(settings)["credentials_enabled"] is False


# --- security: the key ends up in no record ---------------------------------


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class EchoingCli:
    """A Docker CLI whose adapter saw a target that echoes its caller's key back: in a finding
    title, in the report, percent-encoded in the hit log, and on stderr."""

    def __init__(self, key: str, fail: bool = False) -> None:
        self.key, self.fail = key, fail
        self.calls: list[list[str]] = []
        self.env_file = ""

    def __call__(self, args, *, timeout=None, stdout_limit=None):
        self.calls.append(list(args))
        if "--env-file" in args:
            self.env_file = open(args[args.index("--env-file") + 1]).read()
        if args[0] == "info":
            return CliResult(0, b"SYNTHETIC-DAEMON-ID\n", b"")
        if args[0] != "start":
            return CliResult(0, b"", b"")
        stderr = f"401 from target; request carried Authorization: Bearer {self.key}".encode()
        if self.fail:
            return CliResult(2, b"", stderr)
        finding = {
            "schema": "khandaq.finding/2",
            "rule_id": "garak.leakreplay.echo",
            "title": f"garak: the target replayed its caller's key {self.key}",
            "severity": "high",
            "source": {"tool": "garak", "version": "0.17.0"},
            "locations": [{"logicalLocations": [{"fullyQualifiedName": "leakreplay"}]}],
            "x-khandaq": {"phase": "03-scanning", "mappings": []},
            "_evidence_local": ["garak-report.jsonl"],
        }
        files = {
            "findings.jsonl": (json.dumps(finding) + "\n").encode(),
            "garak-report.jsonl": f'{{"output":"your key is {self.key}"}}\n'.encode(),
            "garak-hitlog.jsonl": f'{{"url":"?k={quote(self.key, safe="")}"}}\n'.encode(),
            "clean.log": b"nothing sensitive\n",
        }
        return CliResult(0, _tar(files), stderr)


def _docker_runner(settings, cli) -> DockerRunner:
    from khandaq.adapters import get_manifest

    settings.forwarder_image = "ghcr.io/sira-labs/khandaq-api:test"
    manifest = get_manifest("garak")
    assert manifest is not None
    return DockerRunner(manifest, settings, cli=cli, resolver=lambda host, port: ["203.0.113.7"])


def test_a_secret_sweep_finds_the_key_in_no_record_after_a_full_keyed_run(env, caplog, monkeypatch):
    from khandaq import worker

    client, db, settings = env
    monkeypatch.setattr(settings, "forwarder_image", "")
    eng_id, tid_a, tid_b = _engagement(client, "sweep")
    _put(client, eng_id, tid_a, KEY_A)
    _put(client, eng_id, tid_b, KEY_B)  # another target's key must never show up either
    caplog.set_level(logging.DEBUG)

    ok = _queue(client, eng_id, tid_b)
    cli = EchoingCli(KEY_B)
    worker.drain(db, runner=_docker_runner(settings, cli))
    failing = _queue(client, eng_id, tid_b)
    worker.drain(db, runner=_docker_runner(settings, EchoingCli(KEY_B, fail=True)))

    # The key reached the adapter through the env file only.
    assert f"KHANDAQ_TARGET_CREDENTIAL={KEY_B}\n" in cli.env_file
    request_line = cli.env_file.splitlines()[0]
    assert request_line.startswith("KHANDAQ_RUN_REQUEST=") and KEY_B not in request_line
    assert all(KEY_B not in arg and KEY_A not in arg for call in cli.calls for arg in call)
    # The run's Docker daemon is on record before the first of its objects is created.
    assert cli.calls[0][0] == "info"
    with db.connect() as conn:
        daemons = conn.execute(text("SELECT DISTINCT docker_daemon FROM runs")).scalars().all()
    assert "SYNTHETIC-DAEMON-ID" in daemons

    assert _run(client, eng_id, ok["id"])["state"] == "succeeded"
    failed = _run(client, eng_id, failing["id"])
    assert failed["state"] == "failed" and REDACTION in failed["reject_reason"]

    # Evidence: the redacted bytes are what was stored, marked and sealed.
    with db.connect() as conn:
        evidence = list(
            conn.execute(
                text("SELECT id, object_key, sha256, redacted FROM evidence WHERE run_id = :r"),
                {"r": ok["id"]},
            )
        )
    assert {e.object_key.rsplit("/", 1)[1]: e.redacted for e in evidence} == {
        "garak-report.jsonl": True,
        "garak-hitlog.jsonl": True,
        "clean.log": False,
    }
    downloads = []
    for e in evidence:
        r = client.get(f"/api/engagements/{eng_id}/evidence/{e.id}/content", headers=OWNER)
        assert r.status_code == 200, r.text  # the sealed hash matches the stored (redacted) bytes
        assert e.sha256 == "sha256:" + hashlib.sha256(r.content).hexdigest()
        downloads.append(r.content)
    assert any(REDACTION.encode() in content for content in downloads)
    ledger = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()
    assert ledger["verify"]["ok"] is True

    # The finding survives; the key does not.
    inbox = client.get(f"/api/engagements/{eng_id}/findings", headers=OWNER)
    assert REDACTION in inbox.text

    haystack = [inbox.text, caplog.text, *[c.decode("utf-8", "replace") for c in downloads]]
    for path in ("report", "report.html", "audit", "runs", "targets", "ledger"):
        r = client.get(f"/api/engagements/{eng_id}/{path}", headers=OWNER)
        assert r.status_code == 200, (path, r.text)
        haystack.append(r.text)
    with db.connect() as conn:
        for table in ("audit_log", "runs", "findings", "evidence", "ledger_entries", "targets"):
            rows = conn.execute(text(f"SELECT row_to_json(t)::text FROM {table} t")).scalars()
            haystack.extend(rows)
        blobs = conn.execute(text("SELECT ciphertext FROM target_credentials")).scalars()
        haystack.extend(bytes(b).decode("latin-1") for b in blobs)
    for root, _dirs, names in os.walk(settings.evidence_dir):
        for name in names:
            with open(os.path.join(root, name), "rb") as f:
                haystack.append(f.read().decode("latin-1"))
    encoded = quote(KEY_B, safe="")
    for text_ in haystack:
        assert KEY_A not in text_ and KEY_B not in text_ and encoded not in text_


def test_updated_at_moves_when_a_credential_is_replaced(env):
    client, _, _ = env
    eng_id, tid, _ = _engagement(client, "rotation")
    first = dt.datetime.fromisoformat(_put(client, eng_id, tid, KEY_A).json()["updated_at"])
    second = dt.datetime.fromisoformat(_put(client, eng_id, tid, KEY_B).json()["updated_at"])
    assert second >= first
    [target] = [
        t
        for t in client.get(f"/api/engagements/{eng_id}/targets", headers=OWNER).json()
        if t["id"] == tid
    ]
    assert dt.datetime.fromisoformat(target["credential_updated_at"]) == second


def test_a_long_failure_keeps_its_last_lines_where_the_cause_is():
    from khandaq.runs import _brief

    stderr = "garak adapter: running garak\n" + "progress line\n" * 200 + "HTTP 401 from the target"
    brief = _brief(f"adapter failed: adapter exited with 2: {stderr}")
    assert len(brief) == 500
    assert brief.startswith("adapter failed: adapter exited with 2: garak adapter")
    assert brief.endswith("HTTP 401 from the target")
    assert _brief("short") == "short"


# --- review follow-ups (independent review of PR #76) ---------------------------------------------


def test_redaction_covers_percent_encoded_unreserved_characters_and_json_unicode_escapes():
    key = "ab+cd/ef=gh:ij~kl.mn_op-qr"
    forms = [
        "ab%2Bcd%2Fef%3Dgh%3Aij%7Ekl%2Emn%5Fop%2Dqr",  # an encoder that leaves nothing alone
        "ab%2bcd%2fef%3dgh%3aij%7ekl.mn_op-qr",
        "ab\\u002bcd\\u002fef\\u003dgh\\u003aij\\u007ekl.mn_op-qr",  # JSON escapes, lower case
        "ab\\u002Bcd\\/ef\\u003Dgh:ij~kl.mn_op-qr",  # mixed
        "%61b+cd/ef=gh:ij~kl.mn_op-qr",  # even a letter may arrive encoded
    ]
    for form in forms:
        assert redact(f"<{form}>", key) == f"<{REDACTION}>", form
        assert redact_bytes(f"<{form}>".encode(), key) == f"<{REDACTION}>".encode(), form
    assert redact("ab+cd/ef=gh:ij~kl.mn_op-qX", key) == "ab+cd/ef=gh:ij~kl.mn_op-qX"


def test_redaction_of_a_long_repetitive_key_stays_fast():
    import time

    key = "+/" * 512  # the worst case the value rule allows
    haystack = ("+/" * 400 + "x") * 200
    started = time.perf_counter()
    assert redact(haystack, key) == haystack
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize(
    "url",
    [
        "http://134744072/v1/chat/completions",  # 8.8.8.8 written as one number
        "http://0x8080808/v1/chat/completions",
        "https://203.0.113.7/v1/chat/completions",  # an address even over TLS: never run anyway
        "https://[2001:db8::1]/v1/chat/completions",
        "http://127.1/v1/chat/completions",
    ],
)
def test_a_credential_needs_a_host_name_not_an_address(url):
    problem = target_credentials.transport_problem("llm_endpoint", {"url": url, "model": "m"})
    assert problem is not None and "host name" in problem


def test_an_invalid_target_create_never_echoes_what_was_sent(env):
    client, _, _ = env
    eng_id = client.post("/api/engagements", json={"name": "echo"}, headers=OWNER).json()["id"]
    bodies = [
        {"type": "llm_endpoint", "credential_ref": KEY_A},  # spec missing AND the old field
        {"type": "not-a-type", "spec": {"note": KEY_A}},
        {"type": "llm_endpoint", "spec": KEY_A},
        KEY_A,
        [KEY_A],
    ]
    for body in bodies:
        r = client.post(f"/api/engagements/{eng_id}/targets", json=body, headers=OWNER)
        assert r.status_code == 422, r.text
        assert KEY_A not in r.text
    assert client.get(f"/api/engagements/{eng_id}/targets", headers=OWNER).json() == []
    # A valid target is still created, and an invalid one still says which field is wrong.
    r = client.post(f"/api/engagements/{eng_id}/targets", json={"type": "nope"}, headers=OWNER)
    assert {tuple(e["loc"]) for e in r.json()["detail"]} == {("type",), ("spec",)}
    ok = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": SPEC_A},
        headers=OWNER,
    )
    assert ok.status_code == 201 and ok.json()["has_credential"] is False


def test_a_credential_cannot_slip_in_behind_a_concurrent_close(env):
    """The race the lock closes: a PUT that started while the engagement was active must not
    commit after the close deleted the credentials."""
    import threading

    from khandaq import models as m
    from khandaq.ledger import lock_engagement

    client, db, _ = env
    eng_id, tid, _ = _engagement(client, "race")
    result: dict = {}

    def put() -> None:
        result["response"] = _put(client, eng_id, tid, KEY_A)

    with Session(db) as closing:
        lock_engagement(closing, eng_id)  # a close is in progress and holds the lock
        thread = threading.Thread(target=put)
        thread.start()
        thread.join(timeout=1.0)
        assert thread.is_alive(), "the PUT must wait for the close, not run beside it"
        engagement = closing.get(m.Engagement, eng_id)
        engagement.state = "closed"
        engagement.closed_at = dt.datetime.now(dt.UTC)
        closing.commit()  # releases the lock
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert result["response"].status_code == 409
    assert _stored(db, tid) == []
    assert _audit(db, eng_id, "target.credential_set") == []


def test_two_first_puts_for_one_target_do_not_collide(env):
    from concurrent.futures import ThreadPoolExecutor

    client, db, _ = env
    eng_id, tid, _ = _engagement(client, "double")
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda key: _put(client, eng_id, tid, key), [KEY_A, KEY_B]))
    assert [r.status_code for r in responses] == [200, 200]
    assert sorted(r.json()["version"] for r in responses) == [1, 2]
    [(version, _)] = _stored(db, tid)
    assert version == 2
