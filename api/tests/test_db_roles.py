"""The runtime login is restricted to row access (code review, 2026-10-02).

Connects as the provisioned runtime login and proves it cannot rewrite or truncate the append-only
tables, nor disable their triggers — the guarantees an owner login could bypass.
"""

from __future__ import annotations

import os
from urllib.parse import quote, urlsplit, urlunsplit

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

RUNTIME_USER = "khandaq_rt_test"
RUNTIME_PASSWORD = "p'a:s%s w0rd"  # quote, colon, percent and space: quoting must be server-side


def _with_login(url: str, user: str, password: str) -> str:
    parts = urlsplit(url)
    netloc = f"{quote(user)}:{quote(password, safe='')}@{parts.hostname}"
    if parts.port:
        netloc += f":{parts.port}"
    return urlunsplit(parts._replace(netloc=netloc))


@pytest.fixture(scope="module")
def runtime_engine():
    from khandaq import migrate

    owner = create_engine(TEST_URL, future=True)
    with owner.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    runtime_url = _with_login(TEST_URL, RUNTIME_USER, RUNTIME_PASSWORD)
    migrate.upgrade(url=TEST_URL, runtime_url=runtime_url)
    migrate.upgrade(url=TEST_URL, runtime_url=runtime_url)  # idempotent on every boot

    with owner.begin() as conn:  # a row for the runtime login to try to tamper with
        conn.execute(text("INSERT INTO users (id, email) VALUES ('usr_rt', 'rt@test')"))
        conn.execute(
            text(
                "INSERT INTO engagements (id, name, owner_user_id) VALUES ('eng_rt', 'x', 'usr_rt')"
            )
        )
        conn.execute(text("INSERT INTO audit_log (id, action) VALUES ('aud_rt', 'seed')"))

    runtime = create_engine(runtime_url, future=True)
    yield runtime
    runtime.dispose()
    with owner.begin() as conn:
        conn.execute(text(f"DROP OWNED BY {RUNTIME_USER}"))
        conn.execute(text(f"DROP ROLE {RUNTIME_USER}"))
    owner.dispose()


def _denied(engine, sql: str) -> str:
    with pytest.raises(ProgrammingError) as exc:
        with engine.begin() as conn:
            conn.execute(text(sql))
    return str(exc.value.orig).lower()


def test_runtime_login_can_work_with_rows(runtime_engine):
    with runtime_engine.begin() as conn:
        conn.execute(text("INSERT INTO audit_log (id, action) VALUES ('aud_rt2', 'ok')"))
        conn.execute(text("UPDATE engagements SET name = 'renamed' WHERE id = 'eng_rt'"))
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar() >= 2
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_log SET action = 'forged' WHERE id = 'aud_rt'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
        "DELETE FROM evidence",
        "UPDATE ledger_entries SET entry_hash = 'x'",
        "TRUNCATE ledger_entries",
        "UPDATE alembic_version SET version_num = 'x'",
    ],
)
def test_runtime_login_cannot_rewrite_append_only_tables(runtime_engine, sql):
    assert "permission denied" in _denied(runtime_engine, sql)


def test_runtime_login_cannot_disable_the_audit_trigger(runtime_engine):
    message = _denied(runtime_engine, "ALTER TABLE audit_log DISABLE TRIGGER ALL")
    assert "must be owner" in message


def test_runtime_login_cannot_change_the_schema(runtime_engine):
    assert "permission denied" in _denied(runtime_engine, "CREATE TABLE sneaky (x int)")
