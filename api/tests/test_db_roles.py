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


# --- review (CodeRabbit on #20): refuse unsafe runtime logins; no CREATE on public --------------


def _owner():
    return create_engine(TEST_URL, future=True)


def _provision(name: str, password: str = "pw-test"):
    from khandaq import db_roles

    owner = _owner()
    try:
        with owner.begin() as conn:
            return db_roles.ensure_runtime_role(conn, _with_login(TEST_URL, name, password))
    finally:
        owner.dispose()


def _drop(name: str) -> None:
    owner = _owner()
    with owner.begin() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :n"), {"n": name}
        ).first()
        if exists:
            conn.execute(text(f"DROP OWNED BY {name}"))
            conn.execute(text(f"DROP ROLE {name}"))
    owner.dispose()


def test_a_runtime_login_that_can_become_the_owner_is_refused(runtime_engine):
    owner = _owner()
    with owner.begin() as conn:
        me = conn.execute(text("SELECT current_user")).scalar_one()
        conn.execute(text("CREATE ROLE khandaq_rt_member LOGIN PASSWORD 'x'"))
        conn.execute(text(f'GRANT "{me}" TO khandaq_rt_member'))
    owner.dispose()
    try:
        with pytest.raises(RuntimeError, match="migration owner"):
            _provision("khandaq_rt_member")
    finally:
        _drop("khandaq_rt_member")


def test_a_superuser_runtime_login_is_refused(runtime_engine):
    owner = _owner()
    with owner.begin() as conn:
        conn.execute(text("CREATE ROLE khandaq_rt_super LOGIN SUPERUSER PASSWORD 'x'"))
    owner.dispose()
    try:
        with pytest.raises(RuntimeError, match="SUPERUSER"):
            _provision("khandaq_rt_super")
    finally:
        _drop("khandaq_rt_super")


def test_public_create_inherited_from_old_acls_is_removed(runtime_engine):
    owner = _owner()
    with owner.begin() as conn:  # what a database created before PostgreSQL 15 still has
        conn.execute(text("GRANT CREATE ON SCHEMA public TO PUBLIC"))
    try:
        _provision("khandaq_rt_pub")
        with owner.connect() as conn:
            can_create = conn.execute(
                text("SELECT has_schema_privilege('khandaq_rt_pub', 'public', 'CREATE')")
            ).scalar_one()
        assert can_create is False
    finally:
        owner.dispose()
        _drop("khandaq_rt_pub")


def test_a_missing_role_without_createrole_fails_with_guidance(runtime_engine, monkeypatch):
    from khandaq import db_roles

    monkeypatch.setattr(db_roles, "_can_manage_roles", lambda conn: False)
    with pytest.raises(RuntimeError, match="grant CREATEROLE"):
        _provision("khandaq_rt_nobody")


def test_provisioning_waits_until_the_tables_exist(runtime_engine, monkeypatch):
    from khandaq import db_roles

    monkeypatch.setattr(db_roles, "APPEND_ONLY_TABLES", ("audit_log", "not_migrated_yet"))
    assert _provision("khandaq_rt_early") is None
    with _owner().connect() as conn:
        assert (
            conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'khandaq_rt_early'")).first()
            is None
        )


# --- review round 3: an existing runtime login must be plain; nothing may create objects ---------


def _make_role(sql: str) -> None:
    owner = _owner()
    with owner.begin() as conn:
        conn.execute(text(sql))
    owner.dispose()


@pytest.mark.parametrize("attribute", ["CREATEROLE", "CREATEDB", "BYPASSRLS"])
def test_an_existing_login_with_elevated_attributes_is_refused(runtime_engine, attribute):
    _make_role(f"CREATE ROLE khandaq_rt_attr LOGIN {attribute} PASSWORD 'x'")
    try:
        with pytest.raises(RuntimeError, match=attribute):
            _provision("khandaq_rt_attr")
    finally:
        _drop("khandaq_rt_attr")


def test_an_existing_login_in_any_role_is_refused(runtime_engine):
    _make_role("CREATE ROLE khandaq_rt_group NOLOGIN")
    _make_role("CREATE ROLE khandaq_rt_grouped LOGIN PASSWORD 'x' IN ROLE khandaq_rt_group")
    try:
        with pytest.raises(RuntimeError, match="member of khandaq_rt_group"):
            _provision("khandaq_rt_grouped")
    finally:
        _drop("khandaq_rt_grouped")
        _drop("khandaq_rt_group")


def test_database_level_create_is_removed(runtime_engine):
    _make_role("CREATE ROLE khandaq_rt_db LOGIN PASSWORD 'x'")
    owner = _owner()
    with owner.begin() as conn:
        db = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(text(f'GRANT CREATE ON DATABASE "{db}" TO khandaq_rt_db'))
    try:
        _provision("khandaq_rt_db", password="x")
        with owner.connect() as conn:
            probe = "SELECT has_database_privilege('khandaq_rt_db', current_database(), 'CREATE')"
            assert conn.execute(text(probe)).scalar_one() is False
    finally:
        owner.dispose()
        _drop("khandaq_rt_db")


def test_an_unchangeable_wrong_password_fails_boot(runtime_engine, monkeypatch):
    import psycopg

    from khandaq import db_roles

    def denied(conn, name, password):
        raise psycopg.errors.InsufficientPrivilege("permission denied to alter role")

    monkeypatch.setattr(db_roles, "_sync_password", denied)
    _make_role("CREATE ROLE khandaq_rt_pw LOGIN PASSWORD 'right-one'")
    try:
        with pytest.raises(RuntimeError, match="password in KHANDAQ_DATABASE_URL does not work"):
            _provision("khandaq_rt_pw", password="wrong-one")
        assert _provision("khandaq_rt_pw", password="right-one") == "khandaq_rt_pw"
    finally:
        _drop("khandaq_rt_pw")
