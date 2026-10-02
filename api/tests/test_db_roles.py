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


def _can_log_in(name: str, password: str) -> bool:
    from khandaq import db_roles

    return db_roles._can_log_in(_with_login(TEST_URL, name, password))


def test_an_existing_logins_password_is_never_rewritten(runtime_engine):
    # A restart with a stale URL must not undo an administrator's password rotation.
    _make_role("CREATE ROLE khandaq_rt_pw LOGIN PASSWORD 'rotated'")
    try:
        with pytest.raises(RuntimeError, match="cannot log in"):
            _provision("khandaq_rt_pw", password="stale")
        assert _can_log_in("khandaq_rt_pw", "rotated")  # unchanged
        assert not _can_log_in("khandaq_rt_pw", "stale")
        assert _provision("khandaq_rt_pw", password="rotated") == "khandaq_rt_pw"
    finally:
        _drop("khandaq_rt_pw")


def test_a_disabled_login_is_not_re_enabled(runtime_engine):
    assert _provision("khandaq_rt_off", password="pw") == "khandaq_rt_off"
    _make_role("ALTER ROLE khandaq_rt_off NOLOGIN")  # an administrator revokes it
    try:
        with pytest.raises(RuntimeError, match="cannot log in"):
            _provision("khandaq_rt_off", password="pw")
        with _owner().connect() as conn:
            can_login = conn.execute(
                text("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'khandaq_rt_off'")
            ).scalar_one()
        assert can_login is False
    finally:
        _drop("khandaq_rt_off")


def test_temporary_tables_are_not_allowed(runtime_engine):
    # PostgreSQL grants TEMPORARY on every database to PUBLIC by default.
    owner = _owner()
    with owner.begin() as conn:
        db = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(text(f'GRANT TEMPORARY ON DATABASE "{db}" TO PUBLIC'))
    try:
        _provision("khandaq_rt_tmp")
        with owner.connect() as conn:
            probe = "SELECT has_database_privilege('khandaq_rt_tmp', current_database(), 'TEMP')"
            assert conn.execute(text(probe)).scalar_one() is False
    finally:
        owner.dispose()
        _drop("khandaq_rt_tmp")


@pytest.mark.parametrize("right", ["UPDATE", "DELETE", "TRUNCATE", "TRIGGER"])
def test_rights_inherited_through_public_on_append_only_tables_are_removed(runtime_engine, right):
    owner = _owner()
    with owner.begin() as conn:
        conn.execute(text(f"GRANT {right} ON TABLE audit_log TO PUBLIC"))
    try:
        _provision("khandaq_rt_inh")
        with owner.connect() as conn:
            probe = text("SELECT has_table_privilege('khandaq_rt_inh', 'public.audit_log', :r)")
            assert conn.execute(probe, {"r": right}).scalar_one() is False
    finally:
        owner.dispose()
        _drop("khandaq_rt_inh")


def test_a_forbidden_right_that_cannot_be_removed_fails_boot(runtime_engine, monkeypatch):
    import psycopg

    from khandaq import db_roles

    real_run = db_roles._run

    def no_revoke(conn, template, **ids):
        if template.startswith("REVOKE UPDATE ON TABLE"):
            raise psycopg.errors.InsufficientPrivilege("must be owner of table audit_log")
        real_run(conn, template, **ids)

    owner = _owner()
    with owner.begin() as conn:
        conn.execute(text("GRANT UPDATE ON TABLE audit_log TO PUBLIC"))
    monkeypatch.setattr(db_roles, "_run", no_revoke)
    try:
        with pytest.raises(RuntimeError, match="REVOKE UPDATE ON TABLE audit_log FROM PUBLIC"):
            _provision("khandaq_rt_stuck")
    finally:
        with owner.begin() as conn:
            conn.execute(text("REVOKE UPDATE ON TABLE audit_log FROM PUBLIC"))
        owner.dispose()
        _drop("khandaq_rt_stuck")


def _connect_revoked_from_public(revoked: bool) -> None:
    owner = _owner()
    with owner.begin() as conn:
        db = conn.execute(text("SELECT current_database()")).scalar_one()
        verb = (
            "REVOKE CONNECT ON DATABASE {} FROM PUBLIC"
            if revoked
            else "GRANT CONNECT ON DATABASE {} TO PUBLIC"
        )
        conn.execute(text(verb.format(f'"{db}"')))
    owner.dispose()


def _has_connect(name: str) -> bool:
    with _owner().connect() as conn:
        return conn.execute(
            text("SELECT has_database_privilege(:n, current_database(), 'CONNECT')"), {"n": name}
        ).scalar_one()


def test_an_existing_login_without_connect_still_provisions(runtime_engine):
    # A database that revoked CONNECT from PUBLIC: the login probe used to fail before the
    # grant, even with the right password, and block boot (review on #20).
    _make_role("CREATE ROLE khandaq_rt_noconn LOGIN PASSWORD 'pw'")
    _connect_revoked_from_public(True)
    try:
        assert _provision("khandaq_rt_noconn", password="pw") == "khandaq_rt_noconn"
        assert _has_connect("khandaq_rt_noconn")
    finally:
        _connect_revoked_from_public(False)
        _drop("khandaq_rt_noconn")


def test_a_failed_probe_takes_back_the_temporary_connect(runtime_engine):
    _make_role("CREATE ROLE khandaq_rt_noconn2 LOGIN PASSWORD 'pw'")
    _connect_revoked_from_public(True)
    try:
        with pytest.raises(RuntimeError, match="cannot log in"):
            _provision("khandaq_rt_noconn2", password="wrong")
        assert not _has_connect("khandaq_rt_noconn2")
    finally:
        _connect_revoked_from_public(False)
        _drop("khandaq_rt_noconn2")
