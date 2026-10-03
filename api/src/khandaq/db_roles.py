"""Least-privilege runtime database login (code review, 2026-10-02).

Migrations run as the database **owner**; the API and worker should not. An owner can disable or
drop the trigger that makes ``audit_log`` append-only (spec 001), so if the long-lived API connected
as the owner, a compromise of the API would be a compromise of the audit trail and evidence chain.

When ``KHANDAQ_DATABASE_URL`` names a different login than the one running migrations, this module
(called on every boot, after migrations) makes sure that login exists with the URL's password and
can only work with rows:

- no ownership, no DDL, no trigger management (it owns nothing);
- read/write rows on the mutable tables;
- **INSERT and SELECT only** on the append-only tables (``audit_log``, ``evidence``,
  ``ledger_entries``) — no UPDATE, DELETE or TRUNCATE, enforced by privileges as well as triggers;
- read-only on ``alembic_version``.

When both URLs name the same login (single-user installs, tests), there is nothing to restrict and
this is a no-op. Re-running is safe: grants are re-applied, and the result is checked against the
login's *effective* rights (including anything inherited through ``PUBLIC``), failing boot if a
forbidden right remains.

The login is created with the URL's password on first boot only. An existing login's password and
LOGIN attribute are never rewritten: a restart with an old URL must not undo an administrator's
rotation or ``NOLOGIN``. If the URL no longer authenticates, boot fails with instructions instead.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from urllib.parse import unquote, urlsplit

import psycopg
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError

log = logging.getLogger("khandaq.db_roles")

APPEND_ONLY_TABLES = ("audit_log", "evidence", "ledger_entries", "campaign_diffs")
READ_ONLY_TABLES = ("alembic_version",)


def runtime_login(database_url: str) -> tuple[str, str] | None:
    """``(user, password)`` from a database URL, or ``None`` if it names no user."""
    parts = urlsplit(database_url)
    if not parts.username:
        return None
    return unquote(parts.username), unquote(parts.password or "")


def _run(conn: Connection, template: str, **identifiers: str) -> None:
    """Execute DDL built by the server's ``format()`` (%I identifiers, %L literals), so names and
    the password are quoted by Postgres itself, never by string concatenation."""
    # format() is variadic, so each argument is cast to text for Postgres to type the parameters.
    args = ", ".join(f"CAST(:{key} AS text)" for key in identifiers)
    statement = conn.execute(
        text(f"SELECT format(CAST(:template AS text), {args})"),
        {"template": template, **identifiers},
    ).scalar_one()
    # Raw driver call with no parameters: the formatted DDL may contain ':' or '%' in the password.
    raw = conn.connection.driver_connection
    if raw is None:
        raise RuntimeError("no database driver connection to provision the runtime login")
    raw.execute(statement)


def ensure_runtime_role(conn: Connection, database_url: str) -> str | None:
    """Create/restrict the runtime login named by ``database_url``; return its name, or ``None``
    when it is the same login as the connection's (nothing to do)."""
    login = runtime_login(database_url)
    owner = conn.execute(text("SELECT current_user")).scalar_one()
    if login is None or login[0] == owner:
        return None
    name, password = login

    missing = [
        table
        for table in (*APPEND_ONLY_TABLES, *READ_ONLY_TABLES)
        if conn.execute(text("SELECT to_regclass(:t)"), {"t": f"public.{table}"}).scalar() is None
    ]
    if missing:  # e.g. migrating to an early revision: nothing to restrict yet
        log.info("runtime login not provisioned: tables %s do not exist yet", ", ".join(missing))
        return None

    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :n"), {"n": name}).first()
    if exists is None:
        if not _can_manage_roles(conn):
            raise RuntimeError(
                f"runtime login {name!r} (KHANDAQ_DATABASE_URL) does not exist and the migration "
                "login cannot create roles. Create it as an administrator "
                f"(CREATE ROLE {name} LOGIN PASSWORD '…') or grant CREATEROLE to the "
                "migration login."
            )
        _run(conn, "CREATE ROLE %I LOGIN PASSWORD %L", name=name, password=password)
    else:
        # An existing login must be a plain one: privileges added on top of row access cannot be
        # revoked by GRANT/REVOKE here, so refuse to serve with it at all.
        problems = _elevations(conn, name, owner)
        if problems:
            raise RuntimeError(
                f"runtime login {name!r} must be a plain login with no extra rights: "
                + "; ".join(problems)
            )
        # Never rewrite an existing login's password or LOGIN: that would let a restart with a
        # stale URL reverse an administrator's rotation or NOLOGIN. Verify the URL works instead.
        if not _probe_login(conn, name, database_url):
            raise RuntimeError(
                f"runtime login {name!r} exists but KHANDAQ_DATABASE_URL cannot log in with it "
                "(wrong password, or the login was disabled). Khandaq does not change an existing "
                "login's password: as an administrator run ALTER ROLE ... PASSWORD to match the "
                "URL, or fix the URL"
            )

    db = conn.execute(text("SELECT current_database()")).scalar_one()
    _run(conn, "GRANT CONNECT ON DATABASE %I TO %I", db=db, name=name)
    _run(conn, "GRANT USAGE ON SCHEMA public TO %I", name=name)
    _run(
        conn, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I", name=name
    )
    _run(conn, "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I", name=name)
    for table in APPEND_ONLY_TABLES:
        _run(conn, "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE %I FROM %I", t=table, name=name)
    for table in READ_ONLY_TABLES:
        _run(
            conn, "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE %I FROM %I", t=table, name=name
        )
    # Tables added by later migrations get row rights automatically; a new append-only table must
    # be added to APPEND_ONLY_TABLES so its UPDATE/DELETE are revoked here.
    _run(
        conn,
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I",
        name=name,
    )
    _run(
        conn,
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I",
        name=name,
    )
    _forbid_schema_create(conn, name)
    _forbid_table_rights(conn, name)
    log.info("runtime login %r restricted to row access (append-only tables: insert/select)", name)
    return name


_ELEVATED_ATTRIBUTES = {
    "rolsuper": "SUPERUSER",
    "rolcreaterole": "CREATEROLE",
    "rolcreatedb": "CREATEDB",
    "rolreplication": "REPLICATION",
    "rolbypassrls": "BYPASSRLS",
}


def _elevations(conn: Connection, name: str, owner: str) -> list[str]:
    """Everything that makes an existing login more than a plain, row-level login: elevated role
    attributes, and membership in any role (whose rights it inherits or can SET ROLE to)."""
    row = conn.execute(
        text(f"SELECT {', '.join(_ELEVATED_ATTRIBUTES)} FROM pg_roles WHERE rolname = :n"),
        {"n": name},
    ).one()
    problems = [
        f"has {label}" for attr, label in _ELEVATED_ATTRIBUTES.items() if getattr(row, attr)
    ]
    roles = (
        conn.execute(
            text(
                "SELECT g.rolname FROM pg_auth_members m "
                "JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member "
                "WHERE u.rolname = :n ORDER BY g.rolname"
            ),
            {"n": name},
        )
        .scalars()
        .all()
    )
    if roles:
        note = " (incl. the migration owner: it could SET ROLE and disable the triggers)"
        problems.append(f"is a member of {', '.join(roles)}" + (note if owner in roles else ""))
    return problems


def _probe_login(conn: Connection, name: str, database_url: str) -> bool:
    """Can ``database_url`` log in? The probe is a separate connection, so it cannot see grants
    made in ``conn``'s open transaction. A login that lacks CONNECT (a database that revoked it
    from PUBLIC) would fail the probe even with the right password, so CONNECT, which provisioning
    grants anyway, is committed first on a side connection, and taken back if the probe fails."""
    has_connect = conn.execute(
        text("SELECT has_database_privilege(:n, current_database(), 'CONNECT')"), {"n": name}
    ).scalar_one()
    if has_connect:
        return _can_log_in(database_url)
    db = conn.execute(text("SELECT current_database()")).scalar_one()
    _commit_now(conn, "GRANT CONNECT ON DATABASE %I TO %I", db=db, name=name)
    if _can_log_in(database_url):
        return True
    _commit_now(conn, "REVOKE CONNECT ON DATABASE %I FROM %I", db=db, name=name)
    return False


def _commit_now(conn: Connection, template: str, **identifiers: str) -> None:
    """Run one statement on a separate autocommit connection as the same (owner) login, so it is
    visible to other connections at once without committing ``conn``'s transaction early."""
    with conn.engine.connect() as side:
        _run(side.execution_options(isolation_level="AUTOCOMMIT"), template, **identifiers)


def _can_log_in(database_url: str) -> bool:
    """Does the runtime URL actually authenticate? Bounded by a short connect timeout, so an
    unreachable host fails boot with guidance instead of hanging for the OS TCP timeout."""
    engine = create_engine(database_url, connect_args={"connect_timeout": 10})
    try:
        with engine.connect():
            return True
    except OperationalError:
        return False
    finally:
        engine.dispose()


def _can_manage_roles(conn: Connection) -> bool:
    row = conn.execute(
        text("SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user")
    ).one()
    return bool(row.rolsuper or row.rolcreaterole)


def _forbid_schema_create(conn: Connection, name: str) -> None:
    """The runtime login must not create objects anywhere: not in ``public`` (databases created
    before PostgreSQL 15 grant that to PUBLIC, and GRANT USAGE does not take it away) and not new
    schemas (database-level CREATE)."""
    db = conn.execute(text("SELECT current_database()")).scalar_one()
    checks = (
        (
            "SELECT has_schema_privilege(:n, 'public', 'CREATE')",
            lambda: _run(conn, "REVOKE CREATE ON SCHEMA public FROM PUBLIC, %I", name=name),
            f"REVOKE CREATE ON SCHEMA public FROM PUBLIC, {name}",
        ),
        (
            "SELECT has_database_privilege(:n, current_database(), 'CREATE')",
            lambda: _run(conn, "REVOKE CREATE ON DATABASE %I FROM PUBLIC, %I", db=db, name=name),
            f"REVOKE CREATE ON DATABASE {db} FROM PUBLIC, {name}",
        ),
        (  # PostgreSQL grants TEMPORARY to PUBLIC by default; temp tables are objects too
            "SELECT has_database_privilege(:n, current_database(), 'TEMPORARY')",
            lambda: _run(conn, "REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, %I", db=db, name=name),
            f"REVOKE TEMPORARY ON DATABASE {db} FROM PUBLIC, {name}",
        ),
    )
    for probe, revoke, advice in checks:
        _enforce(conn, name, probe, {}, revoke, advice)


# Rights the runtime login must not hold, even when inherited through PUBLIC (a REVOKE from the
# login alone leaves those in place). TRIGGER would let it attach a trigger that rewrites new rows.
_FORBIDDEN_TABLE_RIGHTS = {
    **{t: ("UPDATE", "DELETE", "TRUNCATE", "TRIGGER") for t in APPEND_ONLY_TABLES},
    **{t: ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER") for t in READ_ONLY_TABLES},
}


def _forbid_table_rights(conn: Connection, name: str) -> None:
    """Check the login's *effective* rights on the append-only and read-only tables; remove a grant
    to PUBLIC that gives it a forbidden one, and refuse to serve if one remains."""
    for table, rights in _FORBIDDEN_TABLE_RIGHTS.items():
        for right in rights:

            def revoke(table: str = table, right: str = right) -> None:
                _run(conn, f"REVOKE {right} ON TABLE %I FROM PUBLIC, %I", t=table, name=name)

            _enforce(
                conn,
                name,
                "SELECT has_table_privilege(:n, :t, :r)",
                {"t": f"public.{table}", "r": right},
                revoke,
                f"REVOKE {right} ON TABLE {table} FROM PUBLIC, {name}",
            )


def _enforce(
    conn: Connection,
    name: str,
    probe: str,
    params: dict[str, str],
    revoke: Callable[[], None],
    advice: str,
) -> None:
    """If ``probe`` says the login holds a forbidden right, revoke it (in a savepoint) and check
    again; fail boot with the exact command for the owner when it cannot be removed from here."""
    if not conn.execute(text(probe), {"n": name, **params}).scalar_one():
        return
    try:
        with conn.begin_nested():
            revoke()
    except psycopg.errors.InsufficientPrivilege:
        pass  # not the owner of the object; the check below reports it
    if conn.execute(text(probe), {"n": name, **params}).scalar_one():
        raise RuntimeError(
            f"runtime login {name!r} still holds a forbidden right; as the owner run: {advice}"
        )
