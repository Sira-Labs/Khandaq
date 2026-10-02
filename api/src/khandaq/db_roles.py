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
this is a no-op. Re-running is safe: grants are re-applied and the password kept in sync.
"""

from __future__ import annotations

import logging
from urllib.parse import unquote, urlsplit

import psycopg
from sqlalchemy import text
from sqlalchemy.engine import Connection

log = logging.getLogger("khandaq.db_roles")

APPEND_ONLY_TABLES = ("audit_log", "evidence", "ledger_entries")
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

    row = conn.execute(
        text("SELECT rolsuper FROM pg_roles WHERE rolname = :n"), {"n": name}
    ).first()
    if row is None:
        if not _can_manage_roles(conn):
            raise RuntimeError(
                f"runtime login {name!r} (KHANDAQ_DATABASE_URL) does not exist and the migration "
                "login cannot create roles. Create it as an administrator "
                f"(CREATE ROLE {name} LOGIN PASSWORD '…') or grant CREATEROLE to the "
                "migration login."
            )
        _run(conn, "CREATE ROLE %I LOGIN PASSWORD %L", name=name, password=password)
    else:
        # Privileges cannot restrict these logins, so refuse to serve with them at all.
        if row.rolsuper:
            raise RuntimeError(f"runtime login {name!r} is a superuser; use a plain login")
        can_be_owner = conn.execute(
            text("SELECT pg_has_role(:n, :o, 'MEMBER')"), {"n": name, "o": owner}
        ).scalar_one()
        if can_be_owner:
            raise RuntimeError(
                f"runtime login {name!r} is a member of the migration owner {owner!r} and could "
                "SET ROLE to it (and so disable the append-only triggers); revoke that membership"
            )
        try:  # keep the password in sync when allowed; an administrator may manage it instead
            with conn.begin_nested():
                _run(conn, "ALTER ROLE %I LOGIN PASSWORD %L", name=name, password=password)
        except psycopg.errors.InsufficientPrivilege:
            log.warning("cannot update the password of runtime login %r; leaving it as is", name)

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
    log.info("runtime login %r restricted to row access (append-only tables: insert/select)", name)
    return name


def _can_manage_roles(conn: Connection) -> bool:
    row = conn.execute(
        text("SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user")
    ).one()
    return bool(row.rolsuper or row.rolcreaterole)


def _forbid_schema_create(conn: Connection, name: str) -> None:
    """The runtime login must not create objects. Databases created before PostgreSQL 15 still
    grant CREATE on ``public`` to PUBLIC, which a GRANT USAGE does not take away."""

    def can_create() -> bool:
        return bool(
            conn.execute(
                text("SELECT has_schema_privilege(:n, 'public', 'CREATE')"), {"n": name}
            ).scalar_one()
        )

    if not can_create():
        return
    try:
        with conn.begin_nested():
            _run(conn, "REVOKE CREATE ON SCHEMA public FROM PUBLIC, %I", name=name)
    except psycopg.errors.InsufficientPrivilege:
        pass  # not the schema owner; the check below reports it
    if can_create():
        raise RuntimeError(
            f"runtime login {name!r} can still create objects in schema public; as the schema "
            f"owner run: REVOKE CREATE ON SCHEMA public FROM PUBLIC, {name}"
        )
