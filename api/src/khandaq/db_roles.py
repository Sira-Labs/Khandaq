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

    row = conn.execute(
        text("SELECT rolsuper FROM pg_roles WHERE rolname = :n"), {"n": name}
    ).first()
    if row is None:
        _run(conn, "CREATE ROLE %I LOGIN PASSWORD %L", name=name, password=password)
    else:
        if row.rolsuper:
            log.warning("runtime login %r is a superuser; privileges cannot restrict it", name)
        _run(conn, "ALTER ROLE %I LOGIN PASSWORD %L", name=name, password=password)

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
    log.info("runtime login %r restricted to row access (append-only tables: insert/select)", name)
    return name
