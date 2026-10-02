"""Alembic migration runner, shipped inside the package so the image can run it on boot.

Usage:
    python -m khandaq.migrate upgrade head     # or: khandaq-db upgrade head
    python -m khandaq.migrate downgrade -1

The database URL comes from KHANDAQ_MIGRATION_DATABASE_URL (preferred) or KHANDAQ_DATABASE_URL.
Migrations live in khandaq/migrations and are packaged with the wheel. After upgrading, the runtime
login named by KHANDAQ_DATABASE_URL is provisioned with row access only (see db_roles).
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

import khandaq

from . import db_roles
from .settings import get_settings

MIGRATIONS_DIR = Path(khandaq.__file__).resolve().parent / "migrations"


def _default_url() -> str:
    s = get_settings()
    return s.migration_database_url or s.database_url


def make_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def upgrade(url: str | None = None, revision: str = "head", runtime_url: str | None = None) -> None:
    """Migrate as the owner, then restrict the runtime login (``runtime_url``, default
    KHANDAQ_DATABASE_URL) to row access. A no-op for the role when both name the same login."""
    owner_url = url or _default_url()
    command.upgrade(make_config(owner_url), revision)
    runtime = get_settings().database_url if runtime_url is None else runtime_url
    if not runtime:
        return
    engine = create_engine(owner_url)
    try:
        with engine.begin() as conn:
            db_roles.ensure_runtime_role(conn, runtime)
    finally:
        engine.dispose()


def downgrade(url: str | None = None, revision: str = "-1") -> None:
    command.downgrade(make_config(url or _default_url()), revision)


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else "upgrade"
    url = _default_url()
    if not url:
        sys.exit(
            "no database url configured "
            "(set KHANDAQ_MIGRATION_DATABASE_URL or KHANDAQ_DATABASE_URL)"
        )
    if cmd == "upgrade":
        upgrade(url, args[1] if len(args) > 1 else "head")
    elif cmd == "downgrade":
        downgrade(url, args[1] if len(args) > 1 else "-1")
    else:
        sys.exit(f"unknown command: {cmd!r} (use 'upgrade' or 'downgrade')")


if __name__ == "__main__":
    main()
