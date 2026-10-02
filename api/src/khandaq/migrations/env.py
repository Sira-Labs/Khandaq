"""Alembic environment (online mode only; the URL is always supplied by khandaq.migrate)."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from khandaq.models import Base

target_metadata = Base.metadata


def run_migrations_online() -> None:
    url = context.config.get_main_option("sqlalchemy.url")
    assert url, "sqlalchemy.url must be set by khandaq.migrate"
    connectable = create_engine(url, poolclass=pool.NullPool, future=True)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


run_migrations_online()
