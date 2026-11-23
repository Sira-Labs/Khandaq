"""Runs remember their Docker daemon (spec 032): ``runs.docker_daemon``.

The id of the daemon a container run's network and containers were created on, recorded before
the first of them exists. Recovery removes a lost run's leftovers only on that daemon: a worker
on another host would find nothing, call the run clean and free the engagement's next paced run
while the first forwarder still relays.

Revision ID: 0014_run_docker_daemon
Revises: 0013_target_artefacts
Create Date: 2026-11-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_run_docker_daemon"
down_revision = "0013_target_artefacts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 0001 is a create_all baseline over the live models: on a fresh database the column exists.
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("runs")}
    if "docker_daemon" not in columns:
        op.add_column("runs", sa.Column("docker_daemon", sa.Text(), nullable=True))


def downgrade() -> None:
    op.execute("ALTER TABLE runs DROP COLUMN IF EXISTS docker_daemon")
