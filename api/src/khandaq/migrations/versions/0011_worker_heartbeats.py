"""Worker heartbeats (spec 023): each worker's last sign of life and settings summary.

Adds ``worker_heartbeats``; no existing row changes.

Revision ID: 0011_worker_heartbeats
Revises: 0010_alert_channels
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0011_worker_heartbeats"
down_revision = "0010_alert_channels"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 0001 is a create_all baseline over the live models: on a fresh database the table exists.
    if "worker_heartbeats" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "worker_heartbeats",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("app_version", sa.Text(), nullable=False),
        sa.Column("summary", JSONB(), nullable=False),
    )
    op.create_index("ix_worker_heartbeats_seen", "worker_heartbeats", ["seen_at"])


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS worker_heartbeats")
