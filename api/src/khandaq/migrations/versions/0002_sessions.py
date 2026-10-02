"""Server-side login sessions for the OIDC BFF (spec 008).

Adds the ``sessions`` table backing the ``__Host-khandaq_session`` cookie (ADR-0005). No change to
the append-only audit trigger from 0001.

Revision ID: 0002_sessions
Revises: 0001_initial
Create Date: 2026-10-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_sessions"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 0001 is a create_all baseline over the live model metadata, so on a *fresh* database it
    # already creates the sessions table (the model now exists); on a database first migrated before
    # spec 008 it does not. Guard on existence so both paths converge on the same schema.
    bind = op.get_bind()
    if "sessions" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "sessions",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Text(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("csrf", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "sessions" in sa.inspect(bind).get_table_names():
        op.drop_table("sessions")
