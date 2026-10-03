"""Alert outbox for worsened campaign diffs (spec 017).

One row per alert, queued in the transaction that records the diff and delivered by the worker
with retries. No existing row changes.

Revision ID: 0009_alert_outbox
Revises: 0008_campaigns
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0009_alert_outbox"
down_revision = "0008_campaigns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 0001 is a create_all baseline over the live models: on a fresh database the table exists.
    if "alert_outbox" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "alert_outbox",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("engagement_id", sa.Text(), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("campaign_id", sa.Text(), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column(
            "diff_id", sa.Text(), sa.ForeignKey("campaign_diffs.id"), nullable=False, unique=True
        ),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("state in ('pending','sent','failed')", name="ck_alert_outbox_state"),
    )
    op.create_index("ix_alert_outbox_due", "alert_outbox", ["state", "next_attempt_at"])


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS alert_outbox")
