"""Campaigns and their diffs (spec 016, ADR-0017).

Adds ``campaigns`` (a run template, an interval and ``next_run_at``), ``runs.campaign_id``, and
``campaign_diffs`` (what each successful campaign run changed), which is append-only like the
ledger: what a diff said, and what an alert was raised on, cannot be rewritten afterwards. No
existing row changes.

Revision ID: 0008_campaigns
Revises: 0007_audit_log_engagement_action
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008_campaigns"
down_revision = "0007_audit_log_engagement_action"
branch_labels = None
depends_on = None


def _ts(name: str) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())


def upgrade() -> None:
    # 0001 is a create_all baseline over the live model metadata, so on a fresh database these
    # tables already exist; guard on existence so both paths converge (as 0002 does).
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "campaigns" not in tables:
        op.create_table(
            "campaigns",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("engagement_id", sa.Text(), sa.ForeignKey("engagements.id"), nullable=False),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("adapter", sa.Text(), nullable=False),
            sa.Column("target_id", sa.Text(), sa.ForeignKey("targets.id"), nullable=False),
            sa.Column("params", JSONB(), nullable=False, server_default="{}"),
            sa.Column("interval_minutes", sa.Integer(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.Text(), sa.ForeignKey("users.id")),
            _ts("created_at"),
            _ts("updated_at"),
            sa.CheckConstraint("interval_minutes > 0", name="ck_campaigns_interval"),
        )
        op.create_index("ix_campaigns_due", "campaigns", ["enabled", "next_run_at"])
    op.execute(
        "ALTER TABLE runs ADD COLUMN IF NOT EXISTS campaign_id text REFERENCES campaigns(id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_runs_campaign_created ON runs (campaign_id, created_at)"
    )
    if "campaign_diffs" not in tables:
        op.create_table(
            "campaign_diffs",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("campaign_id", sa.Text(), sa.ForeignKey("campaigns.id"), nullable=False),
            sa.Column("run_id", sa.Text(), sa.ForeignKey("runs.id"), nullable=False, unique=True),
            sa.Column("previous_run_id", sa.Text(), sa.ForeignKey("runs.id")),
            sa.Column("baseline", sa.Boolean(), nullable=False),
            sa.Column("new", JSONB(), nullable=False, server_default="[]"),
            sa.Column("regressed", JSONB(), nullable=False, server_default="[]"),
            sa.Column("resolved", JSONB(), nullable=False, server_default="[]"),
            sa.Column("unchanged_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("worsened", sa.Boolean(), nullable=False, server_default="false"),
            _ts("created_at"),
        )
        op.create_index(
            "ix_campaign_diffs_campaign_created", "campaign_diffs", ["campaign_id", "created_at"]
        )
    # khandaq_append_only() comes from 0003.
    op.execute("DROP TRIGGER IF EXISTS campaign_diffs_no_update_delete ON campaign_diffs")
    op.execute(
        "CREATE TRIGGER campaign_diffs_no_update_delete BEFORE UPDATE OR DELETE ON campaign_diffs "
        "FOR EACH ROW EXECUTE FUNCTION khandaq_append_only()"
    )
    op.execute("DROP TRIGGER IF EXISTS campaign_diffs_no_truncate ON campaign_diffs")
    op.execute(
        "CREATE TRIGGER campaign_diffs_no_truncate BEFORE TRUNCATE ON campaign_diffs "
        "FOR EACH STATEMENT EXECUTE FUNCTION khandaq_append_only()"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS campaign_diffs")
    op.execute("DROP INDEX IF EXISTS ix_runs_campaign_created")
    op.execute("ALTER TABLE runs DROP COLUMN IF EXISTS campaign_id")
    op.execute("DROP TABLE IF EXISTS campaigns")
