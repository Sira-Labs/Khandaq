"""Index ``audit_log`` by (engagement, action).

Report re-verification (spec 013) asks whether this instance exported a given ledger pin, i.e.
looks up one action within one engagement; without the index that scans the whole log. The index
changes no row, and the table stays append-only.

Revision ID: 0007_audit_log_engagement_action
Revises: 0006_user_oidc_identity
Create Date: 2026-10-03
"""

from __future__ import annotations

from alembic import op

revision = "0007_audit_log_engagement_action"
down_revision = "0006_user_oidc_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS: on a fresh database 0001's create_all already built it from the model.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_audit_log_engagement_action "
        "ON audit_log (engagement_id, action)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_audit_log_engagement_action")
