"""Target artefacts (spec 034): where the stored content of a model or dataset target is recorded.

One row per target: the digest the content was checked against, its size and its object key in the
evidence store. The bytes themselves are not in the database.

Revision ID: 0013_target_artefacts
Revises: 0012_target_credentials
Create Date: 2026-11-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013_target_artefacts"
down_revision = "0012_target_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 0001 is a create_all baseline over the live models: on a fresh database the table exists.
    if "target_artefacts" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "target_artefacts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("target_id", sa.Text(), nullable=False, unique=True),
        sa.Column("engagement_id", sa.Text(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False, unique=True),
        sa.Column("stored_by_user_id", sa.Text(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["target_id", "engagement_id"],
            ["targets.id", "targets.engagement_id"],
            name="fk_target_artefacts_target_engagement",
        ),
        sa.CheckConstraint("bytes > 0", name="ck_target_artefacts_bytes"),
    )
    op.create_index("ix_target_artefacts_engagement", "target_artefacts", ["engagement_id"])


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS target_artefacts")
