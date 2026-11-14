"""Target credentials (spec 028): one write-only, envelope-encrypted secret per target.

Adds ``target_credentials`` and the ``targets (id, engagement_id)`` uniqueness its composite
foreign key needs. Sets the unused free-text ``targets.credential_ref`` to NULL: Khandaq never
read it, and nothing stopped someone from pasting a secret into it. The column itself stays until
a later migration drops it.

Revision ID: 0012_target_credentials
Revises: 0011_worker_heartbeats
Create Date: 2026-11-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_target_credentials"
down_revision = "0011_worker_heartbeats"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE targets SET credential_ref = NULL WHERE credential_ref IS NOT NULL")
    inspector = sa.inspect(op.get_bind())
    # 0001 is a create_all baseline over the live models: on a fresh database both already exist.
    constraints = {c["name"] for c in inspector.get_unique_constraints("targets")}
    if "uq_targets_id_engagement" not in constraints:
        op.create_unique_constraint("uq_targets_id_engagement", "targets", ["id", "engagement_id"])
    if "target_credentials" in inspector.get_table_names():
        return
    op.create_table(
        "target_credentials",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("target_id", sa.Text(), nullable=False, unique=True),
        sa.Column("engagement_id", sa.Text(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("set_by_user_id", sa.Text(), sa.ForeignKey("users.id"), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_id", "engagement_id"],
            ["targets.id", "targets.engagement_id"],
            name="fk_target_credentials_target_engagement",
        ),
        sa.CheckConstraint("version >= 1", name="ck_target_credentials_version"),
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS target_credentials")
    op.execute("ALTER TABLE targets DROP CONSTRAINT IF EXISTS uq_targets_id_engagement")
