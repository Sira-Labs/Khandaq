"""Ledger entry format: format 2 seals the evidence row's metadata (ADR-0014).

Adds ``ledger_entries.format``. Existing entries become format 1 — the artefact's sha256 alone,
exactly what they sealed — so every existing chain keeps verifying; entries sealed from now on are
format 2. Adding a column with a default rewrites no row, so the append-only triggers (0003) are
not involved.

Downgrade is refused once any format-2 entry exists: the previous code would verify it as format 1
and report the chain broken.

Revision ID: 0005_ledger_format
Revises: 0004_fingerprint_v2
Create Date: 2026-10-03
"""

from __future__ import annotations

from alembic import op
from sqlalchemy import text

revision = "0005_ledger_format"
down_revision = "0004_fingerprint_v2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS: on a fresh database 0001's create_all already built the column from the model.
    op.execute(
        "ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS format smallint NOT NULL DEFAULT 1"
    )
    op.execute("ALTER TABLE ledger_entries ALTER COLUMN format SET DEFAULT 2")


def downgrade() -> None:
    # Block appends until the column is gone: a check that a concurrent seal could slip past would
    # let the downgrade strand a format-2 entry. EXCLUSIVE still allows reads.
    op.execute("LOCK TABLE ledger_entries IN EXCLUSIVE MODE")
    sealed = (
        op.get_bind()
        .execute(text("SELECT count(*) FROM ledger_entries WHERE format <> 1"))
        .scalar_one()
    )
    if sealed:
        raise RuntimeError(
            f"{sealed} ledger entries use format 2 (ADR-0014); the previous schema cannot verify "
            "them, so this downgrade is refused"
        )
    op.execute("ALTER TABLE ledger_entries DROP COLUMN format")
