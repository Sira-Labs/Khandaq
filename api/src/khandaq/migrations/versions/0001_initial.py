"""Initial schema (spec 001).

Creates every table from khandaq.models and installs the trigger that makes audit_log append-only.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-02
"""

from __future__ import annotations

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

# audit_log is append-only: reject UPDATE and DELETE at the database, regardless of the login used
# (more portable than a second restricted role; a restricted app role remains a prod hardening
# option — see deploy/caprover.md). This is the invariant SECURITY.md and spec 002 rely on.
_AUDIT_TRIGGER = """
CREATE OR REPLACE FUNCTION khandaq_audit_log_immutable() RETURNS trigger AS $func$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$func$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION khandaq_audit_log_immutable();
"""


def upgrade() -> None:
    # Import here so the migration carries the model metadata without import-time side effects.
    from khandaq.models import Base

    Base.metadata.create_all(op.get_bind())
    op.execute(_AUDIT_TRIGGER)


def downgrade() -> None:
    from khandaq.models import Base

    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update_delete ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS khandaq_audit_log_immutable();")
    Base.metadata.drop_all(op.get_bind())
