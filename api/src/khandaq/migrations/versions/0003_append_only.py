"""Append-only evidence and ledger; one canonical finding per fingerprint (code review).

- ``evidence`` and ``ledger_entries`` reject UPDATE and DELETE, like ``audit_log`` does since 0001
  (ADR-0007: never mutate or delete sealed evidence). Before this, swapping an evidence row's
  ``object_key`` or ``run_id`` went unnoticed by the chain.
- All three append-only tables reject TRUNCATE (a statement-level trigger: the row-level ones never
  fire for TRUNCATE).
- ``findings`` gets a partial unique index on (engagement_id, fingerprint) WHERE canonical, backing
  cross-run deduplication (ADR-0003). Installs that already hold duplicate canonical rows (dedup
  used to run only within one run) have the later ones linked to the earliest first, so the index
  can be built instead of failing the boot.

Revision ID: 0003_append_only
Revises: 0002_sessions
Create Date: 2026-10-02
"""

from __future__ import annotations

from alembic import op

revision = "0003_append_only"
down_revision = "0002_sessions"
branch_labels = None
depends_on = None

_APPEND_ONLY = """
CREATE OR REPLACE FUNCTION khandaq_append_only() RETURNS trigger AS $func$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$func$ LANGUAGE plpgsql;

CREATE TRIGGER evidence_no_update_delete
    BEFORE UPDATE OR DELETE ON evidence
    FOR EACH ROW EXECUTE FUNCTION khandaq_append_only();
CREATE TRIGGER ledger_entries_no_update_delete
    BEFORE UPDATE OR DELETE ON ledger_entries
    FOR EACH ROW EXECUTE FUNCTION khandaq_append_only();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION khandaq_append_only();
CREATE TRIGGER evidence_no_truncate
    BEFORE TRUNCATE ON evidence
    FOR EACH STATEMENT EXECUTE FUNCTION khandaq_append_only();
CREATE TRIGGER ledger_entries_no_truncate
    BEFORE TRUNCATE ON ledger_entries
    FOR EACH STATEMENT EXECUTE FUNCTION khandaq_append_only();
"""

_LINK_EXISTING_DUPLICATES = """
WITH ranked AS (
    SELECT id,
           first_value(id) OVER (
               PARTITION BY engagement_id, fingerprint ORDER BY created_at, id
           ) AS keep_id
    FROM findings
    WHERE canonical
)
UPDATE findings AS f
SET canonical = false, dedup_of = r.keep_id
FROM ranked AS r
WHERE f.id = r.id AND r.id <> r.keep_id;
"""


def upgrade() -> None:
    op.execute(_APPEND_ONLY)
    op.execute(_LINK_EXISTING_DUPLICATES)
    # IF NOT EXISTS: on a fresh database 0001's create_all already built it from the model.
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_canonical_fingerprint "
        "ON findings (engagement_id, fingerprint) WHERE canonical"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_findings_canonical_fingerprint")
    for table, name in (
        ("evidence", "evidence_no_update_delete"),
        ("ledger_entries", "ledger_entries_no_update_delete"),
        ("audit_log", "audit_log_no_truncate"),
        ("evidence", "evidence_no_truncate"),
        ("ledger_entries", "ledger_entries_no_truncate"),
    ):
        op.execute(f"DROP TRIGGER IF EXISTS {name} ON {table}")
    op.execute("DROP FUNCTION IF EXISTS khandaq_append_only()")
