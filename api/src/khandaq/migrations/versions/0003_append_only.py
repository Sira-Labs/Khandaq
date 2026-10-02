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

# Before demoting duplicates, fold their evidence and tool attribution onto the row that stays
# canonical — the inbox and reports read only canonical rows, so anything left on a demoted row
# would vanish from both. Same ranking as the linking step; groups without duplicates are untouched.
_MERGE_EXISTING_DUPLICATE_ATTRIBUTION = """
WITH ranked AS (
    SELECT id, body,
           first_value(id) OVER (
               PARTITION BY engagement_id, fingerprint ORDER BY created_at, id
           ) AS keep_id
    FROM findings
    WHERE canonical
),
evidence AS (
    SELECT r.keep_id,
           COALESCE(jsonb_agg(DISTINCT e.value) FILTER (WHERE e.value IS NOT NULL), '[]'::jsonb)
               AS evidence
    FROM ranked AS r
    LEFT JOIN LATERAL jsonb_array_elements(
        COALESCE(r.body #> '{x-khandaq,evidence}', '[]'::jsonb)
    ) AS e(value) ON true
    GROUP BY r.keep_id
),
tools AS (
    SELECT r.keep_id,
           COALESCE(jsonb_agg(DISTINCT t.tool) FILTER (WHERE t.tool IS NOT NULL), '[]'::jsonb)
               AS also_found_by
    FROM ranked AS r
    JOIN findings AS k ON k.id = r.keep_id
    LEFT JOIN LATERAL (
        SELECT value FROM jsonb_array_elements_text(
            COALESCE(r.body #> '{x-khandaq,also_found_by}', '[]'::jsonb)
        )
        UNION
        SELECT r.body #>> '{source,tool}' WHERE r.id <> r.keep_id
    ) AS t(tool) ON t.tool IS DISTINCT FROM (k.body #>> '{source,tool}')
    GROUP BY r.keep_id
)
UPDATE findings AS k
SET body = jsonb_set(
    k.body,
    '{x-khandaq}',
    COALESCE(k.body -> 'x-khandaq', '{}'::jsonb)
        || jsonb_build_object('evidence', ev.evidence, 'also_found_by', tl.also_found_by),
    true
)
FROM evidence AS ev
JOIN tools AS tl ON tl.keep_id = ev.keep_id
WHERE k.id = ev.keep_id
  AND EXISTS (SELECT 1 FROM ranked AS d WHERE d.keep_id = k.id AND d.id <> k.id);
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
    op.execute(_MERGE_EXISTING_DUPLICATE_ATTRIBUTION)
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
