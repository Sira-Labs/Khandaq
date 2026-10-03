"""Alert channels: one outbox row per channel per diff (spec 022).

Adds ``alert_outbox.channel`` (``webhook`` | ``email``, default ``webhook``) and moves the unique
constraint from ``diff_id`` to ``(diff_id, channel)``. Existing rows become webhook rows; no row is
otherwise changed.

Revision ID: 0010_alert_channels
Revises: 0009_alert_outbox
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_alert_channels"
down_revision = "0009_alert_outbox"
branch_labels = None
depends_on = None

TABLE = "alert_outbox"
UNIQUE = "uq_alert_outbox_diff_channel"
CHECK = "ck_alert_outbox_channel"


def _uniques(bind) -> list[dict]:
    return sa.inspect(bind).get_unique_constraints(TABLE)


def upgrade() -> None:
    # 0001 is a create_all baseline over the live models: on a fresh database the column and the
    # constraints already exist, so each step is guarded and both paths converge.
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns(TABLE)}
    if "channel" not in columns:
        op.add_column(
            TABLE, sa.Column("channel", sa.Text(), nullable=False, server_default="webhook")
        )
        op.create_check_constraint(CHECK, TABLE, "channel in ('webhook','email')")
    for unique in _uniques(bind):
        if unique["column_names"] == ["diff_id"]:
            op.drop_constraint(unique["name"], TABLE, type_="unique")
    if not any(u["name"] == UNIQUE for u in _uniques(bind)):
        op.create_unique_constraint(UNIQUE, TABLE, ["diff_id", "channel"])


def downgrade() -> None:
    bind = op.get_bind()
    emails = bind.execute(sa.text("SELECT count(*) FROM alert_outbox WHERE channel = 'email'"))
    if emails.scalar():
        # Dropping them would erase alert history; keeping them breaks one-row-per-diff.
        raise RuntimeError("alert_outbox holds email alerts; refusing to downgrade past 0010")
    op.drop_constraint(UNIQUE, TABLE, type_="unique")
    op.create_unique_constraint("alert_outbox_diff_id_key", TABLE, ["diff_id"])
    op.drop_constraint(CHECK, TABLE, type_="check")
    op.drop_column(TABLE, "channel")
