"""Key users by their identity-provider account (OIDC ``iss`` + ``sub``).

Adds ``users.oidc_issuer`` / ``users.oidc_subject`` (both set or both NULL) with a unique index.
Existing users keep NULL until their next verified sign-in links them by email (auth service), so
the upgrade itself changes no row. Email stays unique: it is the allow-list key and the display
name, and an email linked to one IdP account is refused for any other.

Revision ID: 0006_user_oidc_identity
Revises: 0005_ledger_format
Create Date: 2026-10-03
"""

from __future__ import annotations

from alembic import op

revision = "0006_user_oidc_identity"
down_revision = "0005_ledger_format"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS / DROP-then-ADD: on a fresh database 0001's create_all already built these.
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer text")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject text")
    op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_oidc_identity_pair")
    op.execute(
        "ALTER TABLE users ADD CONSTRAINT ck_users_oidc_identity_pair "
        "CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL))"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_oidc_identity "
        "ON users (oidc_issuer, oidc_subject)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_users_oidc_identity")
    op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_oidc_identity_pair")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS oidc_subject")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS oidc_issuer")
