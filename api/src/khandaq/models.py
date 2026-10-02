"""SQLAlchemy models — the Khandaq persistence schema (spec 001).

These tables are the durable home for engagements, scope, runs, findings, evidence and the audit
log. The integrity constraints here are load-bearing for the authorised-use guarantees:

- ``findings.dedup_of`` is a **composite** foreign key, so a duplicate can only ever point at a
  finding in the *same* engagement (no cross-engagement linkage).
- ``ledger_entries`` is unique and ordered per engagement (the hash chain, ADR-0007).
- ``audit_log`` is made append-only by a database trigger in the migration (see migrations/).

Enumerations are expressed as ``CHECK`` constraints rather than native PG enum types, so migrations
stay simple and values are still enforced in the database.
"""

from __future__ import annotations

import datetime as dt
import secrets

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id(prefix: str) -> str:
    """A short, URL-safe, prefixed identifier, e.g. ``eng_1a2b3c4d5e6f7081``."""
    return f"{prefix}_{secrets.token_hex(8)}"


class Base(DeclarativeBase):
    pass


def _created_at() -> Mapped[dt.datetime]:
    return mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("usr"))
    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(Text)
    org_role: Mapped[str] = mapped_column(Text, nullable=False, server_default="member")
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        CheckConstraint("org_role in ('admin','member','read_only')", name="ck_users_org_role"),
    )


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("tok"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    hash: Mapped[str] = mapped_column(Text, nullable=False)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = _created_at()


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("eng"))
    name: Mapped[str] = mapped_column(Text, nullable=False)
    client: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="draft")
    authorisation_ref: Mapped[str | None] = mapped_column(Text)
    activated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        CheckConstraint("state in ('draft','active','closed')", name="ck_engagements_state"),
    )


class EngagementMember(Base):
    __tablename__ = "engagement_members"
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        CheckConstraint("role in ('owner','operator','analyst','viewer')", name="ck_members_role"),
    )


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("tgt"))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    spec: Mapped[dict] = mapped_column(JSONB, nullable=False)
    credential_ref: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        CheckConstraint(
            "type in ('llm_endpoint','agent','mcp_server','model_artifact','dataset')",
            name="ck_targets_type",
        ),
    )


class Scope(Base):
    __tablename__ = "scopes"
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    allow: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    deny: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="[]")
    roe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    locked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()


class Suite(Base):
    __tablename__ = "suites"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("ste"))
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    definition: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[dt.datetime] = _created_at()


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("run"))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    suite_id: Mapped[str | None] = mapped_column(ForeignKey("suites.id"))
    adapter: Mapped[str] = mapped_column(Text, nullable=False)
    adapter_version: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id"))
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="queued")
    reject_reason: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        CheckConstraint(
            "state in ('queued','running','succeeded','failed','rejected')",
            name="ck_runs_state",
        ),
    )


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("fnd"))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    canonical: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    dedup_of: Mapped[str | None] = mapped_column(Text)
    rule_id: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(Text, nullable=False, server_default="firm")
    body: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="open")
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        # Target for the composite self-FK below.
        UniqueConstraint("engagement_id", "id", name="uq_findings_engagement_id"),
        # A duplicate may only reference a finding in the SAME engagement.
        ForeignKeyConstraint(
            ["engagement_id", "dedup_of"],
            ["findings.engagement_id", "findings.id"],
            name="fk_findings_dedup_same_engagement",
        ),
        CheckConstraint(
            "severity in ('info','low','medium','high','critical')", name="ck_findings_severity"
        ),
        CheckConstraint(
            "confidence in ('tentative','firm','confirmed')", name="ck_findings_confidence"
        ),
        CheckConstraint(
            "status in ('open','triaged','accepted_risk','fixed','false_positive')",
            name="ck_findings_status",
        ),
    )


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("ev"))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    object_key: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("led"))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), nullable=False)
    entry_hash: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (UniqueConstraint("engagement_id", "seq", name="uq_ledger_engagement_seq"),)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("aud"))
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    actor_token_id: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"))
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
