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
    Index,
    Integer,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
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
    # `auth_token_id` below is a transient, non-column attribute (allowed by this flag).
    __allow_unmapped__ = True
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("usr"))
    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # The identity-provider account (OIDC `iss` + `sub`) this user signs in as — the stable key.
    # Email is for display and the allow-list; NULL until a pre-0006 user's next sign-in links it,
    # and for dev-stub users. Migration 0006.
    oidc_issuer: Mapped[str | None] = mapped_column(Text)
    oidc_subject: Mapped[str | None] = mapped_column(Text)
    display_name: Mapped[str | None] = mapped_column(Text)
    org_role: Mapped[str] = mapped_column(Text, nullable=False, server_default="member")
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        CheckConstraint("org_role in ('admin','member','read_only')", name="ck_users_org_role"),
        CheckConstraint(
            "(oidc_issuer IS NULL) = (oidc_subject IS NULL)", name="ck_users_oidc_identity_pair"
        ),
        Index("uq_users_oidc_identity", "oidc_issuer", "oidc_subject", unique=True),
    )

    # Set by deps.current_user when an API token authenticated this request, so audit.record can
    # attribute the action to the token (spec 008). Not a column: each request has its own DB
    # session, hence its own User instance, so the value never leaks across requests.
    auth_token_id: str | None = None


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("tok"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    hash: Mapped[str] = mapped_column(Text, nullable=False)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = _created_at()


class UserSession(Base):
    """A server-side login session (BFF; ADR-0005 / spec 008).

    The browser holds only the ``__Host-khandaq_session`` cookie carrying this row's id — never an
    OIDC token. ``csrf`` is the double-submit token checked on state-changing requests.
    """

    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("ses"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    csrf: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
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
    deny: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
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
    # The campaign that scheduled this run, if any (spec 016). Migration 0008.
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"))
    __table_args__ = (
        CheckConstraint(
            "state in ('queued','running','succeeded','failed','rejected')",
            name="ck_runs_state",
        ),
        Index("ix_runs_campaign_created", "campaign_id", "created_at"),
    )


class Campaign(Base):
    """A run template re-run every ``interval_minutes`` by the worker (spec 016, ADR-0017)."""

    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("cmp"))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    adapter: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    next_run_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (
        CheckConstraint("interval_minutes > 0", name="ck_campaigns_interval"),
        Index("ix_campaigns_due", "enabled", "next_run_at"),
    )


class CampaignDiff(Base):
    """What a successful campaign run changed against the campaign's earlier runs (spec 016).
    Append-only (trigger, migration 0008)."""

    __tablename__ = "campaign_diffs"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: new_id("dif"))
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False, unique=True)
    previous_run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"))
    baseline: Mapped[bool] = mapped_column(Boolean, nullable=False)
    new: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    regressed: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    resolved: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    unchanged_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    worsened: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()
    __table_args__ = (Index("ix_campaign_diffs_campaign_created", "campaign_id", "created_at"),)


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
        # One canonical finding per fingerprint per engagement (cross-run dedup, ADR-0003);
        # later sightings are non-canonical rows linked via dedup_of. Migration 0003.
        Index(
            "uq_findings_canonical_fingerprint",
            "engagement_id",
            "fingerprint",
            unique=True,
            postgresql_where=text("canonical"),
        ),
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
    # Entry format (ADR-0014): 1 seals the artefact's sha256 alone; 2 seals the evidence row's
    # metadata too. Rows written before migration 0005 are 1; new rows take the core's format.
    format: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="2")
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
    __table_args__ = (
        # Per-engagement action lookups, e.g. "did this instance export this report pin?" (spec
        # 013). Migration 0007.
        Index("ix_audit_log_engagement_action", "engagement_id", "action"),
    )
