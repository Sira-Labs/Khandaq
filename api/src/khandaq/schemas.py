"""Pydantic request/response models for the engagement API (spec 002)."""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

TargetType = Literal["llm_endpoint", "agent", "mcp_server", "model_artifact", "dataset"]


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client: str | None = None


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    client: str | None
    owner_user_id: str
    state: str
    authorisation_ref: str | None
    created_at: dt.datetime
    activated_at: dt.datetime | None
    closed_at: dt.datetime | None


class TargetCreate(BaseModel):
    type: TargetType
    spec: dict[str, Any]
    credential_ref: str | None = None


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    type: str
    spec: dict[str, Any]
    credential_ref: str | None


class ScopeIn(BaseModel):
    allow: dict[str, Any] = Field(default_factory=dict)
    deny: list[dict[str, Any]] = Field(default_factory=list)
    roe: dict[str, Any] = Field(default_factory=dict)


class ScopeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    engagement_id: str
    version: int
    allow: dict[str, Any]
    deny: list[dict[str, Any]]
    roe: dict[str, Any]
    locked: bool


class ActivateIn(BaseModel):
    authorisation_ref: str = Field(min_length=1)


class ScopeCheckIn(BaseModel):
    target_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    # With an adapter, the pre-flight also checks it can honour the rules of engagement (spec 027).
    adapter: str | None = None


class ScopeCheckOut(BaseModel):
    allowed: bool
    reason: str | None = None


class MemberOut(BaseModel):
    user_id: str
    role: str
    email: str | None = None


class AdapterOut(BaseModel):
    name: str
    version: str
    phases: list[str]
    frameworks: list[str]
    builtin: bool
    paces_requests: bool


class RunCreate(BaseModel):
    adapter: str
    target_id: str
    params: dict[str, Any] = Field(default_factory=dict)


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    adapter: str
    adapter_version: str | None
    target_id: str | None
    state: str
    reject_reason: str | None
    started_at: dt.datetime | None
    ended_at: dt.datetime | None
    created_at: dt.datetime
    campaign_id: str | None = None


class FindingOut(BaseModel):
    id: str
    fingerprint: str
    rule_id: str
    title: str | None
    severity: str
    confidence: str
    status: str
    phase: str | None = None
    mappings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    also_found_by: list[str] = Field(default_factory=list)


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    actor_user_id: str | None
    actor_token_id: str | None
    action: str
    engagement_id: str | None
    detail: dict[str, Any]
    at: dt.datetime


class ReportPin(BaseModel):
    """The ``evidence`` pin of an exported report, posted back for re-verification (spec 013).

    Extra keys (the report's ``verify`` block) are ignored, so the block can be posted as is. The
    count is a strict integer: ``"3"`` or ``3.0`` is a malformed pin, not a coercible one."""

    model_config = ConfigDict(extra="ignore")
    root: str | None = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    count: int = Field(strict=True, ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def _root_iff_entries(self) -> ReportPin:
        if (self.root is None) != (self.count == 0):
            raise ValueError("root is null exactly when count is 0")
        return self


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    adapter: str = Field(min_length=1, max_length=100)
    target_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    interval_minutes: int = Field(strict=True, gt=0, le=60 * 24 * 366)
    start_at: dt.datetime | None = None


class CampaignUpdate(BaseModel):
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, strict=True, gt=0, le=60 * 24 * 366)


class CampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    name: str
    adapter: str
    target_id: str
    params: dict[str, Any]
    interval_minutes: int
    enabled: bool
    next_run_at: dt.datetime
    created_by: str | None
    created_at: dt.datetime
    updated_at: dt.datetime


class DiffEntry(BaseModel):
    fingerprint: str
    finding_id: str
    rule_id: str
    severity: str
    title: str | None = None


class DiffOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    campaign_id: str
    run_id: str
    previous_run_id: str | None
    baseline: bool
    new: list[DiffEntry]
    regressed: list[DiffEntry]
    resolved: list[DiffEntry]
    unchanged_count: int
    findings_count: int
    worsened: bool
    created_at: dt.datetime
