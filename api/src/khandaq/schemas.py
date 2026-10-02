"""Pydantic request/response models for the engagement API (spec 002)."""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

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


class ScopeCheckOut(BaseModel):
    allowed: bool
    reason: str | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    actor_user_id: str | None
    actor_token_id: str | None
    action: str
    engagement_id: str | None
    detail: dict[str, Any]
    at: dt.datetime
