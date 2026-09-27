"""Pydantic schemas for audit-event API operations."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    """Safe representation of a vault audit event."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    description: str
    credential_id: int | None
    ip_address: str | None
    user_agent: str | None
    success: bool
    created_at: datetime


class AuditEventListResponse(BaseModel):
    """Response containing recent audit events."""

    items: list[AuditEventResponse]
    count: int


__all__ = [
    "AuditEventListResponse",
    "AuditEventResponse",
]
