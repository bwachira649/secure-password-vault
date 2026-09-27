"""Protected audit-event API routes for the secure password vault."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from password_vault.api.dependencies import get_current_session, get_db
from password_vault.auth.session import VaultSession
from password_vault.schemas import (
    AuditEventListResponse,
    AuditEventResponse,
)
from password_vault.services.vault_service import (
    VaultService,
    VaultServiceError,
)


router = APIRouter(
    prefix="/api/v1/audit",
    tags=["Audit"],
)


def _audit_event_response(event) -> AuditEventResponse:
    """Convert a database audit event into an API response."""
    return AuditEventResponse.model_validate(event)


@router.get(
    "/events",
    response_model=AuditEventListResponse,
    summary="List audit events",
)
def list_audit_events(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
        description="Maximum number of recent audit events to return.",
    ),
    event_type: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
        description="Optional exact audit event type filter.",
    ),
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> AuditEventListResponse:
    """Return recent security and vault activity."""
    service = VaultService(db)

    try:
        events = service.get_audit_events(
            limit=limit,
            event_type=event_type,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except VaultServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve audit events.",
        ) from exc

    return AuditEventListResponse(
        items=[
            _audit_event_response(event)
            for event in events
        ],
        count=len(events),
    )


__all__ = ["router"]
