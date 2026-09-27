"""Protected encrypted vault transfer API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from password_vault.api.dependencies import get_current_session, get_db
from password_vault.auth.session import VaultSession
from password_vault.schemas import (
    ExportRequest,
    ExportResponse,
    ImportRequest,
    ImportResponse,
)
from password_vault.services.import_export import (
    EXPORT_FORMAT,
    EXPORT_VERSION,
    InvalidExportFormatError,
    InvalidExportPasswordError,
    VaultExportError,
    VaultImportError,
    VaultImportExportService,
)
from password_vault.services.vault_service import VaultService


router = APIRouter(
    prefix="/api/v1/transfer",
    tags=["Transfer"],
)


EXPORT_FILENAME = "secure-password-vault-export.json"


def _request_ip_address(request: Request) -> str | None:
    """Return the client IP address when available."""
    if request.client is None:
        return None

    return request.client.host


def _request_user_agent(request: Request) -> str | None:
    """Return the request user-agent when available."""
    return request.headers.get("user-agent")


@router.post(
    "/export",
    response_model=ExportResponse,
    summary="Export the encrypted vault",
)
def export_vault(
    request: ExportRequest,
    http_request: Request,
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> ExportResponse:
    """Create a password-protected encrypted vault export."""
    service = VaultImportExportService(db)

    try:
        export_data = service.export_vault(
            session.encryption_key,
            request.export_password.get_secret_value(),
        )
    except InvalidExportPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except VaultExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create encrypted vault export.",
        ) from exc

    audit_service = VaultService(db)

    audit_service.record_event(
        event_type="vault_exported",
        description="Encrypted vault export created successfully.",
        ip_address=_request_ip_address(http_request),
        user_agent=_request_user_agent(http_request),
        success=True,
    )
    db.commit()

    return ExportResponse(
        format=EXPORT_FORMAT,
        version=EXPORT_VERSION,
        filename=EXPORT_FILENAME,
        export_data=export_data,
    )


@router.post(
    "/import",
    response_model=ImportResponse,
    summary="Import an encrypted vault",
)
def import_vault(
    request: ImportRequest,
    http_request: Request,
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> ImportResponse:
    """Import credentials from a password-protected encrypted export."""
    service = VaultImportExportService(db)

    try:
        imported_count = service.import_vault(
            session.encryption_key,
            request.export_password.get_secret_value(),
            request.export_data,
        )
    except InvalidExportPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except InvalidExportFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except VaultImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to import encrypted vault export.",
        ) from exc

    audit_service = VaultService(db)

    audit_service.record_event(
        event_type="vault_imported",
        description=(
            f"Encrypted vault import completed successfully. "
            f"{imported_count} credential(s) imported."
        ),
        ip_address=_request_ip_address(http_request),
        user_agent=_request_user_agent(http_request),
        success=True,
    )
    db.commit()

    return ImportResponse(
        imported_count=imported_count,
        message=(
            f"Encrypted vault import completed successfully. "
            f"{imported_count} credential(s) imported."
        ),
    )


__all__ = ["router"]
