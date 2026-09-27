"""Protected credential API routes for the secure password vault."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from password_vault.api.dependencies import (
    get_current_session,
    get_db,
)
from password_vault.auth.session import VaultSession
from password_vault.schemas import (
    CredentialCreateRequest,
    CredentialListResponse,
    CredentialOperationResponse,
    CredentialPasswordResponse,
    CredentialResponse,
    CredentialUpdateRequest,
)
from password_vault.services.vault_service import (
    UPDATE_UNSET,
    CredentialNotFoundError,
    VaultService,
    VaultServiceError,
)


router = APIRouter(
    prefix="/api/v1/credentials",
    tags=["Credentials"],
)


def _credential_response(credential) -> CredentialResponse:
    """Convert a database credential into a safe API response."""
    return CredentialResponse.model_validate(credential)


@router.get(
    "",
    response_model=CredentialListResponse,
    summary="List credentials",
)
def list_credentials(
    search: str | None = Query(
        default=None,
        description="Search name, username, category, or URL.",
    ),
    category: str | None = Query(
        default=None,
        description="Filter credentials by category.",
    ),
    favorites_only: bool = Query(
        default=False,
        description="Return only favorite credentials.",
    ),
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> CredentialListResponse:
    """Return credential metadata without decrypting passwords."""
    service = VaultService(db)

    credentials = service.list_credentials(
        search=search,
        category=category,
        favorites_only=favorites_only,
    )

    return CredentialListResponse(
        items=[
            _credential_response(credential)
            for credential in credentials
        ],
        count=len(credentials),
    )


@router.post(
    "",
    response_model=CredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a credential",
)
def create_credential(
    request: CredentialCreateRequest,
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> CredentialResponse:
    """Create a new encrypted credential."""
    service = VaultService(db)

    try:
        credential = service.create_credential(
            session.encryption_key,
            name=request.name,
            username=request.username,
            password=request.password,
            url=request.url,
            category=request.category,
            notes=request.notes,
            expires_at=request.expires_at,
            is_favorite=request.is_favorite,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except VaultServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create credential.",
        ) from exc

    return _credential_response(credential)


@router.get(
    "/{credential_id}",
    response_model=CredentialResponse,
    summary="Get credential metadata",
)
def get_credential(
    credential_id: int,
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> CredentialResponse:
    """Return credential metadata without decrypting its password."""
    service = VaultService(db)

    try:
        credential = service.get_credential(credential_id)
    except CredentialNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found.",
        ) from exc

    return _credential_response(credential)


@router.get(
    "/{credential_id}/password",
    response_model=CredentialPasswordResponse,
    summary="Reveal a credential password",
)
def get_credential_password(
    credential_id: int,
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> CredentialPasswordResponse:
    """Decrypt and return a credential password."""
    service = VaultService(db)

    try:
        password = service.decrypt_credential_password(
            session.encryption_key,
            credential_id,
        )
    except CredentialNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found.",
        ) from exc
    except VaultServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to decrypt credential password.",
        ) from exc

    return CredentialPasswordResponse(
        password=password,
    )


@router.put(
    "/{credential_id}",
    response_model=CredentialResponse,
    summary="Update a credential",
)
def update_credential(
    credential_id: int,
    request: CredentialUpdateRequest,
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> CredentialResponse:
    """Update credential metadata or replace its encrypted password."""
    service = VaultService(db)

    fields = request.model_fields_set

    update_kwargs = {
        "name": request.name if "name" in fields else UPDATE_UNSET,
        "username": (
            request.username
            if "username" in fields
            else UPDATE_UNSET
        ),
        "password": (
            request.password
            if "password" in fields
            else UPDATE_UNSET
        ),
        "url": request.url if "url" in fields else UPDATE_UNSET,
        "category": (
            request.category
            if "category" in fields
            else UPDATE_UNSET
        ),
        "notes": request.notes if "notes" in fields else UPDATE_UNSET,
        "expires_at": (
            request.expires_at
            if "expires_at" in fields
            else UPDATE_UNSET
        ),
        "is_favorite": (
            request.is_favorite
            if "is_favorite" in fields
            else UPDATE_UNSET
        ),
    }

    try:
        credential = service.update_credential(
            session.encryption_key,
            credential_id,
            **update_kwargs,
        )
    except CredentialNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except VaultServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to update credential.",
        ) from exc

    return _credential_response(credential)


@router.delete(
    "/{credential_id}",
    response_model=CredentialOperationResponse,
    summary="Delete a credential",
)
def delete_credential(
    credential_id: int,
    session: VaultSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> CredentialOperationResponse:
    """Delete a credential."""
    service = VaultService(db)

    try:
        service.delete_credential(credential_id)
    except CredentialNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found.",
        ) from exc

    return CredentialOperationResponse(
        message="Credential deleted successfully.",
        credential=None,
    )


__all__ = ["router"]
