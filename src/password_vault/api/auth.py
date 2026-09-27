"""Authentication API routes for the secure password vault."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from password_vault.api.dependencies import (
    SESSION_COOKIE_NAME,
    get_db,
    get_session_manager,
)
from password_vault.auth.session import (
    InvalidSessionError,
    SessionExpiredError,
    VaultSessionManager,
)
from password_vault.schemas import (
    AuthenticationResponse,
    MasterPasswordRequest,
    SessionStatusResponse,
)
from password_vault.services.vault_service import (
    InvalidMasterPasswordError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    VaultService,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


SESSION_COOKIE_HTTP_ONLY = True
SESSION_COOKIE_SAMESITE = "strict"
SESSION_COOKIE_SECURE = False


@router.post(
    "/initialize",
    response_model=AuthenticationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initialize the vault",
)
def initialize_vault(
    request: MasterPasswordRequest,
    db: Session = Depends(get_db),
) -> AuthenticationResponse:
    service = VaultService(db)

    try:
        service.initialize_vault(request.master_password)
    except VaultAlreadyInitializedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault is already initialized.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return AuthenticationResponse(
        authenticated=False,
        message="Vault initialized successfully. Please log in.",
    )


@router.post(
    "/login",
    response_model=AuthenticationResponse,
    summary="Authenticate to the vault",
)
def login(
    request: MasterPasswordRequest,
    response: Response,
    session_manager: VaultSessionManager = Depends(get_session_manager),
    db: Session = Depends(get_db),
) -> AuthenticationResponse:
    service = VaultService(db)

    try:
        encryption_key = service.authenticate(request.master_password)
    except VaultNotInitializedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault has not been initialized.",
        ) from exc
    except InvalidMasterPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password.",
        ) from exc

    session = session_manager.create_session(encryption_key)

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session.session_id,
        httponly=SESSION_COOKIE_HTTP_ONLY,
        samesite=SESSION_COOKIE_SAMESITE,
        secure=SESSION_COOKIE_SECURE,
        max_age=session_manager.timeout_minutes * 60,
        path="/",
    )

    return AuthenticationResponse(
        authenticated=True,
        message="Authentication successful.",
    )


@router.post(
    "/logout",
    response_model=AuthenticationResponse,
    summary="Lock the current vault session",
)
def logout(
    request: Request,
    response: Response,
    session_manager: VaultSessionManager = Depends(get_session_manager),
) -> AuthenticationResponse:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if session_id:
        try:
            session_manager.lock_session(session_id)
        except (InvalidSessionError, SessionExpiredError):
            pass

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
    )

    return AuthenticationResponse(
        authenticated=False,
        message="Vault session locked.",
    )


@router.get(
    "/status",
    response_model=SessionStatusResponse,
    summary="Check authentication status",
)
def authentication_status(
    request: Request,
    session_manager: VaultSessionManager = Depends(get_session_manager),
) -> SessionStatusResponse:
    """Return whether current request has valid vault session.

    Status checks intentionally do not refresh inactivity timeout.
    Actual protected vault operations are responsible for session activity.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        return SessionStatusResponse(
            authenticated=False,
            expires_at=None,
        )

    try:
        session = session_manager.get_session(
            session_id,
            touch=False,
        )
    except (InvalidSessionError, SessionExpiredError):
        return SessionStatusResponse(
            authenticated=False,
            expires_at=None,
        )

    return SessionStatusResponse(
        authenticated=True,
        expires_at=session.expires_at.isoformat(),
    )


__all__ = ["router"]
