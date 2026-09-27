"""FastAPI dependencies and application state for the password vault."""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from password_vault.auth.session import (
    InvalidSessionError,
    SessionExpiredError,
    VaultSession,
    VaultSessionManager,
)
from password_vault.database import SessionLocal


SESSION_COOKIE_NAME = "vault_session"


class ApplicationState:
    """Application-wide state shared by FastAPI requests."""

    def __init__(self) -> None:
        self.session_manager = VaultSessionManager()


def get_application_state(request: Request) -> ApplicationState:
    """Return the application state attached during startup."""
    state = getattr(request.app.state, "vault", None)

    if not isinstance(state, ApplicationState):
        raise RuntimeError("Vault application state has not been initialized.")

    return state


def get_session_manager(
    request: Request,
) -> VaultSessionManager:
    """Return the application's shared session manager."""
    return get_application_state(request).session_manager


def get_db() -> Generator[Session, None, None]:
    """Provide a database session for a FastAPI request."""
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def get_current_session(
    request: Request,
    session_manager: VaultSessionManager = Depends(get_session_manager),
) -> VaultSession:
    """Return the authenticated vault session for the current request.

    This dependency is intended for protected API endpoints. The session
    is touched only when a protected operation actually uses it.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    try:
        return session_manager.get_session(
            session_id,
            touch=True,
        )
    except (InvalidSessionError, SessionExpiredError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Vault session is invalid or expired.",
        ) from exc


__all__ = [
    "ApplicationState",
    "SESSION_COOKIE_NAME",
    "get_application_state",
    "get_current_session",
    "get_db",
    "get_session_manager",
]
