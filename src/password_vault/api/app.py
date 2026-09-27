"""FastAPI application for the secure password vault."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from password_vault.api.audit import router as audit_router
from password_vault.api.auth import router as auth_router
from password_vault.api.credentials import router as credentials_router
from password_vault.api.dependencies import ApplicationState
from password_vault.api.security import router as security_router
from password_vault.api.transfer import router as transfer_router
from password_vault.database import init_database


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize application resources during startup."""
    init_database()
    app.state.vault = ApplicationState()

    yield

    app.state.vault = None


app = FastAPI(
    title="Secure Password Vault API",
    description=(
        "A secure credential vault API with encrypted storage, "
        "master-password authentication, session management, "
        "audit logging, password security analysis, protected "
        "credential operations, and encrypted vault transfer."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(credentials_router)
app.include_router(audit_router)
app.include_router(security_router)
app.include_router(transfer_router)


@app.get(
    "/health",
    tags=["System"],
    summary="Health check",
)
def health_check() -> JSONResponse:
    """Return the health status of the application."""
    return JSONResponse(
        content={
            "status": "healthy",
            "service": "secure-password-vault",
            "version": app.version,
        }
    )


@app.get(
    "/",
    tags=["System"],
    summary="Application information",
)
def application_info() -> dict[str, str]:
    """Return basic application information."""
    return {
        "name": "Secure Password Vault API",
        "version": app.version,
        "status": "operational",
        "docs": "/docs",
        "health": "/health",
    }


__all__ = ["app"]
