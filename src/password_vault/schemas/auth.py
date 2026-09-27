"""Pydantic schemas for vault authentication."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class MasterPasswordRequest(BaseModel):
    """Request containing a master password."""

    model_config = ConfigDict(
        str_strip_whitespace=False,
        extra="forbid",
    )

    master_password: str = Field(
        ...,
        min_length=12,
        description="The vault master password.",
    )


class AuthenticationResponse(BaseModel):
    """Response returned after an authentication operation."""

    authenticated: bool = Field(
        ...,
        description="Whether the request resulted in authentication.",
    )

    message: str = Field(
        ...,
        description="Human-readable authentication status.",
    )


class SessionStatusResponse(BaseModel):
    """Response describing the current authentication session."""

    authenticated: bool = Field(
        ...,
        description="Whether the current session is authenticated.",
    )

    expires_at: str | None = Field(
        default=None,
        description="UTC session expiration timestamp.",
    )


__all__ = [
    "AuthenticationResponse",
    "MasterPasswordRequest",
    "SessionStatusResponse",
]
