"""Pydantic schemas for credential API operations."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CredentialCreateRequest(BaseModel):
    """Request for creating a new credential."""

    model_config = ConfigDict(
        str_strip_whitespace=False,
        extra="forbid",
    )

    name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Human-readable credential name.",
    )

    username: str = Field(
        ...,
        min_length=1,
        description="Username or account identifier.",
    )

    password: str = Field(
        ...,
        min_length=1,
        description="Credential password.",
    )

    url: str | None = Field(
        default=None,
        max_length=2048,
        description="Optional service or login URL.",
    )

    category: str = Field(
        default="General",
        min_length=1,
        max_length=100,
        description="Credential category.",
    )

    notes: str | None = Field(
        default=None,
        description="Optional private notes.",
    )

    expires_at: datetime | None = Field(
        default=None,
        description="Optional UTC expiration timestamp.",
    )

    is_favorite: bool = Field(
        default=False,
        description="Whether the credential is marked as a favorite.",
    )


class CredentialUpdateRequest(BaseModel):
    """Request for updating an existing credential.

    An omitted field means "leave unchanged".
    An explicitly supplied null clears nullable fields.
    """

    model_config = ConfigDict(
        str_strip_whitespace=False,
        extra="forbid",
    )

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="Updated credential name.",
    )

    username: str | None = Field(
        default=None,
        min_length=1,
        description="Updated username or account identifier.",
    )

    password: str | None = Field(
        default=None,
        min_length=1,
        description="Replacement credential password.",
    )

    url: str | None = Field(
        default=None,
        max_length=2048,
        description="Updated service or login URL. Null clears the URL.",
    )

    category: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Updated credential category.",
    )

    notes: str | None = Field(
        default=None,
        description="Updated private notes. Null clears the notes.",
    )

    expires_at: datetime | None = Field(
        default=None,
        description=(
            "Updated UTC expiration timestamp. "
            "Null clears the expiration date."
        ),
    )

    is_favorite: bool | None = Field(
        default=None,
        description="Updated favorite status.",
    )


class CredentialResponse(BaseModel):
    """Safe credential representation that never exposes the password."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    username: str
    url: str | None
    category: str
    notes: str | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
    last_accessed_at: datetime | None
    is_favorite: bool


class CredentialPasswordResponse(BaseModel):
    """Response containing a deliberately requested credential password."""

    password: str = Field(
        ...,
        description="Decrypted credential password.",
    )


class CredentialListResponse(BaseModel):
    """Paginated-style response for credential listings."""

    items: list[CredentialResponse]
    count: int


class CredentialOperationResponse(BaseModel):
    """Response for credential mutation operations."""

    message: str
    credential: CredentialResponse | None = None


__all__ = [
    "CredentialCreateRequest",
    "CredentialListResponse",
    "CredentialOperationResponse",
    "CredentialPasswordResponse",
    "CredentialResponse",
    "CredentialUpdateRequest",
]
