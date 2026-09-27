"""Pydantic schemas for encrypted vault transfer operations."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, SecretStr


MAX_EXPORT_DATA_LENGTH = 10 * 1024 * 1024


class ExportRequest(BaseModel):
    """Request to create an encrypted vault export."""

    model_config = ConfigDict(extra="forbid")

    export_password: SecretStr = Field(
        min_length=12,
        max_length=512,
        description="Password used to encrypt the exported vault.",
    )


class ExportResponse(BaseModel):
    """Response containing an encrypted vault export."""

    model_config = ConfigDict(extra="forbid")

    format: str
    version: int
    filename: str
    export_data: str


class ImportRequest(BaseModel):
    """Request to restore credentials from an encrypted vault export."""

    model_config = ConfigDict(extra="forbid")

    export_password: SecretStr = Field(
        min_length=12,
        max_length=512,
        description="Password used to decrypt the exported vault.",
    )

    export_data: str = Field(
        min_length=1,
        max_length=MAX_EXPORT_DATA_LENGTH,
        description="Encrypted vault export document.",
    )


class ImportResponse(BaseModel):
    """Response describing an encrypted vault import."""

    model_config = ConfigDict(extra="forbid")

    imported_count: int
    message: str


__all__ = [
    "ExportRequest",
    "ExportResponse",
    "ImportRequest",
    "ImportResponse",
    "MAX_EXPORT_DATA_LENGTH",
]
