"""Pydantic schemas for password-security API operations."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PasswordGenerationRequest(BaseModel):
    """Request parameters for secure password generation."""

    model_config = ConfigDict(extra="forbid")

    length: int = Field(
        default=24,
        ge=16,
        le=128,
        description="Generated password length.",
    )
    include_lowercase: bool = Field(
        default=True,
        description="Include lowercase letters.",
    )
    include_uppercase: bool = Field(
        default=True,
        description="Include uppercase letters.",
    )
    include_digits: bool = Field(
        default=True,
        description="Include digits.",
    )
    include_symbols: bool = Field(
        default=True,
        description="Include symbols.",
    )


class PasswordGenerationResponse(BaseModel):
    """Response containing a generated password."""

    password: str
    length: int


class PasswordAnalysisRequest(BaseModel):
    """Request containing a password for strength analysis."""

    model_config = ConfigDict(extra="forbid")

    password: str = Field(
        min_length=1,
        max_length=1024,
        description="Password to analyze.",
    )


class PasswordAnalysisResponse(BaseModel):
    """Safe password-strength analysis response."""

    score: int
    strength: str
    length: int
    entropy_bits: float
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    is_common_password: bool
    has_repeated_characters: bool
    has_sequential_pattern: bool
    feedback: list[str]


__all__ = [
    "PasswordAnalysisRequest",
    "PasswordAnalysisResponse",
    "PasswordGenerationRequest",
    "PasswordGenerationResponse",
]
