"""Protected password-security API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from password_vault.api.dependencies import get_current_session
from password_vault.auth.session import VaultSession
from password_vault.schemas import (
    PasswordAnalysisRequest,
    PasswordAnalysisResponse,
    PasswordGenerationRequest,
    PasswordGenerationResponse,
)
from password_vault.services.password_security import (
    PasswordSecurityError,
    analyze_password,
    generate_password,
)


router = APIRouter(
    prefix="/api/v1/security",
    tags=["Security"],
)


@router.post(
    "/generate-password",
    response_model=PasswordGenerationResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate a secure password",
)
def generate_secure_password(
    request: PasswordGenerationRequest,
    session: VaultSession = Depends(get_current_session),
) -> PasswordGenerationResponse:
    """Generate a cryptographically secure random password."""
    _ = session

    try:
        password = generate_password(
            length=request.length,
            include_lowercase=request.include_lowercase,
            include_uppercase=request.include_uppercase,
            include_digits=request.include_digits,
            include_symbols=request.include_symbols,
        )
    except PasswordSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return PasswordGenerationResponse(
        password=password,
        length=len(password),
    )


@router.post(
    "/analyze-password",
    response_model=PasswordAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze password strength",
)
def analyze_password_strength(
    request: PasswordAnalysisRequest,
    session: VaultSession = Depends(get_current_session),
) -> PasswordAnalysisResponse:
    """Analyze password strength without storing or logging the password."""
    _ = session

    try:
        analysis = analyze_password(request.password)
    except PasswordSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return PasswordAnalysisResponse(
        score=analysis.score,
        strength=analysis.strength,
        length=analysis.length,
        entropy_bits=analysis.entropy_bits,
        has_lowercase=analysis.has_lowercase,
        has_uppercase=analysis.has_uppercase,
        has_digits=analysis.has_digits,
        has_symbols=analysis.has_symbols,
        is_common_password=analysis.is_common_password,
        has_repeated_characters=analysis.has_repeated_characters,
        has_sequential_pattern=analysis.has_sequential_pattern,
        feedback=list(analysis.feedback),
    )


__all__ = ["router"]
