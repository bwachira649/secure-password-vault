"""Password generation and strength analysis services."""

from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass
from typing import Final


DEFAULT_PASSWORD_LENGTH: Final[int] = 24
MIN_GENERATED_PASSWORD_LENGTH: Final[int] = 16
MAX_GENERATED_PASSWORD_LENGTH: Final[int] = 128

LOW_ENTROPY_THRESHOLD: Final[float] = 50.0
STRONG_ENTROPY_THRESHOLD: Final[float] = 80.0

UPPERCASE_CHARACTERS: Final[str] = string.ascii_uppercase
LOWERCASE_CHARACTERS: Final[str] = string.ascii_lowercase
DIGIT_CHARACTERS: Final[str] = string.digits
SYMBOL_CHARACTERS: Final[str] = "!@#$%^&*()-_=+[]{}:,.?/"
DEFAULT_ALPHABET: Final[str] = (
    UPPERCASE_CHARACTERS
    + LOWERCASE_CHARACTERS
    + DIGIT_CHARACTERS
    + SYMBOL_CHARACTERS
)

SEQUENTIAL_PATTERNS: Final[tuple[str, ...]] = (
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

COMMON_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "letmein",
        "welcome",
        "admin",
        "admin123",
        "administrator",
        "root",
        "changeme",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
        "abc123",
    }
)

REPEATED_CHARACTER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(.)\1{2,}",
)

SEQUENTIAL_LENGTH: Final[int] = 4


@dataclass(frozen=True, slots=True)
class PasswordAnalysis:
    """Result of analyzing a password."""

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
    feedback: tuple[str, ...]


class PasswordSecurityError(ValueError):
    """Base exception for password-security operations."""


class PasswordGenerationError(PasswordSecurityError):
    """Raised when a password cannot be generated from the requested rules."""


def generate_password(
    *,
    length: int = DEFAULT_PASSWORD_LENGTH,
    include_lowercase: bool = True,
    include_uppercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
) -> str:
    """Generate a cryptographically secure random password.

    Each enabled character class is guaranteed to appear at least once.
    """
    if (
        length < MIN_GENERATED_PASSWORD_LENGTH
        or length > MAX_GENERATED_PASSWORD_LENGTH
    ):
        raise PasswordGenerationError(
            f"Password length must be between "
            f"{MIN_GENERATED_PASSWORD_LENGTH} and "
            f"{MAX_GENERATED_PASSWORD_LENGTH}."
        )

    character_sets: list[str] = []

    if include_lowercase:
        character_sets.append(LOWERCASE_CHARACTERS)

    if include_uppercase:
        character_sets.append(UPPERCASE_CHARACTERS)

    if include_digits:
        character_sets.append(DIGIT_CHARACTERS)

    if include_symbols:
        character_sets.append(SYMBOL_CHARACTERS)

    if not character_sets:
        raise PasswordGenerationError(
            "At least one character class must be enabled."
        )

    if length < len(character_sets):
        raise PasswordGenerationError(
            "Password length is too short for the selected character classes."
        )

    password_characters = [
        secrets.choice(character_set)
        for character_set in character_sets
    ]

    alphabet = "".join(character_sets)

    password_characters.extend(
        secrets.choice(alphabet)
        for _ in range(length - len(password_characters))
    )

    secrets.SystemRandom().shuffle(password_characters)

    return "".join(password_characters)


def analyze_password(password: str) -> PasswordAnalysis:
    """Analyze password strength without storing or logging the password."""
    if not isinstance(password, str):
        raise PasswordSecurityError("Password must be a string.")

    if not password:
        raise PasswordSecurityError("Password cannot be empty.")

    length = len(password)

    has_lowercase = any(character.islower() for character in password)
    has_uppercase = any(character.isupper() for character in password)
    has_digits = any(character.isdigit() for character in password)
    has_symbols = any(
        not character.isalnum()
        for character in password
    )

    character_pool_size = 0

    if has_lowercase:
        character_pool_size += len(LOWERCASE_CHARACTERS)

    if has_uppercase:
        character_pool_size += len(UPPERCASE_CHARACTERS)

    if has_digits:
        character_pool_size += len(DIGIT_CHARACTERS)

    if has_symbols:
        character_pool_size += len(SYMBOL_CHARACTERS)

    entropy_bits = 0.0

    if character_pool_size:
        entropy_bits = length * math.log2(character_pool_size)

    normalized_password = password.casefold()

    is_common_password = (
        normalized_password in COMMON_PASSWORDS
    )

    has_repeated_characters = bool(
        REPEATED_CHARACTER_PATTERN.search(password)
    )

    has_sequential_pattern = _contains_sequential_pattern(
        normalized_password
    )

    score = _calculate_score(
        length=length,
        entropy_bits=entropy_bits,
        has_lowercase=has_lowercase,
        has_uppercase=has_uppercase,
        has_digits=has_digits,
        has_symbols=has_symbols,
        is_common_password=is_common_password,
        has_repeated_characters=has_repeated_characters,
        has_sequential_pattern=has_sequential_pattern,
    )

    feedback = _build_feedback(
        length=length,
        entropy_bits=entropy_bits,
        has_lowercase=has_lowercase,
        has_uppercase=has_uppercase,
        has_digits=has_digits,
        has_symbols=has_symbols,
        is_common_password=is_common_password,
        has_repeated_characters=has_repeated_characters,
        has_sequential_pattern=has_sequential_pattern,
    )

    return PasswordAnalysis(
        score=score,
        strength=_strength_label(score),
        length=length,
        entropy_bits=round(entropy_bits, 2),
        has_lowercase=has_lowercase,
        has_uppercase=has_uppercase,
        has_digits=has_digits,
        has_symbols=has_symbols,
        is_common_password=is_common_password,
        has_repeated_characters=has_repeated_characters,
        has_sequential_pattern=has_sequential_pattern,
        feedback=tuple(feedback),
    )


def _calculate_score(
    *,
    length: int,
    entropy_bits: float,
    has_lowercase: bool,
    has_uppercase: bool,
    has_digits: bool,
    has_symbols: bool,
    is_common_password: bool,
    has_repeated_characters: bool,
    has_sequential_pattern: bool,
) -> int:
    """Calculate a deterministic password-strength score."""
    score = 0

    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 8:
        score += 12
    elif length >= 6:
        score += 5

    character_classes = sum(
        (
            has_lowercase,
            has_uppercase,
            has_digits,
            has_symbols,
        )
    )

    score += character_classes * 10

    if entropy_bits >= STRONG_ENTROPY_THRESHOLD:
        score += 20
    elif entropy_bits >= LOW_ENTROPY_THRESHOLD:
        score += 12
    elif entropy_bits >= 35:
        score += 6

    if is_common_password:
        score -= 45

    if has_repeated_characters:
        score -= 10

    if has_sequential_pattern:
        score -= 10

    return max(0, min(100, score))


def _strength_label(score: int) -> str:
    """Convert a numeric score into a strength label."""
    if score >= 80:
        return "strong"

    if score >= 60:
        return "good"

    if score >= 40:
        return "fair"

    return "weak"


def _contains_sequential_pattern(password: str) -> bool:
    """Detect ascending or descending runs of four characters."""
    if len(password) < SEQUENTIAL_LENGTH:
        return False

    for pattern in SEQUENTIAL_PATTERNS:
        for index in range(
            len(pattern) - SEQUENTIAL_LENGTH + 1
        ):
            sequence = pattern[
                index : index + SEQUENTIAL_LENGTH
            ]

            if sequence in password:
                return True

            if sequence[::-1] in password:
                return True

    return False


def _build_feedback(
    *,
    length: int,
    entropy_bits: float,
    has_lowercase: bool,
    has_uppercase: bool,
    has_digits: bool,
    has_symbols: bool,
    is_common_password: bool,
    has_repeated_characters: bool,
    has_sequential_pattern: bool,
) -> list[str]:
    """Build actionable password-strength feedback."""
    feedback: list[str] = []

    if length < 16:
        feedback.append(
            "Use at least 16 characters for a stronger password."
        )

    if not has_lowercase:
        feedback.append(
            "Add lowercase letters."
        )

    if not has_uppercase:
        feedback.append(
            "Add uppercase letters."
        )

    if not has_digits:
        feedback.append(
            "Add numbers."
        )

    if not has_symbols:
        feedback.append(
            "Add symbols."
        )

    if is_common_password:
        feedback.append(
            "Avoid common passwords and well-known password patterns."
        )

    if has_repeated_characters:
        feedback.append(
            "Avoid repeating the same character three or more times."
        )

    if has_sequential_pattern:
        feedback.append(
            "Avoid sequential keyboard or character patterns."
        )

    if entropy_bits < LOW_ENTROPY_THRESHOLD:
        feedback.append(
            "Increase password length and character diversity."
        )

    if not feedback:
        feedback.append(
            "Password has good length and character diversity."
        )

    return feedback


__all__ = [
    "DEFAULT_PASSWORD_LENGTH",
    "MAX_GENERATED_PASSWORD_LENGTH",
    "MIN_GENERATED_PASSWORD_LENGTH",
    "PasswordAnalysis",
    "PasswordGenerationError",
    "PasswordSecurityError",
    "analyze_password",
    "generate_password",
]
