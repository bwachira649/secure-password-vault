"""Tests for password generation and strength analysis."""

from __future__ import annotations

import string

import pytest

from password_vault.services.password_security import (
    DEFAULT_PASSWORD_LENGTH,
    MAX_GENERATED_PASSWORD_LENGTH,
    MIN_GENERATED_PASSWORD_LENGTH,
    PasswordGenerationError,
    PasswordSecurityError,
    analyze_password,
    generate_password,
)


def test_generate_password_uses_default_length() -> None:
    password = generate_password()

    assert len(password) == DEFAULT_PASSWORD_LENGTH


def test_generate_password_meets_all_enabled_character_classes() -> None:
    password = generate_password(length=32)

    assert any(character.islower() for character in password)
    assert any(character.isupper() for character in password)
    assert any(character.isdigit() for character in password)
    assert any(
        character in "!@#$%^&*()-_=+[]{}:,.?/"
        for character in password
    )


def test_generate_password_respects_disabled_character_classes() -> None:
    password = generate_password(
        length=24,
        include_lowercase=True,
        include_uppercase=False,
        include_digits=False,
        include_symbols=False,
    )

    assert len(password) == 24
    assert all(character in string.ascii_lowercase for character in password)


def test_generate_password_can_use_only_digits() -> None:
    password = generate_password(
        length=24,
        include_lowercase=False,
        include_uppercase=False,
        include_digits=True,
        include_symbols=False,
    )

    assert len(password) == 24
    assert all(character in string.digits for character in password)


def test_generate_password_rejects_length_below_minimum() -> None:
    with pytest.raises(PasswordGenerationError):
        generate_password(length=MIN_GENERATED_PASSWORD_LENGTH - 1)


def test_generate_password_rejects_length_above_maximum() -> None:
    with pytest.raises(PasswordGenerationError):
        generate_password(length=MAX_GENERATED_PASSWORD_LENGTH + 1)


def test_generate_password_requires_at_least_one_character_class() -> None:
    with pytest.raises(
        PasswordGenerationError,
        match="At least one character class",
    ):
        generate_password(
            length=24,
            include_lowercase=False,
            include_uppercase=False,
            include_digits=False,
            include_symbols=False,
        )


def test_generate_password_is_random() -> None:
    first = generate_password(length=32)
    second = generate_password(length=32)

    assert first != second


def test_analyze_password_rejects_empty_password() -> None:
    with pytest.raises(
        PasswordSecurityError,
        match="Password cannot be empty",
    ):
        analyze_password("")


def test_analyze_password_rejects_non_string_input() -> None:
    with pytest.raises(
        PasswordSecurityError,
        match="Password must be a string",
    ):
        analyze_password(None)  # type: ignore[arg-type]


def test_analyze_strong_password() -> None:
    result = analyze_password(
        "vQ7$kP2!xR9@Lm4#tY8&nC6?"
    )

    assert result.strength == "strong"
    assert result.score >= 80
    assert result.length == 24
    assert result.entropy_bits > 80
    assert result.has_lowercase is True
    assert result.has_uppercase is True
    assert result.has_digits is True
    assert result.has_symbols is True
    assert result.is_common_password is False
    assert result.has_repeated_characters is False
    assert result.has_sequential_pattern is False


def test_analyze_common_password() -> None:
    result = analyze_password("password123")

    assert result.is_common_password is True
    assert result.strength == "weak"
    assert any(
        "common passwords" in message
        for message in result.feedback
    )


def test_analyze_repeated_characters() -> None:
    result = analyze_password("SecurePasswordAAA123!")

    assert result.has_repeated_characters is True
    assert any(
        "repeating" in message
        for message in result.feedback
    )


def test_analyze_sequential_pattern() -> None:
    result = analyze_password("SecurePassword1234!")

    assert result.has_sequential_pattern is True
    assert any(
        "sequential" in message
        for message in result.feedback
    )


def test_analyze_missing_character_classes_provides_feedback() -> None:
    result = analyze_password("onlylowercasepassword")

    assert result.has_lowercase is True
    assert result.has_uppercase is False
    assert result.has_digits is False
    assert result.has_symbols is False

    assert any(
        "uppercase" in message.lower()
        for message in result.feedback
    )
    assert any(
        "numbers" in message.lower()
        for message in result.feedback
    )
    assert any(
        "symbols" in message.lower()
        for message in result.feedback
    )


def test_analysis_does_not_store_password() -> None:
    password = "ThisIsASecretPassword123!"

    result = analyze_password(password)

    assert password not in result.feedback
    assert not hasattr(result, "password")


def test_entropy_increases_with_character_diversity() -> None:
    simple = analyze_password("aaaaaaaaaaaaaaaa")
    diverse = analyze_password("aA7!aA7!aA7!aA7!")

    assert diverse.entropy_bits > simple.entropy_bits


def test_generated_password_can_be_analyzed() -> None:
    password = generate_password(length=32)
    result = analyze_password(password)

    assert result.length == 32
    assert result.has_lowercase is True
    assert result.has_uppercase is True
    assert result.has_digits is True
    assert result.has_symbols is True
    assert result.entropy_bits > 80
