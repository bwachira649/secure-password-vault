"""Tests for the password vault cryptographic primitives."""

import pytest

from password_vault.security.crypto import (
    KEY_LENGTH,
    SALT_LENGTH,
    CryptoError,
    EncryptionError,
    InvalidPasswordError,
    derive_encryption_key,
    decrypt_value,
    encrypt_value,
    generate_random_password,
    generate_salt,
    generate_secure_token,
    hash_master_password,
    needs_password_rehash,
    secure_compare,
    validate_master_password,
    verify_master_password,
)


MASTER_PASSWORD = "Correct-Horse-Battery-Staple-2026!"
PLAINTEXT = "SuperSecretCredentialValue"


def test_generate_salt_has_expected_length() -> None:
    salt = generate_salt()

    assert isinstance(salt, bytes)
    assert len(salt) == SALT_LENGTH


def test_generate_salts_are_unique() -> None:
    first = generate_salt()
    second = generate_salt()

    assert first != second


def test_master_password_validation_accepts_strong_password() -> None:
    validate_master_password(MASTER_PASSWORD)


def test_master_password_validation_rejects_short_password() -> None:
    with pytest.raises(InvalidPasswordError):
        validate_master_password("short")


def test_master_password_hash_verifies_correct_password() -> None:
    password_hash = hash_master_password(MASTER_PASSWORD)

    assert password_hash.startswith("$argon2")
    assert verify_master_password(password_hash, MASTER_PASSWORD)


def test_master_password_hash_rejects_wrong_password() -> None:
    password_hash = hash_master_password(MASTER_PASSWORD)

    assert not verify_master_password(password_hash, "Wrong-password-2026!")


def test_password_hashes_are_unique_for_same_password() -> None:
    first = hash_master_password(MASTER_PASSWORD)
    second = hash_master_password(MASTER_PASSWORD)

    assert first != second
    assert verify_master_password(first, MASTER_PASSWORD)
    assert verify_master_password(second, MASTER_PASSWORD)


def test_malformed_password_hash_fails_verification() -> None:
    assert not verify_master_password("not-an-argon2-hash", MASTER_PASSWORD)


def test_password_hash_rehash_check_accepts_valid_hash() -> None:
    password_hash = hash_master_password(MASTER_PASSWORD)

    assert isinstance(needs_password_rehash(password_hash), bool)


def test_key_derivation_produces_256_bit_key() -> None:
    salt = generate_salt()
    derived = derive_encryption_key(MASTER_PASSWORD, salt)

    assert len(derived.key) == KEY_LENGTH
    assert derived.salt == salt


def test_key_derivation_is_deterministic_for_same_password_and_salt() -> None:
    salt = generate_salt()

    first = derive_encryption_key(MASTER_PASSWORD, salt)
    second = derive_encryption_key(MASTER_PASSWORD, salt)

    assert first.key == second.key


def test_key_derivation_changes_when_salt_changes() -> None:
    first = derive_encryption_key(MASTER_PASSWORD, generate_salt())
    second = derive_encryption_key(MASTER_PASSWORD, generate_salt())

    assert first.key != second.key


def test_key_derivation_rejects_invalid_salt() -> None:
    with pytest.raises(CryptoError):
        derive_encryption_key(MASTER_PASSWORD, b"too-short")


def test_encrypt_decrypt_round_trip() -> None:
    key = derive_encryption_key(MASTER_PASSWORD, generate_salt()).key

    encrypted = encrypt_value(PLAINTEXT, key)
    decrypted = decrypt_value(encrypted, key)

    assert decrypted == PLAINTEXT
    assert encrypted != PLAINTEXT


def test_encryptions_of_same_plaintext_are_unique() -> None:
    key = derive_encryption_key(MASTER_PASSWORD, generate_salt()).key

    first = encrypt_value(PLAINTEXT, key)
    second = encrypt_value(PLAINTEXT, key)

    assert first != second


def test_decryption_with_wrong_key_fails() -> None:
    first_key = derive_encryption_key(MASTER_PASSWORD, generate_salt()).key
    second_key = derive_encryption_key(
        "Different-Correct-Horse-Password-2026!",
        generate_salt(),
    ).key

    encrypted = encrypt_value(PLAINTEXT, first_key)

    with pytest.raises(EncryptionError):
        decrypt_value(encrypted, second_key)


def test_tampered_ciphertext_fails_authentication() -> None:
    key = derive_encryption_key(MASTER_PASSWORD, generate_salt()).key
    encrypted = encrypt_value(PLAINTEXT, key)

    last_character = "A" if encrypted[-1] != "A" else "B"
    tampered = encrypted[:-1] + last_character

    with pytest.raises(EncryptionError):
        decrypt_value(tampered, key)


def test_associated_data_is_authenticated() -> None:
    key = derive_encryption_key(MASTER_PASSWORD, generate_salt()).key
    associated_data = b"vault-entry:123"

    encrypted = encrypt_value(
        PLAINTEXT,
        key,
        associated_data=associated_data,
    )

    assert (
        decrypt_value(
            encrypted,
            key,
            associated_data=associated_data,
        )
        == PLAINTEXT
    )

    with pytest.raises(EncryptionError):
        decrypt_value(
            encrypted,
            key,
            associated_data=b"vault-entry:456",
        )


def test_encryption_rejects_invalid_key_length() -> None:
    with pytest.raises(EncryptionError):
        encrypt_value(PLAINTEXT, b"invalid-key")


def test_decryption_rejects_malformed_ciphertext() -> None:
    key = derive_encryption_key(MASTER_PASSWORD, generate_salt()).key

    with pytest.raises(EncryptionError):
        decrypt_value("not-valid-encrypted-data", key)


def test_secure_tokens_are_unique() -> None:
    first = generate_secure_token()
    second = generate_secure_token()

    assert first != second
    assert len(first) > 20
    assert len(second) > 20


def test_secure_token_rejects_unsafe_length() -> None:
    with pytest.raises(ValueError):
        generate_secure_token(8)


def test_generated_password_has_requested_length() -> None:
    password = generate_random_password(32)

    assert len(password) == 32


def test_generated_passwords_are_unique() -> None:
    first = generate_random_password()
    second = generate_random_password()

    assert first != second


def test_secure_compare_matches_equal_values() -> None:
    assert secure_compare("same-value", "same-value")


def test_secure_compare_rejects_different_values() -> None:
    assert not secure_compare("first-value", "second-value")
