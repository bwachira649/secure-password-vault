"""Cryptographic primitives for the secure password vault."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
MIN_PASSWORD_LENGTH = 12

PBKDF2_ITERATIONS = 600_000

EXPORT_KDF_CONTEXT = b"secure-password-vault:export-key:v1"

# These parameters deliberately favor password-cracking resistance while
# remaining practical for normal interactive authentication.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4


_password_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
)


class CryptoError(Exception):
    """Base exception for vault cryptographic failures."""


class InvalidPasswordError(CryptoError):
    """Raised when a password fails validation or verification."""


class EncryptionError(CryptoError):
    """Raised when encryption or decryption fails."""


@dataclass(frozen=True)
class DerivedKey:
    """A derived encryption key and the salt used to create it."""

    key: bytes
    salt: bytes


def generate_salt() -> bytes:
    """Generate a cryptographically secure salt."""
    return secrets.token_bytes(SALT_LENGTH)


def generate_nonce() -> bytes:
    """Generate a cryptographically secure AES-GCM nonce."""
    return secrets.token_bytes(NONCE_LENGTH)


def validate_master_password(password: str) -> None:
    """Validate basic master-password requirements.

    The vault requires a reasonably long master password. Strength rules
    beyond length can be added at the application layer without changing
    the cryptographic primitives.
    """
    if not isinstance(password, str):
        raise InvalidPasswordError("Master password must be a string.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidPasswordError(
            f"Master password must contain at least {MIN_PASSWORD_LENGTH} characters."
        )


def hash_master_password(password: str) -> str:
    """Hash a master password using Argon2id."""
    validate_master_password(password)
    return _password_hasher.hash(password)


def verify_master_password(password_hash: str, password: str) -> bool:
    """Verify a master password against an Argon2id hash.

    Returns False for an incorrect password while treating malformed hashes
    as verification failures rather than exposing internal exceptions.
    """
    if not isinstance(password_hash, str) or not password_hash:
        return False

    if not isinstance(password, str):
        return False

    try:
        return _password_hasher.verify(password_hash, password)
    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
    ):
        return False


def needs_password_rehash(password_hash: str) -> bool:
    """Return whether an existing password hash should be upgraded."""
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, TypeError):
        return False


def derive_encryption_key(
    password: str,
    salt: bytes,
) -> DerivedKey:
    """Derive a 256-bit vault encryption key.

    A unique, randomly generated salt must be stored alongside the vault
    metadata. The salt is not secret; the derived key is.
    """
    validate_master_password(password)

    if not isinstance(salt, bytes) or len(salt) != SALT_LENGTH:
        raise CryptoError(
            f"Salt must be exactly {SALT_LENGTH} bytes."
        )

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH,
    )

    return DerivedKey(
        key=key,
        salt=salt,
    )


def derive_export_key(
    password: str,
    salt: bytes,
) -> DerivedKey:
    """Derive a 256-bit key dedicated to export encryption.

    Export key derivation uses the same PBKDF2-HMAC-SHA256 primitive as
    vault key derivation, but applies a dedicated domain-separation context.
    This prevents the export derivation from being interchangeable with
    the normal vault encryption-key derivation.
    """
    if not isinstance(password, str):
        raise InvalidPasswordError(
            "Export password must be a string."
        )

    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidPasswordError(
            f"Export password must contain at least "
            f"{MIN_PASSWORD_LENGTH} characters."
        )

    if not isinstance(salt, bytes) or len(salt) != SALT_LENGTH:
        raise CryptoError(
            f"Salt must be exactly {SALT_LENGTH} bytes."
        )

    derivation_material = (
        EXPORT_KDF_CONTEXT
        + b"\x00"
        + password.encode("utf-8")
    )

    key = hashlib.pbkdf2_hmac(
        "sha256",
        derivation_material,
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH,
    )

    return DerivedKey(
        key=key,
        salt=salt,
    )


def _encode(value: bytes) -> str:
    """Encode binary data for safe storage/transmission."""
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    """Decode URL-safe base64 data with normalized error handling."""
    if not isinstance(value, str) or not value:
        raise EncryptionError(
            "Encoded cryptographic value is empty."
        )

    try:
        return base64.urlsafe_b64decode(
            value.encode("ascii")
        )
    except (
        ValueError,
        UnicodeEncodeError,
        binascii.Error,
    ) as exc:
        raise EncryptionError(
            "Invalid encoded cryptographic value."
        ) from exc


def encrypt_value(
    plaintext: str,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> str:
    """Encrypt plaintext using AES-256-GCM.

    The returned value contains the nonce and ciphertext in a single
    URL-safe base64 string. AES-GCM authenticates the ciphertext and the
    optional associated data.
    """
    if not isinstance(plaintext, str):
        raise EncryptionError(
            "Plaintext must be a string."
        )

    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise EncryptionError(
            f"Encryption key must be exactly {KEY_LENGTH} bytes."
        )

    nonce = generate_nonce()

    try:
        ciphertext = AESGCM(key).encrypt(
            nonce,
            plaintext.encode("utf-8"),
            associated_data,
        )
    except Exception as exc:
        raise EncryptionError(
            "Unable to encrypt value."
        ) from exc

    return _encode(nonce + ciphertext)


def decrypt_value(
    encrypted_value: str,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> str:
    """Decrypt and authenticate an AES-256-GCM encrypted value."""
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise EncryptionError(
            f"Encryption key must be exactly {KEY_LENGTH} bytes."
        )

    payload = _decode(encrypted_value)

    if len(payload) <= NONCE_LENGTH:
        raise EncryptionError(
            "Encrypted value is malformed."
        )

    nonce = payload[:NONCE_LENGTH]
    ciphertext = payload[NONCE_LENGTH:]

    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            associated_data,
        )
    except InvalidTag as exc:
        raise EncryptionError(
            "Encrypted value failed authentication or the key is incorrect."
        ) from exc
    except Exception as exc:
        raise EncryptionError(
            "Unable to decrypt value."
        ) from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EncryptionError(
            "Decrypted value is not valid UTF-8 text."
        ) from exc


def encrypt_export_payload(
    payload: str,
    export_password: str,
    *,
    associated_data: bytes,
) -> str:
    """Encrypt a complete export payload with an export password.

    The result contains the randomly generated salt, AES-GCM nonce, and
    authenticated ciphertext in one URL-safe base64 string.

    The export key is derived independently from the vault encryption key.
    """
    if not isinstance(payload, str):
        raise EncryptionError(
            "Export payload must be a string."
        )

    if not isinstance(associated_data, bytes):
        raise EncryptionError(
            "Export associated data must be bytes."
        )

    salt = generate_salt()

    try:
        derived_key = derive_export_key(
            export_password,
            salt,
        )

        nonce = generate_nonce()

        ciphertext = AESGCM(derived_key.key).encrypt(
            nonce,
            payload.encode("utf-8"),
            associated_data,
        )
    except InvalidPasswordError:
        raise
    except CryptoError:
        raise
    except Exception as exc:
        raise EncryptionError(
            "Unable to encrypt export payload."
        ) from exc

    return _encode(
        salt
        + nonce
        + ciphertext
    )


def decrypt_export_payload(
    encrypted_payload: str,
    export_password: str,
    *,
    associated_data: bytes,
) -> str:
    """Decrypt and authenticate a protected export payload."""
    if not isinstance(associated_data, bytes):
        raise EncryptionError(
            "Export associated data must be bytes."
        )

    payload = _decode(encrypted_payload)

    minimum_length = (
        SALT_LENGTH
        + NONCE_LENGTH
        + 16
    )

    if len(payload) < minimum_length:
        raise EncryptionError(
            "Encrypted export payload is malformed."
        )

    salt = payload[:SALT_LENGTH]
    nonce = payload[
        SALT_LENGTH : SALT_LENGTH + NONCE_LENGTH
    ]
    ciphertext = payload[
        SALT_LENGTH + NONCE_LENGTH :
    ]

    try:
        derived_key = derive_export_key(
            export_password,
            salt,
        )

        plaintext = AESGCM(derived_key.key).decrypt(
            nonce,
            ciphertext,
            associated_data,
        )
    except InvalidPasswordError:
        raise
    except InvalidTag as exc:
        raise EncryptionError(
            "Export authentication failed or the export password is incorrect."
        ) from exc
    except CryptoError:
        raise
    except Exception as exc:
        raise EncryptionError(
            "Unable to decrypt export payload."
        ) from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EncryptionError(
            "Decrypted export payload is not valid UTF-8 text."
        ) from exc


def secure_compare(left: str, right: str) -> bool:
    """Compare two strings using constant-time comparison."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False

    return hmac.compare_digest(
        left.encode("utf-8"),
        right.encode("utf-8"),
    )


def generate_secure_token(length: int = 32) -> str:
    """Generate a URL-safe cryptographically secure token."""
    if length < 16:
        raise ValueError(
            "Token length must be at least 16 bytes."
        )

    return secrets.token_urlsafe(length)


def generate_random_password(length: int = 24) -> str:
    """Generate a cryptographically secure random password.

    This function intentionally uses the secrets module rather than
    pseudo-random generators.
    """
    if length < 16:
        raise ValueError(
            "Generated password length must be at least 16."
        )

    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}:,.?"
    )

    return "".join(
        secrets.choice(alphabet)
        for _ in range(length)
    )


__all__ = [
    "ARGON2_MEMORY_COST",
    "ARGON2_PARALLELISM",
    "ARGON2_TIME_COST",
    "CryptoError",
    "DerivedKey",
    "EncryptionError",
    "EXPORT_KDF_CONTEXT",
    "InvalidPasswordError",
    "KEY_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "NONCE_LENGTH",
    "PBKDF2_ITERATIONS",
    "SALT_LENGTH",
    "derive_encryption_key",
    "derive_export_key",
    "decrypt_export_payload",
    "decrypt_value",
    "encrypt_export_payload",
    "encrypt_value",
    "generate_nonce",
    "generate_random_password",
    "generate_salt",
    "generate_secure_token",
    "hash_master_password",
    "needs_password_rehash",
    "secure_compare",
    "validate_master_password",
    "verify_master_password",
]
