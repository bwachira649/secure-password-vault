"""Encrypted vault import and export services."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Final

from sqlalchemy.orm import Session

from password_vault.models import Credential
from password_vault.security.crypto import (
    CryptoError,
    decrypt_value,
    derive_export_key,
    encrypt_value,
    generate_salt,
)
from password_vault.services.vault_service import VaultService


EXPORT_FORMAT: Final[str] = "secure-password-vault"
EXPORT_VERSION: Final[int] = 1
EXPORT_KDF: Final[str] = "PBKDF2-HMAC-SHA256"
EXPORT_CIPHER: Final[str] = "AES-256-GCM"
EXPORT_AAD: Final[bytes] = (
    b"secure-password-vault:encrypted-export:v1"
)
MAX_EXPORT_SIZE_BYTES: Final[int] = 10 * 1024 * 1024


class VaultImportExportError(Exception):
    """Base exception for encrypted import/export failures."""


class InvalidExportPasswordError(VaultImportExportError):
    """Raised when an export password is invalid."""


class InvalidExportFormatError(VaultImportExportError):
    """Raised when an encrypted export is malformed or unsupported."""


class VaultExportError(VaultImportExportError):
    """Raised when a vault export cannot be created."""


class VaultImportError(VaultImportExportError):
    """Raised when an encrypted vault import fails."""


class VaultImportExportService:
    """Create and restore encrypted portable vault exports."""

    EXPORT_AAD = EXPORT_AAD

    def __init__(
        self,
        db: Session,
        vault_service: VaultService | None = None,
    ) -> None:
        self.db = db
        self.vault_service = vault_service or VaultService(db)

    def export_vault(
        self,
        encryption_key: bytes,
        export_password: str,
    ) -> str:
        """Export credentials into a password-protected encrypted document."""
        self._require_export_password(export_password)

        try:
            credentials = self.vault_service.list_credentials()

            records = [
                self._credential_to_record(
                    credential,
                    encryption_key,
                )
                for credential in credentials
            ]

            payload = {
                "format": EXPORT_FORMAT,
                "version": EXPORT_VERSION,
                "exported_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "credentials": records,
            }

            plaintext = json.dumps(
                payload,
                separators=(",", ":"),
                ensure_ascii=False,
            )

            export_salt = generate_salt()

            derived_key = derive_export_key(
                export_password,
                export_salt,
            )

            encrypted_payload = encrypt_value(
                plaintext,
                derived_key.key,
                associated_data=EXPORT_AAD,
            )

            envelope = {
                "format": EXPORT_FORMAT,
                "version": EXPORT_VERSION,
                "kdf": EXPORT_KDF,
                "cipher": EXPORT_CIPHER,
                "salt": base64.urlsafe_b64encode(
                    export_salt
                ).decode("ascii"),
                "ciphertext": encrypted_payload,
            }

            return json.dumps(
                envelope,
                indent=2,
                ensure_ascii=False,
            )

        except VaultImportExportError:
            raise
        except (CryptoError, ValueError, TypeError) as exc:
            raise VaultExportError(
                "Unable to create encrypted vault export."
            ) from exc

    def import_vault(
        self,
        encryption_key: bytes,
        export_password: str,
        export_data: str,
    ) -> int:
        """Import credentials from an encrypted vault export.

        Imported credentials receive new database IDs and are encrypted
        using the current vault encryption key.
        """
        self._require_export_password(export_password)

        payload = self._decrypt_export(
            export_password,
            export_data,
        )

        records = self._validate_payload(payload)

        imported_credentials: list[Credential] = []

        try:
            for record in records:
                credential = self._import_record(
                    record,
                    encryption_key,
                )

                imported_credentials.append(credential)

            self.db.flush()

            for credential in imported_credentials:
                self.vault_service.record_event(
                    event_type="credential_imported",
                    description=(
                        f"Credential '{credential.name}' "
                        "imported from encrypted vault export."
                    ),
                    credential_id=credential.id,
                    success=True,
                )

            self.db.commit()

            return len(imported_credentials)

        except VaultImportExportError:
            self.db.rollback()
            raise
        except (CryptoError, ValueError, TypeError) as exc:
            self.db.rollback()

            raise VaultImportError(
                "Unable to import encrypted vault export."
            ) from exc

    def _decrypt_export(
        self,
        export_password: str,
        export_data: str,
    ) -> dict[str, Any]:
        """Validate and decrypt an encrypted export envelope."""
        if not isinstance(export_data, str):
            raise InvalidExportFormatError(
                "Export data must be a string."
            )

        if not export_data.strip():
            raise InvalidExportFormatError(
                "Export data cannot be empty."
            )

        if len(export_data.encode("utf-8")) > MAX_EXPORT_SIZE_BYTES:
            raise InvalidExportFormatError(
                "Export data exceeds the maximum supported size."
            )

        try:
            envelope = json.loads(export_data)
        except json.JSONDecodeError as exc:
            raise InvalidExportFormatError(
                "Export data is not valid JSON."
            ) from exc

        if not isinstance(envelope, dict):
            raise InvalidExportFormatError(
                "Export envelope must be a JSON object."
            )

        self._validate_envelope(envelope)

        try:
            salt = base64.urlsafe_b64decode(
                envelope["salt"].encode("ascii")
            )
        except (
            ValueError,
            UnicodeEncodeError,
            KeyError,
            base64.binascii.Error
            if hasattr(base64, "binascii")
            else ValueError,
        ) as exc:
            raise InvalidExportFormatError(
                "Export salt is invalid."
            ) from exc

        if len(salt) != 16:
            raise InvalidExportFormatError(
                "Export salt has an invalid length."
            )

        try:
            derived_key = derive_export_key(
                export_password,
                salt,
            )

            plaintext = decrypt_value(
                envelope["ciphertext"],
                derived_key.key,
                associated_data=EXPORT_AAD,
            )
        except CryptoError as exc:
            raise InvalidExportPasswordError(
                "Unable to decrypt export. "
                "The export password may be incorrect or the file may "
                "have been modified."
            ) from exc

        try:
            payload = json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise InvalidExportFormatError(
                "Decrypted export payload is invalid JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise InvalidExportFormatError(
                "Decrypted export payload must be a JSON object."
            )

        return payload

    @staticmethod
    def _validate_envelope(
        envelope: dict[str, Any],
    ) -> None:
        """Validate the public portion of an export envelope."""
        if envelope.get("format") != EXPORT_FORMAT:
            raise InvalidExportFormatError(
                "Unsupported export format."
            )

        if envelope.get("version") != EXPORT_VERSION:
            raise InvalidExportFormatError(
                "Unsupported export version."
            )

        if envelope.get("kdf") != EXPORT_KDF:
            raise InvalidExportFormatError(
                "Unsupported export key-derivation algorithm."
            )

        if envelope.get("cipher") != EXPORT_CIPHER:
            raise InvalidExportFormatError(
                "Unsupported export encryption algorithm."
            )

        salt = envelope.get("salt")
        ciphertext = envelope.get("ciphertext")

        if not isinstance(salt, str) or not salt:
            raise InvalidExportFormatError(
                "Export salt is missing."
            )

        if not isinstance(ciphertext, str) or not ciphertext:
            raise InvalidExportFormatError(
                "Export ciphertext is missing."
            )

    @staticmethod
    def _validate_payload(
        payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Validate the decrypted export payload."""
        if payload.get("format") != EXPORT_FORMAT:
            raise InvalidExportFormatError(
                "Unsupported export payload format."
            )

        if payload.get("version") != EXPORT_VERSION:
            raise InvalidExportFormatError(
                "Unsupported export payload version."
            )

        credentials = payload.get("credentials")

        if not isinstance(credentials, list):
            raise InvalidExportFormatError(
                "Export credentials must be a list."
            )

        validated_records: list[dict[str, Any]] = []

        for index, record in enumerate(credentials):
            if not isinstance(record, dict):
                raise InvalidExportFormatError(
                    f"Credential record {index} must be an object."
                )

            required_fields = (
                "name",
                "username",
                "password",
                "url",
                "category",
                "notes",
                "expires_at",
                "is_favorite",
            )

            missing_fields = [
                field
                for field in required_fields
                if field not in record
            ]

            if missing_fields:
                raise InvalidExportFormatError(
                    f"Credential record {index} is missing fields: "
                    + ", ".join(missing_fields)
                )

            if not isinstance(record["name"], str):
                raise InvalidExportFormatError(
                    f"Credential record {index} has an invalid name."
                )

            if not record["name"].strip():
                raise InvalidExportFormatError(
                    f"Credential record {index} has an empty name."
                )

            if len(record["name"].strip()) > 200:
                raise InvalidExportFormatError(
                    f"Credential record {index} has an oversized name."
                )

            if not isinstance(record["username"], str):
                raise InvalidExportFormatError(
                    f"Credential record {index} has an invalid username."
                )

            if not record["username"].strip():
                raise InvalidExportFormatError(
                    f"Credential record {index} has an empty username."
                )

            if not isinstance(record["password"], str):
                raise InvalidExportFormatError(
                    f"Credential record {index} has an invalid password."
                )

            if not record["password"]:
                raise InvalidExportFormatError(
                    f"Credential record {index} has an empty password."
                )

            if record["url"] is not None and not isinstance(
                record["url"],
                str,
            ):
                raise InvalidExportFormatError(
                    f"Credential record {index} has an invalid URL."
                )

            if not isinstance(record["category"], str):
                raise InvalidExportFormatError(
                    f"Credential record {index} has an invalid category."
                )

            if not record["category"].strip():
                raise InvalidExportFormatError(
                    f"Credential record {index} has an empty category."
                )

            if record["notes"] is not None and not isinstance(
                record["notes"],
                str,
            ):
                raise InvalidExportFormatError(
                    f"Credential record {index} has invalid notes."
                )

            if record["expires_at"] is not None:
                if not isinstance(record["expires_at"], str):
                    raise InvalidExportFormatError(
                        f"Credential record {index} has an invalid "
                        "expiration timestamp."
                    )

                try:
                    datetime.fromisoformat(
                        record["expires_at"]
                    )
                except ValueError as exc:
                    raise InvalidExportFormatError(
                        f"Credential record {index} has an invalid "
                        "expiration timestamp."
                    ) from exc

            if not isinstance(record["is_favorite"], bool):
                raise InvalidExportFormatError(
                    f"Credential record {index} has an invalid favorite flag."
                )

            validated_records.append(record)

        return validated_records

    def _credential_to_record(
        self,
        credential: Credential,
        encryption_key: bytes,
    ) -> dict[str, Any]:
        """Convert a credential into an export record."""
        try:
            password = self.vault_service.decrypt_credential_password(
                encryption_key,
                credential.id,
            )
        except Exception as exc:
            raise VaultExportError(
                f"Unable to decrypt credential {credential.id} for export."
            ) from exc

        expires_at = credential.expires_at

        if expires_at is not None:
            expires_at = self._normalize_datetime(
                expires_at
            )

        return {
            "name": credential.name,
            "username": credential.username,
            "password": password,
            "url": credential.url,
            "category": credential.category,
            "notes": credential.notes,
            "expires_at": (
                expires_at.isoformat()
                if expires_at is not None
                else None
            ),
            "is_favorite": credential.is_favorite,
        }

    def _import_record(
        self,
        record: dict[str, Any],
        encryption_key: bytes,
    ) -> Credential:
        """Create one credential from a validated export record."""
        expires_at = record["expires_at"]

        if expires_at is not None:
            expires_at = datetime.fromisoformat(
                expires_at
            )

            expires_at = self._normalize_datetime(
                expires_at
            )

        try:
            credential = self.vault_service.create_credential(
                encryption_key,
                name=record["name"],
                username=record["username"],
                password=record["password"],
                url=record["url"],
                category=record["category"],
                notes=record["notes"],
                expires_at=expires_at,
                is_favorite=record["is_favorite"],
            )
        except Exception as exc:
            raise VaultImportError(
                f"Unable to import credential '{record['name']}'."
            ) from exc

        return credential

    @staticmethod
    def _normalize_datetime(
        value: datetime,
    ) -> datetime:
        """Normalize timestamps to UTC."""
        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(timezone.utc)

    @staticmethod
    def _require_export_password(
        export_password: str,
    ) -> None:
        """Validate the password protecting an export."""
        if not isinstance(export_password, str):
            raise InvalidExportPasswordError(
                "Export password must be a string."
            )

        if len(export_password) < 12:
            raise InvalidExportPasswordError(
                "Export password must contain at least 12 characters."
            )


__all__ = [
    "EXPORT_AAD",
    "EXPORT_CIPHER",
    "EXPORT_FORMAT",
    "EXPORT_KDF",
    "EXPORT_VERSION",
    "InvalidExportFormatError",
    "InvalidExportPasswordError",
    "MAX_EXPORT_SIZE_BYTES",
    "VaultExportError",
    "VaultImportError",
    "VaultImportExportError",
    "VaultImportExportService",
]
