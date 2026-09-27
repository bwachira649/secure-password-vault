"""Business logic for vault authentication and credential management."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Final

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from password_vault.models import AuditEvent, Credential, VaultMetadata
from password_vault.security.crypto import (
    CryptoError,
    decrypt_value,
    derive_encryption_key,
    encrypt_value,
    generate_salt,
    hash_master_password,
    validate_master_password,
    verify_master_password,
)


class VaultServiceError(Exception):
    """Base exception for vault service failures."""


class VaultNotInitializedError(VaultServiceError):
    """Raised when an operation requires an initialized vault."""


class VaultAlreadyInitializedError(VaultServiceError):
    """Raised when attempting to initialize an existing vault."""


class InvalidMasterPasswordError(VaultServiceError):
    """Raised when master-password authentication fails."""


class CredentialNotFoundError(VaultServiceError):
    """Raised when a requested credential does not exist."""


class _UpdateUnset:
    """Sentinel type used to distinguish omitted fields from explicit None."""


UPDATE_UNSET: Final = _UpdateUnset()


class VaultService:
    """Application service for secure vault operations."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def initialize_vault(self, master_password: str) -> VaultMetadata:
        """Create the vault metadata using a new master password."""
        existing = self.db.scalar(select(VaultMetadata).limit(1))

        if existing is not None:
            raise VaultAlreadyInitializedError("Vault is already initialized.")

        validate_master_password(master_password)

        salt = generate_salt()
        password_hash = hash_master_password(master_password)

        metadata = VaultMetadata(
            password_hash=password_hash,
            encryption_salt=base64.urlsafe_b64encode(salt).decode("ascii"),
            is_initialized=True,
        )

        self.db.add(metadata)
        self.db.flush()

        self.record_event(
            event_type="vault_initialized",
            description="Vault initialized successfully.",
            success=True,
        )

        self.db.commit()
        self.db.refresh(metadata)

        return metadata

    def authenticate(self, master_password: str) -> bytes:
        """Authenticate the master password and derive the encryption key."""
        metadata = self._get_metadata()

        if not verify_master_password(
            metadata.password_hash,
            master_password,
        ):
            self.record_event(
                event_type="login_failed",
                description="Vault authentication failed.",
                success=False,
            )
            self.db.commit()
            raise InvalidMasterPasswordError("Invalid master password.")

        try:
            salt = base64.urlsafe_b64decode(
                metadata.encryption_salt.encode("ascii")
            )

            derived_key = derive_encryption_key(
                master_password,
                salt,
            )
        except (ValueError, CryptoError) as exc:
            raise VaultServiceError(
                "Unable to derive the vault encryption key."
            ) from exc

        self.record_event(
            event_type="login",
            description="Vault authentication succeeded.",
            success=True,
        )
        self.db.commit()

        return derived_key.key

    def create_credential(
        self,
        encryption_key: bytes,
        *,
        name: str,
        username: str,
        password: str,
        url: str | None = None,
        category: str = "General",
        notes: str | None = None,
        expires_at: datetime | None = None,
        is_favorite: bool = False,
    ) -> Credential:
        """Create a credential with its password encrypted before storage."""
        self._require_initialized()
        self._validate_credential_name(name)
        self._validate_username(username)
        self._validate_password(password)

        credential = Credential(
            name=name.strip(),
            username=username,
            encrypted_password="",
            url=url,
            category=category.strip() or "General",
            notes=notes,
            expires_at=expires_at,
            is_favorite=is_favorite,
        )

        self.db.add(credential)

        # Flush first so SQLAlchemy assigns the permanent credential ID.
        # The immutable ID is used as AES-GCM associated authenticated data.
        self.db.flush()

        credential.encrypted_password = encrypt_value(
            password,
            encryption_key,
            associated_data=self._credential_aad(credential.id),
        )

        self.db.flush()

        self.record_event(
            event_type="credential_created",
            description=f"Credential '{credential.name}' created.",
            credential_id=credential.id,
            success=True,
        )

        self.db.commit()
        self.db.refresh(credential)

        return credential

    def list_credentials(
        self,
        *,
        search: str | None = None,
        category: str | None = None,
        favorites_only: bool = False,
    ) -> list[Credential]:
        """List credential metadata without decrypting passwords."""
        self._require_initialized()

        statement = select(Credential).order_by(Credential.name.asc())

        if search:
            pattern = f"%{search.strip()}%"

            statement = statement.where(
                or_(
                    Credential.name.ilike(pattern),
                    Credential.username.ilike(pattern),
                    Credential.category.ilike(pattern),
                    Credential.url.ilike(pattern),
                )
            )

        if category:
            statement = statement.where(
                Credential.category == category.strip()
            )

        if favorites_only:
            statement = statement.where(Credential.is_favorite.is_(True))

        return list(self.db.scalars(statement).all())

    def get_credential(
        self,
        credential_id: int,
    ) -> Credential:
        """Retrieve a credential by ID without decrypting its password."""
        self._require_initialized()

        credential = self.db.get(Credential, credential_id)

        if credential is None:
            raise CredentialNotFoundError(
                f"Credential {credential_id} was not found."
            )

        return credential

    def decrypt_credential_password(
        self,
        encryption_key: bytes,
        credential_id: int,
    ) -> str:
        """Decrypt a credential password and record the access event."""
        credential = self.get_credential(credential_id)

        try:
            password = decrypt_value(
                credential.encrypted_password,
                encryption_key,
                associated_data=self._credential_aad(credential.id),
            )
        except CryptoError as exc:
            raise VaultServiceError(
                "Unable to decrypt credential password."
            ) from exc

        credential.last_accessed_at = datetime.now(timezone.utc)

        self.record_event(
            event_type="credential_accessed",
            description=f"Credential '{credential.name}' password accessed.",
            credential_id=credential.id,
            success=True,
        )

        self.db.commit()

        return password

    def update_credential(
        self,
        encryption_key: bytes,
        credential_id: int,
        *,
        name: str | None | _UpdateUnset = UPDATE_UNSET,
        username: str | None | _UpdateUnset = UPDATE_UNSET,
        password: str | None | _UpdateUnset = UPDATE_UNSET,
        url: str | None | _UpdateUnset = UPDATE_UNSET,
        category: str | None | _UpdateUnset = UPDATE_UNSET,
        notes: str | None | _UpdateUnset = UPDATE_UNSET,
        expires_at: datetime | None | _UpdateUnset = UPDATE_UNSET,
        is_favorite: bool | None | _UpdateUnset = UPDATE_UNSET,
    ) -> Credential:
        """Update a credential.

        The UPDATE_UNSET sentinel distinguishes an omitted field from an
        explicitly supplied None value. This allows nullable fields such as
        URL, notes, and expiration timestamps to be cleared deliberately.
        """
        credential = self.get_credential(credential_id)

        old_name = credential.name

        if name is not UPDATE_UNSET:
            if name is None:
                raise ValueError("Credential name cannot be cleared.")

            self._validate_credential_name(name)
            credential.name = name.strip()

        if username is not UPDATE_UNSET:
            if username is None:
                raise ValueError("Username cannot be cleared.")

            self._validate_username(username)
            credential.username = username

        if password is not UPDATE_UNSET:
            if password is None:
                raise ValueError("Credential password cannot be cleared.")

            self._validate_password(password)

            credential.encrypted_password = encrypt_value(
                password,
                encryption_key,
                associated_data=self._credential_aad(credential.id),
            )

        if url is not UPDATE_UNSET:
            credential.url = url

        if category is not UPDATE_UNSET:
            if category is None:
                raise ValueError("Credential category cannot be cleared.")

            credential.category = category.strip() or "General"

        if notes is not UPDATE_UNSET:
            credential.notes = notes

        if expires_at is not UPDATE_UNSET:
            credential.expires_at = expires_at

        if is_favorite is not UPDATE_UNSET:
            credential.is_favorite = is_favorite

        self.db.flush()

        self.record_event(
            event_type="credential_updated",
            description=f"Credential '{old_name}' updated.",
            credential_id=credential.id,
            success=True,
        )

        self.db.commit()
        self.db.refresh(credential)

        return credential

    def delete_credential(self, credential_id: int) -> None:
        """Delete a credential and record the operation."""
        credential = self.get_credential(credential_id)
        credential_name = credential.name

        self.db.delete(credential)

        self.record_event(
            event_type="credential_deleted",
            description=f"Credential '{credential_name}' deleted.",
            credential_id=credential_id,
            success=True,
        )

        self.db.commit()

    def record_event(
        self,
        *,
        event_type: str,
        description: str,
        credential_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        success: bool = True,
    ) -> AuditEvent:
        """Create an audit event."""
        event = AuditEvent(
            event_type=event_type,
            description=description,
            credential_id=credential_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
        )

        self.db.add(event)
        self.db.flush()

        return event

    def get_audit_events(
        self,
        *,
        limit: int = 100,
        event_type: str | None = None,
    ) -> list[AuditEvent]:
        """Return recent audit events, optionally filtered by event type."""
        self._require_initialized()

        if limit < 1:
            raise ValueError("Audit event limit must be at least 1.")

        if limit > 500:
            limit = 500

        statement = (
            select(AuditEvent)
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.id.desc(),
            )
            .limit(limit)
        )

        if event_type is not None:
            normalized_event_type = event_type.strip()

            if not normalized_event_type:
                raise ValueError("Audit event type cannot be empty.")

            statement = statement.where(
                AuditEvent.event_type == normalized_event_type
            )

        return list(self.db.scalars(statement).all())

    def _get_metadata(self) -> VaultMetadata:
        """Return vault metadata or raise if the vault is not initialized."""
        metadata = self.db.scalar(select(VaultMetadata).limit(1))

        if metadata is None or not metadata.is_initialized:
            raise VaultNotInitializedError(
                "Vault has not been initialized."
            )

        return metadata

    def _require_initialized(self) -> None:
        """Ensure the vault has been initialized."""
        self._get_metadata()

    @staticmethod
    def _validate_credential_name(name: str) -> None:
        """Validate a credential name."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Credential name is required.")

        if len(name.strip()) > 200:
            raise ValueError("Credential name cannot exceed 200 characters.")

    @staticmethod
    def _validate_username(username: str) -> None:
        """Validate a credential username."""
        if not isinstance(username, str) or not username.strip():
            raise ValueError("Username is required.")

    @staticmethod
    def _validate_password(password: str) -> None:
        """Validate a credential password."""
        if not isinstance(password, str) or not password:
            raise ValueError("Credential password is required.")

    @staticmethod
    def _credential_aad(credential_id: int) -> bytes:
        """Build stable associated authenticated data for a credential."""
        return f"credential:{credential_id}".encode("utf-8")


__all__ = [
    "CredentialNotFoundError",
    "InvalidMasterPasswordError",
    "UPDATE_UNSET",
    "VaultAlreadyInitializedError",
    "VaultNotInitializedError",
    "VaultService",
    "VaultServiceError",
]
