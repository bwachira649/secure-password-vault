"""Tests for encrypted vault import and export."""

from __future__ import annotations

import base64
import json

import pytest

from password_vault.database import Base, SessionLocal, engine
from password_vault.models import Credential
from password_vault.security.crypto import (
    decrypt_value,
    derive_export_key,
    encrypt_value,
)
from password_vault.services.import_export import (
    EXPORT_AAD,
    EXPORT_CIPHER,
    EXPORT_FORMAT,
    EXPORT_KDF,
    EXPORT_VERSION,
    InvalidExportFormatError,
    InvalidExportPasswordError,
    VaultImportExportService,
)
from password_vault.services.vault_service import VaultService


MASTER_PASSWORD = "CorrectHorseBatteryStaple!2026"
EXPORT_PASSWORD = "PortableVaultExport!2026"


@pytest.fixture()
def db():
    """Provide a clean database for each test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()


def initialize_vault(db) -> bytes:
    """Initialize a test vault and return its encryption key."""
    service = VaultService(db)

    service.initialize_vault(
        MASTER_PASSWORD
    )

    return service.authenticate(
        MASTER_PASSWORD
    )


def create_test_credential(
    db,
    encryption_key: bytes,
) -> Credential:
    """Create a representative test credential."""
    service = VaultService(db)

    return service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHubSecret!2026",
        url="https://github.com",
        category="Development",
        notes="Portfolio repository",
        is_favorite=True,
    )


def test_export_requires_export_password(db) -> None:
    """Reject an export password that is too short."""
    encryption_key = initialize_vault(db)

    service = VaultImportExportService(db)

    with pytest.raises(
        InvalidExportPasswordError,
        match="at least 12 characters",
    ):
        service.export_vault(
            encryption_key,
            "short",
        )


def test_export_requires_initialized_vault(db) -> None:
    """Reject export when the vault has not been initialized."""
    service = VaultImportExportService(db)

    with pytest.raises(Exception):
        service.export_vault(
            b"x" * 32,
            EXPORT_PASSWORD,
        )


def test_export_contains_encrypted_envelope_only(db) -> None:
    """Verify sensitive credential data is not exposed in the envelope."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    envelope = json.loads(export_data)

    assert envelope["format"] == EXPORT_FORMAT
    assert envelope["version"] == EXPORT_VERSION
    assert envelope["kdf"] == EXPORT_KDF
    assert envelope["cipher"] == EXPORT_CIPHER
    assert envelope["salt"]
    assert envelope["ciphertext"]

    assert "GitHubSecret!2026" not in export_data
    assert "bwachira649" not in export_data
    assert MASTER_PASSWORD not in export_data
    assert "password_hash" not in export_data
    assert "encryption_key" not in export_data


def test_export_can_be_decrypted_with_correct_password(db) -> None:
    """Verify an export can be restored with the correct export password."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    assert export_data.startswith("{")

    imported_db = SessionLocal()

    try:
        imported_service = VaultImportExportService(
            imported_db
        )

        count = imported_service.import_vault(
            encryption_key,
            EXPORT_PASSWORD,
            export_data,
        )

        assert count == 1

        credentials = list(
            imported_db.query(Credential).all()
        )

        assert len(credentials) == 2

    finally:
        imported_db.close()


def test_import_rejects_wrong_export_password(db) -> None:
    """Reject an export protected by another password."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    with pytest.raises(
        InvalidExportPasswordError
    ):
        service.import_vault(
            encryption_key,
            "WrongExportPassword!2026",
            export_data,
        )


def test_import_rejects_malformed_json(db) -> None:
    """Reject an export that is not valid JSON."""
    encryption_key = initialize_vault(db)

    service = VaultImportExportService(db)

    with pytest.raises(
        InvalidExportFormatError,
        match="valid JSON",
    ):
        service.import_vault(
            encryption_key,
            EXPORT_PASSWORD,
            "not-json",
        )


def test_import_rejects_unsupported_format(db) -> None:
    """Reject an unsupported export format."""
    encryption_key = initialize_vault(db)

    service = VaultImportExportService(db)

    envelope = {
        "format": "unknown-format",
        "version": EXPORT_VERSION,
        "kdf": EXPORT_KDF,
        "cipher": EXPORT_CIPHER,
        "salt": "invalid",
        "ciphertext": "invalid",
    }

    with pytest.raises(
        InvalidExportFormatError,
        match="Unsupported export format",
    ):
        service.import_vault(
            encryption_key,
            EXPORT_PASSWORD,
            json.dumps(envelope),
        )


def test_import_rejects_tampered_export(db) -> None:
    """Reject an export whose authenticated ciphertext was modified."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    envelope = json.loads(export_data)

    envelope["ciphertext"] = (
        envelope["ciphertext"][:-2] + "AA"
    )

    tampered_export = json.dumps(
        envelope
    )

    with pytest.raises(
        InvalidExportPasswordError
    ):
        service.import_vault(
            encryption_key,
            EXPORT_PASSWORD,
            tampered_export,
        )


def test_import_reencrypts_password_with_current_vault_key(
    db,
) -> None:
    """Verify imported passwords are re-encrypted with the vault key."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    imported_count = service.import_vault(
        encryption_key,
        EXPORT_PASSWORD,
        export_data,
    )

    assert imported_count == 1

    credentials = list(
        db.query(Credential)
        .order_by(Credential.id.asc())
        .all()
    )

    assert len(credentials) == 2

    first, second = credentials

    assert first.id != second.id
    assert first.encrypted_password != second.encrypted_password

    passwords = [
        service.vault_service.decrypt_credential_password(
            encryption_key,
            credential.id,
        )
        for credential in credentials
    ]

    assert passwords == [
        "GitHubSecret!2026",
        "GitHubSecret!2026",
    ]


def test_import_preserves_credential_metadata(db) -> None:
    """Verify credential metadata survives export and import."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    service.import_vault(
        encryption_key,
        EXPORT_PASSWORD,
        export_data,
    )

    credentials = list(
        db.query(Credential)
        .order_by(Credential.id.asc())
        .all()
    )

    imported = credentials[-1]

    assert imported.name == "GitHub"
    assert imported.username == "bwachira649"
    assert imported.url == "https://github.com"
    assert imported.category == "Development"
    assert imported.notes == "Portfolio repository"
    assert imported.is_favorite is True


def test_import_rolls_back_when_record_is_invalid(db) -> None:
    """Verify invalid imported records do not partially modify the vault."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    envelope = json.loads(export_data)

    salt = base64.urlsafe_b64decode(
        envelope["salt"].encode("ascii")
    )

    export_key = derive_export_key(
        EXPORT_PASSWORD,
        salt,
    ).key

    plaintext = decrypt_value(
        envelope["ciphertext"],
        export_key,
        associated_data=EXPORT_AAD,
    )

    payload = json.loads(plaintext)

    payload["credentials"][0]["name"] = ""

    envelope["ciphertext"] = encrypt_value(
        json.dumps(payload),
        export_key,
        associated_data=EXPORT_AAD,
    )

    corrupted_export = json.dumps(
        envelope
    )

    with pytest.raises(
        InvalidExportFormatError
    ):
        service.import_vault(
            encryption_key,
            EXPORT_PASSWORD,
            corrupted_export,
        )

    credentials = list(
        db.query(Credential).all()
    )

    assert len(credentials) == 1


def test_import_records_audit_event(db) -> None:
    """Verify successful imports generate audit events."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    service.import_vault(
        encryption_key,
        EXPORT_PASSWORD,
        export_data,
    )

    events = service.vault_service.get_audit_events(
        event_type="credential_imported"
    )

    assert len(events) == 1
    assert events[0].event_type == "credential_imported"
    assert events[0].credential_id is not None


def test_export_key_is_separate_from_vault_key(db) -> None:
    """Verify export-key derivation is cryptographically separated."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    export_data = service.export_vault(
        encryption_key,
        EXPORT_PASSWORD,
    )

    envelope = json.loads(export_data)

    salt = base64.urlsafe_b64decode(
        envelope["salt"].encode("ascii")
    )

    export_key = derive_export_key(
        EXPORT_PASSWORD,
        salt,
    ).key

    vault_key = derive_export_key(
        MASTER_PASSWORD,
        salt,
    ).key

    assert export_key != vault_key


def test_export_uses_random_salt_and_ciphertext(
    db,
) -> None:
    """Verify repeated exports do not produce identical encrypted payloads."""
    encryption_key = initialize_vault(db)

    create_test_credential(
        db,
        encryption_key,
    )

    service = VaultImportExportService(db)

    first_export = json.loads(
        service.export_vault(
            encryption_key,
            EXPORT_PASSWORD,
        )
    )

    second_export = json.loads(
        service.export_vault(
            encryption_key,
            EXPORT_PASSWORD,
        )
    )

    assert first_export["salt"] != second_export["salt"]
    assert first_export["ciphertext"] != second_export["ciphertext"]
