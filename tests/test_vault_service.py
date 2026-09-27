"""Tests for the password vault service layer."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from password_vault.database import Base
from password_vault.models import AuditEvent, Credential, VaultMetadata
from password_vault.services.vault_service import (
    CredentialNotFoundError,
    InvalidMasterPasswordError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    VaultService,
)


MASTER_PASSWORD = "Correct-Horse-Battery-Staple-2026!"
WRONG_PASSWORD = "Wrong-Horse-Battery-Staple-2026!"


@pytest.fixture
def db_session(tmp_path):
    """Provide an isolated SQLite database for each test."""
    database_path = tmp_path / "test-vault.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(bind=engine)

    Session = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    session = Session()

    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def service(db_session):
    """Provide a VaultService using the isolated test database."""
    return VaultService(db_session)


def test_initialize_vault(service, db_session) -> None:
    """A new vault should store password hash and encryption salt."""
    metadata = service.initialize_vault(MASTER_PASSWORD)

    assert metadata.id == 1
    assert metadata.is_initialized is True
    assert metadata.password_hash.startswith("$argon2")
    assert metadata.encryption_salt

    saved = db_session.query(VaultMetadata).one()

    assert saved.password_hash == metadata.password_hash
    assert saved.encryption_salt == metadata.encryption_salt


def test_initialize_vault_records_audit_event(service, db_session) -> None:
    """Vault initialization should create an audit event."""
    service.initialize_vault(MASTER_PASSWORD)

    events = db_session.query(AuditEvent).all()

    assert len(events) == 1
    assert events[0].event_type == "vault_initialized"
    assert events[0].success is True


def test_initialize_vault_cannot_run_twice(service) -> None:
    """An initialized vault cannot be initialized again."""
    service.initialize_vault(MASTER_PASSWORD)

    with pytest.raises(VaultAlreadyInitializedError):
        service.initialize_vault(MASTER_PASSWORD)


def test_authenticate_returns_encryption_key(service) -> None:
    """Successful authentication should return a 256-bit encryption key."""
    service.initialize_vault(MASTER_PASSWORD)

    encryption_key = service.authenticate(MASTER_PASSWORD)

    assert isinstance(encryption_key, bytes)
    assert len(encryption_key) == 32


def test_authentication_with_wrong_password_fails(
    service,
    db_session,
) -> None:
    """Incorrect master passwords should be rejected."""
    service.initialize_vault(MASTER_PASSWORD)

    with pytest.raises(InvalidMasterPasswordError):
        service.authenticate(WRONG_PASSWORD)

    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "login_failed")
        .all()
    )

    assert len(events) == 1
    assert events[0].success is False


def test_authentication_records_successful_login(
    service,
    db_session,
) -> None:
    """Successful authentication should create an audit event."""
    service.initialize_vault(MASTER_PASSWORD)

    service.authenticate(MASTER_PASSWORD)

    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "login")
        .all()
    )

    assert len(events) == 1
    assert events[0].success is True


def test_authentication_requires_initialized_vault(service) -> None:
    """Authentication should fail if the vault does not exist."""
    with pytest.raises(VaultNotInitializedError):
        service.authenticate(MASTER_PASSWORD)


def test_create_credential_encrypts_password(
    service,
    db_session,
) -> None:
    """Credential passwords should be encrypted before persistence."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="Plaintext-Secret-2026!",
        url="https://github.com",
        category="Development",
        notes="Primary GitHub account",
    )

    assert credential.id == 1
    assert credential.name == "GitHub"
    assert credential.username == "bwachira649"
    assert credential.encrypted_password
    assert credential.encrypted_password != "Plaintext-Secret-2026!"

    saved = db_session.query(Credential).one()

    assert saved.encrypted_password != "Plaintext-Secret-2026!"


def test_create_credential_records_audit_event(
    service,
    db_session,
) -> None:
    """Credential creation should be audited."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="Plaintext-Secret-2026!",
    )

    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "credential_created")
        .one()
    )

    assert event.credential_id == credential.id
    assert event.success is True


def test_list_credentials_returns_metadata_without_decryption(
    service,
) -> None:
    """Listing credentials should not require decrypting passwords."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
        category="Development",
    )

    service.create_credential(
        encryption_key,
        name="AWS",
        username="cloud-user",
        password="AWS-Secret-2026!",
        category="Cloud",
    )

    credentials = service.list_credentials()

    assert len(credentials) == 2
    assert [credential.name for credential in credentials] == [
        "AWS",
        "GitHub",
    ]

    assert all(
        credential.encrypted_password
        for credential in credentials
    )


def test_search_credentials(service) -> None:
    """Credential searches should match useful metadata fields."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    service.create_credential(
        encryption_key,
        name="GitHub Production",
        username="bwachira649",
        password="GitHub-Secret-2026!",
        category="Development",
    )

    service.create_credential(
        encryption_key,
        name="Company Email",
        username="brian@example.com",
        password="Email-Secret-2026!",
        category="Email",
    )

    results = service.list_credentials(search="GitHub")

    assert len(results) == 1
    assert results[0].name == "GitHub Production"


def test_filter_credentials_by_category(service) -> None:
    """Credentials should be filterable by category."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
        category="Development",
    )

    service.create_credential(
        encryption_key,
        name="Company Email",
        username="brian@example.com",
        password="Email-Secret-2026!",
        category="Email",
    )

    results = service.list_credentials(category="Email")

    assert len(results) == 1
    assert results[0].category == "Email"


def test_filter_favorite_credentials(service) -> None:
    """Favorite filtering should return only marked credentials."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
        is_favorite=True,
    )

    service.create_credential(
        encryption_key,
        name="Email",
        username="brian@example.com",
        password="Email-Secret-2026!",
        is_favorite=False,
    )

    results = service.list_credentials(favorites_only=True)

    assert len(results) == 1
    assert results[0].name == "GitHub"


def test_decrypt_credential_password(
    service,
    db_session,
) -> None:
    """A credential password should decrypt only with the correct key."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
    )

    password = service.decrypt_credential_password(
        encryption_key,
        credential.id,
    )

    assert password == "GitHub-Secret-2026!"

    saved = db_session.get(Credential, credential.id)

    assert saved is not None
    assert saved.last_accessed_at is not None

    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "credential_accessed")
        .one()
    )

    assert event.credential_id == credential.id


def test_decrypt_credential_with_wrong_key_fails(service) -> None:
    """A wrong encryption key should never decrypt a credential."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
    )

    wrong_key = b"x" * 32

    with pytest.raises(Exception):
        service.decrypt_credential_password(
            wrong_key,
            credential.id,
        )


def test_get_credential(service) -> None:
    """An existing credential should be retrievable by ID."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    created = service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
    )

    retrieved = service.get_credential(created.id)

    assert retrieved.id == created.id
    assert retrieved.name == "GitHub"


def test_get_missing_credential_fails(service) -> None:
    """Missing credential IDs should raise a specific service error."""
    service.initialize_vault(MASTER_PASSWORD)

    with pytest.raises(CredentialNotFoundError):
        service.get_credential(999)


def test_update_credential(service) -> None:
    """Credential fields and encrypted passwords should be updateable."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        encryption_key,
        name="GitHub",
        username="old-user",
        password="Old-Secret-2026!",
    )

    updated = service.update_credential(
        encryption_key,
        credential.id,
        name="GitHub Production",
        username="new-user",
        password="New-Secret-2026!",
        category="Development",
        is_favorite=True,
    )

    assert updated.name == "GitHub Production"
    assert updated.username == "new-user"
    assert updated.category == "Development"
    assert updated.is_favorite is True

    decrypted = service.decrypt_credential_password(
        encryption_key,
        credential.id,
    )

    assert decrypted == "New-Secret-2026!"


def test_update_credential_records_event(
    service,
    db_session,
) -> None:
    """Credential updates should create an audit event."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
    )

    service.update_credential(
        encryption_key,
        credential.id,
        category="Development",
    )

    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "credential_updated")
        .one()
    )

    assert event.credential_id == credential.id
    assert event.success is True


def test_delete_credential(service, db_session) -> None:
    """Deleting a credential should remove it from storage."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        encryption_key,
        name="GitHub",
        username="bwachira649",
        password="GitHub-Secret-2026!",
    )

    credential_id = credential.id

    service.delete_credential(credential_id)

    assert db_session.get(Credential, credential_id) is None

    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "credential_deleted")
        .one()
    )

    assert event.credential_id == credential_id
    assert event.success is True


def test_audit_events_can_be_limited(service) -> None:
    """Audit event retrieval should respect its limit."""
    service.initialize_vault(MASTER_PASSWORD)

    events = service.get_audit_events(limit=1)

    assert len(events) == 1
    assert events[0].event_type == "vault_initialized"


def test_audit_event_limit_is_bounded(service) -> None:
    """Very large audit-event limits should be safely bounded."""
    service.initialize_vault(MASTER_PASSWORD)

    events = service.get_audit_events(limit=10000)

    assert len(events) <= 500


def test_credential_expiration_can_be_stored(service) -> None:
    """Credentials should support an optional expiration timestamp."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    expiration = datetime(
        2027,
        1,
        1,
        tzinfo=timezone.utc,
    )

    credential = service.create_credential(
        encryption_key,
        name="Expiring Credential",
        username="user",
        password="Secret-2026!",
        expires_at=expiration,
    )

    assert credential.expires_at is not None

    stored_expiration = credential.expires_at

    if stored_expiration.tzinfo is None:
        stored_expiration = stored_expiration.replace(
            tzinfo=timezone.utc
        )

    assert stored_expiration == expiration


def test_credential_name_is_required(service) -> None:
    """Credential names must not be empty."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    with pytest.raises(ValueError):
        service.create_credential(
            encryption_key,
            name="   ",
            username="user",
            password="Secret-2026!",
        )


def test_credential_username_is_required(service) -> None:
    """Credential usernames must not be empty."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    with pytest.raises(ValueError):
        service.create_credential(
            encryption_key,
            name="GitHub",
            username="   ",
            password="Secret-2026!",
        )


def test_credential_password_is_required(service) -> None:
    """Credential passwords must not be empty."""
    service.initialize_vault(MASTER_PASSWORD)
    encryption_key = service.authenticate(MASTER_PASSWORD)

    with pytest.raises(ValueError):
        service.create_credential(
            encryption_key,
            name="GitHub",
            username="user",
            password="",
        )
