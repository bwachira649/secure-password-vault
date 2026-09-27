"""API tests for encrypted vault transfer operations."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

import password_vault.api.app as app_module
from password_vault.api.dependencies import get_db
from password_vault.database import Base
from password_vault.models import AuditEvent, Credential


MASTER_PASSWORD = "StrongMasterPassword123!"
EXPORT_PASSWORD = "StrongExportPassword456!"


@pytest.fixture
def test_database(monkeypatch):
    """Create an isolated in-memory database for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()

        try:
            yield db
        finally:
            db.close()

    def override_init_database():
        Base.metadata.create_all(bind=engine)

    monkeypatch.setattr(
        app_module,
        "init_database",
        override_init_database,
    )

    app_module.app.dependency_overrides[get_db] = override_get_db

    try:
        yield TestingSessionLocal
    finally:
        app_module.app.dependency_overrides.clear()
        engine.dispose()


@pytest.fixture
def client(test_database):
    """Return a FastAPI test client using the isolated database."""
    with TestClient(app_module.app) as test_client:
        yield test_client


@pytest.fixture
def authenticated_client(client):
    """Initialize and authenticate a test vault."""
    initialize_response = client.post(
        "/api/v1/auth/initialize",
        json={
            "master_password": MASTER_PASSWORD,
        },
    )

    assert initialize_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "master_password": MASTER_PASSWORD,
        },
    )

    assert login_response.status_code == 200
    assert login_response.json()["authenticated"] is True

    return client


def create_sample_credential(client, **overrides):
    """Create a sample credential and return its response."""
    payload = {
        "name": "GitHub",
        "username": "bwachira",
        "password": "GitHubSecret123!",
        "url": "https://github.com",
        "category": "Development",
        "notes": "Primary development account",
        "expires_at": "2030-01-01T00:00:00Z",
        "is_favorite": True,
    }

    payload.update(overrides)

    response = client.post(
        "/api/v1/credentials",
        json=payload,
    )

    assert response.status_code == 201

    return response


def test_export_requires_authentication(client):
    """Vault export requires an authenticated session."""
    response = client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert response.status_code == 401


def test_import_requires_authentication(client):
    """Vault import requires an authenticated session."""
    response = client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": "{}",
        },
    )

    assert response.status_code == 401


def test_export_requires_valid_export_password(authenticated_client):
    """Export rejects an export password shorter than 12 characters."""
    response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": "short",
        },
    )

    assert response.status_code == 422


def test_export_creates_encrypted_document(authenticated_client):
    """Authenticated users can create encrypted vault exports."""
    create_sample_credential(authenticated_client)

    response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["format"] == "secure-password-vault"
    assert data["version"] == 1
    assert data["filename"] == "secure-password-vault-export.json"
    assert isinstance(data["export_data"], str)
    assert data["export_data"]

    assert "GitHubSecret123!" not in data["export_data"]
    assert "bwachira" not in data["export_data"]
    assert "Primary development account" not in data["export_data"]


def test_export_returns_valid_json_envelope(authenticated_client):
    """The API export is a valid encrypted export envelope."""
    create_sample_credential(authenticated_client)

    response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert response.status_code == 200

    envelope = json.loads(response.json()["export_data"])

    assert envelope["format"] == "secure-password-vault"
    assert envelope["version"] == 1
    assert envelope["kdf"] == "PBKDF2-HMAC-SHA256"
    assert envelope["cipher"] == "AES-256-GCM"
    assert envelope["salt"]
    assert envelope["ciphertext"]


def test_export_records_audit_event(
    authenticated_client,
    test_database,
):
    """Successful exports create an audit event."""
    response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert response.status_code == 200

    with test_database() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(AuditEvent.event_type == "vault_exported")
            .order_by(AuditEvent.id.desc())
        )

        assert event is not None
        assert event.success is True
        assert "Encrypted vault export" in event.description


def test_import_rejects_wrong_export_password(
    authenticated_client,
):
    """Import rejects an incorrect export password."""
    create_sample_credential(authenticated_client)

    export_response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert export_response.status_code == 200

    import_response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": "WrongExportPassword789!",
            "export_data": export_response.json()["export_data"],
        },
    )

    assert import_response.status_code == 400
    assert "decrypt" in import_response.json()["detail"].lower()


def test_import_rejects_malformed_export(
    authenticated_client,
):
    """Import rejects malformed encrypted export data."""
    response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": "not-json",
        },
    )

    assert response.status_code == 400
    assert "valid JSON" in response.json()["detail"]


def test_import_rejects_unsupported_export(
    authenticated_client,
):
    """Import rejects unsupported export formats."""
    export_data = json.dumps(
        {
            "format": "unknown-format",
            "version": 1,
            "kdf": "PBKDF2-HMAC-SHA256",
            "cipher": "AES-256-GCM",
            "salt": "invalid",
            "ciphertext": "invalid",
        }
    )

    response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": export_data,
        },
    )

    assert response.status_code == 400
    assert "Unsupported export format" in response.json()["detail"]


def test_import_rejects_tampered_export(
    authenticated_client,
):
    """Import rejects an export whose authenticated ciphertext was modified."""
    create_sample_credential(authenticated_client)

    export_response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert export_response.status_code == 200

    envelope = json.loads(export_response.json()["export_data"])

    ciphertext = envelope["ciphertext"]

    replacement = "A" if ciphertext[-1] != "A" else "B"

    envelope["ciphertext"] = ciphertext[:-1] + replacement

    import_response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": json.dumps(envelope),
        },
    )

    assert import_response.status_code == 400
    assert "decrypt" in import_response.json()["detail"].lower()


def test_import_restores_credentials(
    authenticated_client,
    test_database,
):
    """Authenticated users can import credentials from an encrypted export."""
    create_sample_credential(authenticated_client)

    export_response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert export_response.status_code == 200

    import_response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": export_response.json()["export_data"],
        },
    )

    assert import_response.status_code == 200

    data = import_response.json()

    assert data["imported_count"] == 1
    assert "successfully" in data["message"].lower()

    with test_database() as db:
        credentials = db.scalars(
            select(Credential)
            .order_by(Credential.id)
        ).all()

        assert len(credentials) == 2
        assert credentials[0].name == "GitHub"
        assert credentials[1].name == "GitHub"


def test_import_preserves_metadata(
    authenticated_client,
    test_database,
):
    """Imported credentials preserve their non-password metadata."""
    create_sample_credential(authenticated_client)

    export_response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert export_response.status_code == 200

    import_response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": export_response.json()["export_data"],
        },
    )

    assert import_response.status_code == 200

    with test_database() as db:
        credentials = db.scalars(
            select(Credential)
            .order_by(Credential.id)
        ).all()

        imported = credentials[-1]

        assert imported.name == "GitHub"
        assert imported.username == "bwachira"
        assert imported.url == "https://github.com"
        assert imported.category == "Development"
        assert imported.notes == "Primary development account"
        assert imported.is_favorite is True


def test_import_records_audit_events(
    authenticated_client,
    test_database,
):
    """Successful import creates transfer and credential audit events."""
    create_sample_credential(authenticated_client)

    export_response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert export_response.status_code == 200

    import_response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": export_response.json()["export_data"],
        },
    )

    assert import_response.status_code == 200

    with test_database() as db:
        events = db.scalars(
            select(AuditEvent)
            .order_by(AuditEvent.id)
        ).all()

        event_types = [event.event_type for event in events]

        assert "vault_exported" in event_types
        assert "vault_imported" in event_types
        assert "credential_imported" in event_types


def test_import_does_not_expose_plaintext_password(
    authenticated_client,
):
    """Import responses never contain credential passwords."""
    create_sample_credential(authenticated_client)

    export_response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
        },
    )

    assert export_response.status_code == 200

    import_response = authenticated_client.post(
        "/api/v1/transfer/import",
        json={
            "export_password": EXPORT_PASSWORD,
            "export_data": export_response.json()["export_data"],
        },
    )

    assert import_response.status_code == 200

    response_text = import_response.text

    assert "GitHubSecret123!" not in response_text
    assert "password" not in response_text.lower()


def test_transfer_rejects_extra_request_fields(
    authenticated_client,
):
    """Transfer requests reject unexpected fields."""
    response = authenticated_client.post(
        "/api/v1/transfer/export",
        json={
            "export_password": EXPORT_PASSWORD,
            "unexpected": "value",
        },
    )

    assert response.status_code == 422
