"""API tests for protected credential operations."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

import password_vault.api.app as app_module
from password_vault.api.dependencies import get_db
from password_vault.database import Base
from password_vault.models import AuditEvent, Credential


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
            "master_password": "StrongMasterPassword123!",
        },
    )

    assert initialize_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "master_password": "StrongMasterPassword123!",
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


def test_credentials_require_authentication(client, test_database):
    """Protected credential endpoints reject unauthenticated requests."""
    response = client.get("/api/v1/credentials")

    assert response.status_code == 401


def test_create_credential(authenticated_client):
    """Authenticated users can create encrypted credentials."""
    response = create_sample_credential(authenticated_client)

    data = response.json()

    assert data["name"] == "GitHub"
    assert data["username"] == "bwachira"
    assert data["category"] == "Development"
    assert data["url"] == "https://github.com"
    assert data["is_favorite"] is True
    assert "password" not in data


def test_list_credentials_does_not_expose_password(authenticated_client):
    """Credential listings never expose decrypted passwords."""
    create_sample_credential(authenticated_client)

    response = authenticated_client.get(
        "/api/v1/credentials",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert len(data["items"]) == 1
    assert "password" not in data["items"][0]
    assert "encrypted_password" not in data["items"][0]


def test_get_credential_metadata(authenticated_client):
    """Credential detail endpoint returns metadata only."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.get(
        f"/api/v1/credentials/{credential_id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == credential_id
    assert data["name"] == "GitHub"
    assert data["username"] == "bwachira"
    assert "password" not in data
    assert "encrypted_password" not in data


def test_get_credential_password(authenticated_client):
    """Authenticated users can explicitly reveal a credential password."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.get(
        f"/api/v1/credentials/{credential_id}/password",
    )

    assert response.status_code == 200
    assert response.json()["password"] == "GitHubSecret123!"


def test_get_missing_credential(authenticated_client):
    """Missing credentials return HTTP 404."""
    response = authenticated_client.get(
        "/api/v1/credentials/99999",
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Credential not found."


def test_get_missing_credential_password(authenticated_client):
    """Password reveal for a missing credential returns HTTP 404."""
    response = authenticated_client.get(
        "/api/v1/credentials/99999/password",
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Credential not found."


def test_update_credential(authenticated_client):
    """Authenticated users can update credential fields."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "name": "GitHub Production",
            "category": "Infrastructure",
            "is_favorite": False,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "GitHub Production"
    assert data["category"] == "Infrastructure"
    assert data["is_favorite"] is False


def test_update_missing_credential(authenticated_client):
    """Updating a missing credential returns HTTP 404."""
    response = authenticated_client.put(
        "/api/v1/credentials/99999",
        json={
            "name": "Missing",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Credential not found."


def test_delete_credential(authenticated_client):
    """Authenticated users can delete credentials."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.delete(
        f"/api/v1/credentials/{credential_id}",
    )

    assert response.status_code == 200
    assert response.json()["message"] == (
        "Credential deleted successfully."
    )

    get_response = authenticated_client.get(
        f"/api/v1/credentials/{credential_id}",
    )

    assert get_response.status_code == 404


def test_delete_missing_credential(authenticated_client):
    """Deleting a missing credential returns HTTP 404."""
    response = authenticated_client.delete(
        "/api/v1/credentials/99999",
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Credential not found."


def test_search_credentials(authenticated_client):
    """Credential search matches supported metadata fields."""
    create_sample_credential(
        authenticated_client,
        username="unique-search-user",
    )

    create_sample_credential(
        authenticated_client,
        name="AWS Console",
        username="cloud-admin",
        category="Cloud",
        url="https://aws.amazon.com",
    )

    response = authenticated_client.get(
        "/api/v1/credentials",
        params={"search": "unique-search-user"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert data["items"][0]["username"] == "unique-search-user"


def test_filter_credentials_by_category(authenticated_client):
    """Credential listings can be filtered by category."""
    create_sample_credential(
        authenticated_client,
        category="Development",
    )

    create_sample_credential(
        authenticated_client,
        name="AWS Console",
        username="cloud-admin",
        category="Cloud",
    )

    response = authenticated_client.get(
        "/api/v1/credentials",
        params={"category": "Cloud"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert data["items"][0]["category"] == "Cloud"


def test_filter_favorite_credentials(authenticated_client):
    """Credential listings can return favorites only."""
    create_sample_credential(
        authenticated_client,
        is_favorite=True,
    )

    create_sample_credential(
        authenticated_client,
        name="Non Favorite",
        username="other-user",
        is_favorite=False,
    )

    response = authenticated_client.get(
        "/api/v1/credentials",
        params={"favorites_only": True},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert data["items"][0]["is_favorite"] is True


def test_create_credential_validation(authenticated_client):
    """Invalid credential creation requests are rejected."""
    response = authenticated_client.post(
        "/api/v1/credentials",
        json={
            "name": "",
            "username": "user",
            "password": "secret",
        },
    )

    assert response.status_code == 422


def test_update_credential_validation(authenticated_client):
    """Invalid credential update requests are rejected."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "name": "",
        },
    )

    assert response.status_code == 422


def test_credential_password_access_updates_last_accessed_at(
    authenticated_client,
):
    """Password access updates the credential access timestamp."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    before = authenticated_client.get(
        f"/api/v1/credentials/{credential_id}",
    ).json()

    assert before["last_accessed_at"] is None

    password_response = authenticated_client.get(
        f"/api/v1/credentials/{credential_id}/password",
    )

    assert password_response.status_code == 200

    after = authenticated_client.get(
        f"/api/v1/credentials/{credential_id}",
    ).json()

    assert after["last_accessed_at"] is not None


def test_credential_audit_events_are_created(
    authenticated_client,
    test_database,
):
    """Credential operations create audit events."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    authenticated_client.get(
        f"/api/v1/credentials/{credential_id}/password",
    )

    db = test_database()

    try:
        events = list(
            db.scalars(
                select(AuditEvent).order_by(
                    AuditEvent.id.asc(),
                )
            ).all()
        )

        event_types = [event.event_type for event in events]

        assert "credential_created" in event_types
        assert "credential_accessed" in event_types
    finally:
        db.close()


def test_expiration_timestamp_is_accepted(authenticated_client):
    """Credential expiration timestamps are stored and returned."""
    response = create_sample_credential(
        authenticated_client,
        expires_at="2031-06-15T12:30:00Z",
    )

    assert response.status_code == 201

    data = response.json()

    assert data["expires_at"] is not None


def test_update_can_clear_url(authenticated_client):
    """Explicit null clears an existing credential URL."""
    create_response = create_sample_credential(
        authenticated_client,
        url="https://github.com",
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "url": None,
        },
    )

    assert response.status_code == 200
    assert response.json()["url"] is None


def test_update_can_clear_notes(authenticated_client):
    """Explicit null clears existing credential notes."""
    create_response = create_sample_credential(
        authenticated_client,
        notes="Private account notes",
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "notes": None,
        },
    )

    assert response.status_code == 200
    assert response.json()["notes"] is None


def test_update_can_clear_expiration(authenticated_client):
    """Explicit null clears an existing credential expiration."""
    create_response = create_sample_credential(
        authenticated_client,
        expires_at="2030-01-01T00:00:00Z",
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "expires_at": None,
        },
    )

    assert response.status_code == 200
    assert response.json()["expires_at"] is None


def test_update_omitted_nullable_fields_remain_unchanged(
    authenticated_client,
):
    """Omitted nullable fields remain unchanged during an update."""
    create_response = create_sample_credential(
        authenticated_client,
        url="https://github.com",
        notes="Keep these notes",
        expires_at="2030-01-01T00:00:00Z",
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "name": "GitHub Updated",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "GitHub Updated"
    assert data["url"] == "https://github.com"
    assert data["notes"] == "Keep these notes"
    assert data["expires_at"] is not None


def test_update_rejects_null_for_required_fields(
    authenticated_client,
):
    """Required credential fields cannot be cleared with null."""
    create_response = create_sample_credential(
        authenticated_client,
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "name": None,
        },
    )

    assert response.status_code == 422


def test_update_password_remains_encrypted(
    authenticated_client,
    test_database,
):
    """Updating a password stores ciphertext rather than plaintext."""
    create_response = create_sample_credential(
        authenticated_client,
        password="OriginalSecret123!",
    )

    credential_id = create_response.json()["id"]

    response = authenticated_client.put(
        f"/api/v1/credentials/{credential_id}",
        json={
            "password": "ReplacementSecret456!",
        },
    )

    assert response.status_code == 200

    db = test_database()

    try:
        credential = db.get(
            Credential,
            credential_id,
        )

        assert credential is not None
        assert credential.encrypted_password
        assert "ReplacementSecret456!" not in (
            credential.encrypted_password
        )
        assert "OriginalSecret123!" not in (
            credential.encrypted_password
        )
    finally:
        db.close()

    password_response = authenticated_client.get(
        f"/api/v1/credentials/{credential_id}/password",
    )

    assert password_response.status_code == 200
    assert password_response.json()["password"] == (
        "ReplacementSecret456!"
    )
