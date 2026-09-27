"""API tests for vault authentication and session management."""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import password_vault.api.app as app_module
from password_vault.api.app import app
from password_vault.api.dependencies import get_db
from password_vault.database import Base


TEST_MASTER_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def test_database() -> Generator[sessionmaker[Session], None, None]:
    """Create an isolated in-memory SQLite database for API tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    testing_session_local = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    yield testing_session_local

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def client(
    test_database: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[TestClient, None, None]:
    """Create a TestClient using the isolated test database."""

    def override_get_db() -> Generator[Session, None, None]:
        """Provide a test database session."""
        db = test_database()

        try:
            yield db
        finally:
            db.close()

    # Prevent the FastAPI lifespan from initializing the real vault.db.
    monkeypatch.setattr(
        app_module,
        "init_database",
        lambda: None,
    )

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def initialize_vault(client: TestClient) -> None:
    """Initialize the test vault."""
    response = client.post(
        "/api/v1/auth/initialize",
        json={"master_password": TEST_MASTER_PASSWORD},
    )

    assert response.status_code == 201
    assert response.json() == {
        "authenticated": False,
        "message": "Vault initialized successfully. Please log in.",
    }


def login(client: TestClient) -> dict:
    """Authenticate against the test vault."""
    response = client.post(
        "/api/v1/auth/login",
        json={"master_password": TEST_MASTER_PASSWORD},
    )

    assert response.status_code == 200

    return response.json()


def test_initialize_vault(client: TestClient) -> None:
    """A new vault can be initialized successfully."""
    initialize_vault(client)


def test_initialize_vault_twice_returns_conflict(
    client: TestClient,
) -> None:
    """A vault cannot be initialized more than once."""
    initialize_vault(client)

    response = client.post(
        "/api/v1/auth/initialize",
        json={"master_password": TEST_MASTER_PASSWORD},
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Vault is already initialized.",
    }


def test_initialize_rejects_short_master_password(
    client: TestClient,
) -> None:
    """The API rejects master passwords shorter than 12 characters."""
    response = client.post(
        "/api/v1/auth/initialize",
        json={"master_password": "short"},
    )

    assert response.status_code == 422


def test_login_before_initialization_returns_conflict(
    client: TestClient,
) -> None:
    """Login is rejected when the vault has not been initialized."""
    response = client.post(
        "/api/v1/auth/login",
        json={"master_password": TEST_MASTER_PASSWORD},
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Vault has not been initialized.",
    }


def test_login_with_correct_password_creates_session(
    client: TestClient,
) -> None:
    """A correct master password creates an authenticated session."""
    initialize_vault(client)

    result = login(client)

    assert result == {
        "authenticated": True,
        "message": "Authentication successful.",
    }

    assert "vault_session" in client.cookies


def test_login_with_incorrect_password_returns_unauthorized(
    client: TestClient,
) -> None:
    """An incorrect master password is rejected."""
    initialize_vault(client)

    response = client.post(
        "/api/v1/auth/login",
        json={"master_password": "wrong-password-value"},
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid master password.",
    }


def test_authentication_status_is_unauthenticated_initially(
    client: TestClient,
) -> None:
    """Authentication status is false when no session exists."""
    response = client.get("/api/v1/auth/status")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "expires_at": None,
    }


def test_authentication_status_is_authenticated_after_login(
    client: TestClient,
) -> None:
    """Authentication status reports an active session after login."""
    initialize_vault(client)
    login(client)

    response = client.get("/api/v1/auth/status")

    assert response.status_code == 200

    body = response.json()

    assert body["authenticated"] is True
    assert body["expires_at"] is not None


def test_logout_locks_current_session(
    client: TestClient,
) -> None:
    """Logout destroys the current session and clears authentication."""
    initialize_vault(client)
    login(client)

    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "message": "Vault session locked.",
    }

    status_response = client.get("/api/v1/auth/status")

    assert status_response.status_code == 200
    assert status_response.json() == {
        "authenticated": False,
        "expires_at": None,
    }


def test_logout_without_session_is_idempotent(
    client: TestClient,
) -> None:
    """Logout succeeds even when no session is currently active."""
    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "message": "Vault session locked.",
    }


def test_login_replaces_previous_session_cookie(
    client: TestClient,
) -> None:
    """A successful second login creates another valid session."""
    initialize_vault(client)

    login(client)
    first_session = client.cookies.get("vault_session")

    login(client)
    second_session = client.cookies.get("vault_session")

    assert first_session
    assert second_session
    assert first_session != second_session


def test_authentication_status_rejects_invalid_session_cookie(
    client: TestClient,
) -> None:
    """An unknown session cookie is treated as unauthenticated."""
    client.cookies.set(
        "vault_session",
        "invalid-session-token",
    )

    response = client.get("/api/v1/auth/status")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "expires_at": None,
    }
