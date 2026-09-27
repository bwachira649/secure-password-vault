"""API tests for protected audit-event operations."""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from password_vault.api.app import app
from password_vault.api.dependencies import get_db
from password_vault.database import Base


MASTER_PASSWORD = "Correct-Horse-Battery-Staple-123"


@pytest.fixture
def test_database() -> Generator[Session, None, None]:
    """Provide an isolated database for API tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)

    with Session(engine) as session:
        yield session

    engine.dispose()


@pytest.fixture
def client(
    test_database: Session,
) -> Generator[TestClient, None, None]:
    """Provide a test client using the isolated database."""
    app.dependency_overrides[get_db] = lambda: test_database

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def authenticated_client(
    client: TestClient,
) -> TestClient:
    """Initialize and authenticate a test vault."""
    initialize_response = client.post(
        "/api/v1/auth/initialize",
        json={"master_password": MASTER_PASSWORD},
    )

    assert initialize_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={"master_password": MASTER_PASSWORD},
    )

    assert login_response.status_code == 200
    assert client.cookies.get("vault_session")

    return client


def test_audit_events_require_authentication(
    client: TestClient,
) -> None:
    """Audit events must not be accessible without authentication."""
    response = client.get("/api/v1/audit/events")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."


def test_audit_events_return_initialization_and_login_events(
    authenticated_client: TestClient,
) -> None:
    """Authenticated users should receive vault audit events."""
    response = authenticated_client.get(
        "/api/v1/audit/events",
    )

    assert response.status_code == 200

    payload = response.json()

    assert "items" in payload
    assert "count" in payload
    assert payload["count"] >= 2

    event_types = {
        event["event_type"]
        for event in payload["items"]
    }

    assert "vault_initialized" in event_types
    assert "login" in event_types


def test_audit_events_can_be_filtered_by_event_type(
    authenticated_client: TestClient,
) -> None:
    """The API should support exact event-type filtering."""
    response = authenticated_client.get(
        "/api/v1/audit/events",
        params={"event_type": "login"},
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["count"] >= 1
    assert payload["items"]

    assert all(
        event["event_type"] == "login"
        for event in payload["items"]
    )


def test_audit_events_respect_limit(
    authenticated_client: TestClient,
) -> None:
    """The API should limit the number of returned events."""
    response = authenticated_client.get(
        "/api/v1/audit/events",
        params={"limit": 1},
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["count"] == 1
    assert len(payload["items"]) == 1


def test_audit_events_reject_limit_above_maximum(
    authenticated_client: TestClient,
) -> None:
    """The API should reject audit-event limits above 500."""
    response = authenticated_client.get(
        "/api/v1/audit/events",
        params={"limit": 501},
    )

    assert response.status_code == 422


def test_audit_events_reject_empty_event_type(
    authenticated_client: TestClient,
) -> None:
    """The API should reject a blank event-type filter."""
    response = authenticated_client.get(
        "/api/v1/audit/events",
        params={"event_type": " "},
    )

    assert response.status_code == 422


def test_audit_event_response_contains_safe_fields_only(
    authenticated_client: TestClient,
) -> None:
    """Audit responses must not expose credential passwords or keys."""
    response = authenticated_client.get(
        "/api/v1/audit/events",
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["items"]

    event = payload["items"][0]

    expected_fields = {
        "id",
        "event_type",
        "description",
        "credential_id",
        "ip_address",
        "user_agent",
        "success",
        "created_at",
    }

    assert set(event) == expected_fields

    forbidden_fields = {
        "password",
        "encrypted_password",
        "encryption_key",
        "master_password",
    }

    assert forbidden_fields.isdisjoint(event)


def test_audit_events_include_credential_activity(
    authenticated_client: TestClient,
) -> None:
    """Credential operations should appear in the audit log."""
    create_response = authenticated_client.post(
        "/api/v1/credentials",
        json={
            "name": "Audit API Test",
            "username": "api-user",
            "password": "StrongPassword-123!",
            "url": "https://example.com",
            "category": "Testing",
            "notes": "Audit API test credential.",
            "is_favorite": True,
        },
    )

    assert create_response.status_code == 201

    credential_id = create_response.json()["id"]

    response = authenticated_client.get(
        "/api/v1/audit/events",
        params={"event_type": "credential_created"},
    )

    assert response.status_code == 200

    payload = response.json()

    matching_events = [
        event
        for event in payload["items"]
        if event["credential_id"] == credential_id
    ]

    assert matching_events

    event = matching_events[0]

    assert event["event_type"] == "credential_created"
    assert event["success"] is True
    assert "password" not in event["description"].lower()


def test_audit_events_are_newest_first(
    authenticated_client: TestClient,
) -> None:
    """Audit events should be returned newest first."""
    response = authenticated_client.get(
        "/api/v1/audit/events",
        params={"limit": 2},
    )

    assert response.status_code == 200

    items = response.json()["items"]

    assert len(items) == 2

    assert (
        items[0]["created_at"],
        items[0]["id"],
    ) >= (
        items[1]["created_at"],
        items[1]["id"],
    )
