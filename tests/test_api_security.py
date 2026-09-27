"""Tests for password-security API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from password_vault.api.app import app
from password_vault.api.dependencies import SESSION_COOKIE_NAME
from password_vault.database import Base, engine
from password_vault.models import AuditEvent, Credential, VaultMetadata
from password_vault.services.vault_service import VaultService


MASTER_PASSWORD = "CorrectHorseBatteryStaple!2026"


def reset_database() -> None:
    """Reset database tables between API tests."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def authenticate_client(client: TestClient) -> None:
    """Initialize and authenticate a test client."""
    reset_database()

    response = client.post(
        "/api/v1/auth/initialize",
        json={"master_password": MASTER_PASSWORD},
    )

    assert response.status_code == 201

    response = client.post(
        "/api/v1/auth/login",
        json={"master_password": MASTER_PASSWORD},
    )

    assert response.status_code == 200
    assert SESSION_COOKIE_NAME in client.cookies


def test_generate_password_requires_authentication() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/security/generate-password",
            json={"length": 24},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."


def test_analyze_password_requires_authentication() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": "ExamplePassword123!"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."


def test_generate_password_returns_requested_length() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/generate-password",
            json={"length": 40},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["length"] == 40
    assert len(data["password"]) == 40


def test_generate_password_includes_requested_character_classes() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/generate-password",
            json={
                "length": 32,
                "include_lowercase": True,
                "include_uppercase": True,
                "include_digits": True,
                "include_symbols": True,
            },
        )

    assert response.status_code == 200

    password = response.json()["password"]

    assert any(character.islower() for character in password)
    assert any(character.isupper() for character in password)
    assert any(character.isdigit() for character in password)
    assert any(
        not character.isalnum()
        for character in password
    )


def test_generate_password_can_disable_character_classes() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/generate-password",
            json={
                "length": 24,
                "include_lowercase": True,
                "include_uppercase": False,
                "include_digits": False,
                "include_symbols": False,
            },
        )

    assert response.status_code == 200

    password = response.json()["password"]

    assert len(password) == 24
    assert all(character.islower() for character in password)


def test_generate_password_rejects_invalid_length() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/generate-password",
            json={"length": 15},
        )

    assert response.status_code == 422


def test_generate_password_rejects_unknown_fields() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/generate-password",
            json={
                "length": 24,
                "unexpected": True,
            },
        )

    assert response.status_code == 422


def test_analyze_password_returns_strength_information() -> None:
    password = "vQ7$kP2!xR9@Lm4#tY8&nC6?"

    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": password},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["length"] == len(password)
    assert data["strength"] == "strong"
    assert data["score"] >= 80
    assert data["entropy_bits"] > 80
    assert data["has_lowercase"] is True
    assert data["has_uppercase"] is True
    assert data["has_digits"] is True
    assert data["has_symbols"] is True
    assert data["is_common_password"] is False


def test_analyze_password_detects_common_password() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": "password123"},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["is_common_password"] is True
    assert data["strength"] == "weak"
    assert any(
        "common passwords" in message
        for message in data["feedback"]
    )


def test_analyze_password_detects_repeated_characters() -> None:
    password = "SecurePasswordAAA123!"

    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": password},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["has_repeated_characters"] is True


def test_analyze_password_detects_sequential_patterns() -> None:
    password = "SecurePassword1234!"

    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": password},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["has_sequential_pattern"] is True


def test_analyze_password_rejects_empty_password() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": ""},
        )

    assert response.status_code == 422


def test_analyze_password_rejects_unknown_fields() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/analyze-password",
            json={
                "password": "ExamplePassword123!",
                "unexpected": True,
            },
        )

    assert response.status_code == 422


def test_analyze_password_does_not_return_submitted_password() -> None:
    password = "ThisIsASecretPassword123!"

    with TestClient(app) as client:
        authenticate_client(client)

        response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": password},
        )

    assert response.status_code == 200

    data = response.json()

    assert "password" not in data
    assert password not in response.text


def test_password_security_endpoints_do_not_create_audit_events() -> None:
    with TestClient(app) as client:
        authenticate_client(client)

        before_events = len(
            client.get("/api/v1/audit/events").json()["items"]
        )

        generate_response = client.post(
            "/api/v1/security/generate-password",
            json={"length": 24},
        )

        assert generate_response.status_code == 200

        analyze_response = client.post(
            "/api/v1/security/analyze-password",
            json={"password": "ExamplePassword123!"},
        )

        assert analyze_response.status_code == 200

        after_events = len(
            client.get("/api/v1/audit/events").json()["items"]
        )

    assert after_events == before_events
