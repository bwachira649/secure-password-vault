"""Tests for audit-event service operations."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from password_vault.database import Base
from password_vault.services.vault_service import VaultService


MASTER_PASSWORD = "Correct-Horse-Battery-Staple-123"


@pytest.fixture
def db() -> Session:
    """Provide an isolated in-memory database session."""
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
def service(db: Session) -> VaultService:
    """Provide an initialized vault service."""
    vault_service = VaultService(db)
    vault_service.initialize_vault(MASTER_PASSWORD)
    return vault_service


def test_get_audit_events_returns_newest_events_first(
    service: VaultService,
) -> None:
    """Audit events should be returned in reverse chronological order."""
    service.record_event(
        event_type="test_first",
        description="First test event",
    )
    service.record_event(
        event_type="test_second",
        description="Second test event",
    )

    events = service.get_audit_events(limit=10)

    test_events = [
        event
        for event in events
        if event.event_type.startswith("test_")
    ]

    assert [event.event_type for event in test_events] == [
        "test_second",
        "test_first",
    ]


def test_get_audit_events_filters_by_event_type(
    service: VaultService,
) -> None:
    """The event_type filter should return only matching events."""
    service.record_event(
        event_type="credential_created",
        description="Credential created.",
    )
    service.record_event(
        event_type="credential_updated",
        description="Credential updated.",
    )
    service.record_event(
        event_type="credential_created",
        description="Another credential created.",
    )

    events = service.get_audit_events(
        limit=100,
        event_type="credential_created",
    )

    assert len(events) == 2
    assert all(
        event.event_type == "credential_created"
        for event in events
    )


def test_get_audit_events_returns_empty_for_unknown_event_type(
    service: VaultService,
) -> None:
    """An unknown event type should produce an empty result."""
    events = service.get_audit_events(
        event_type="does_not_exist",
    )

    assert events == []


def test_get_audit_events_rejects_empty_event_type(
    service: VaultService,
) -> None:
    """Blank event-type filters should be rejected."""
    with pytest.raises(
        ValueError,
        match="Audit event type cannot be empty",
    ):
        service.get_audit_events(event_type="   ")


def test_get_audit_events_rejects_invalid_limit(
    service: VaultService,
) -> None:
    """Audit-event limits below one should be rejected."""
    with pytest.raises(
        ValueError,
        match="Audit event limit must be at least 1",
    ):
        service.get_audit_events(limit=0)


def test_get_audit_events_caps_large_limit(
    service: VaultService,
) -> None:
    """Audit-event requests should be capped at 500 records."""
    for index in range(510):
        service.record_event(
            event_type="bulk_test",
            description=f"Bulk test event {index}.",
        )

    events = service.get_audit_events(
        limit=1000,
        event_type="bulk_test",
    )

    assert len(events) == 500


def test_get_audit_events_preserves_credential_reference(
    service: VaultService,
) -> None:
    """Audit events should retain their credential reference."""
    encryption_key = service.authenticate(MASTER_PASSWORD)

    credential = service.create_credential(
        name="Audit Test",
        username="audit-user",
        password="AuditPassword-123!",
        encryption_key=encryption_key,
    )

    events = service.get_audit_events(
        event_type="credential_created",
    )

    matching = [
        event
        for event in events
        if event.credential_id == credential.id
    ]

    assert matching
    assert matching[0].success is True
