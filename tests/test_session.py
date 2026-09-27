"""Tests for secure in-memory vault session management."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from password_vault.auth.session import (
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    MAX_SESSION_TIMEOUT_MINUTES,
    MIN_SESSION_TIMEOUT_MINUTES,
    InvalidSessionError,
    SessionExpiredError,
    VaultSessionManager,
)


BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
ENCRYPTION_KEY = b"k" * 32


def test_create_session_generates_session_id() -> None:
    manager = VaultSessionManager()

    session = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    assert session.session_id
    assert len(session.session_id) >= 32
    assert session.encryption_key == ENCRYPTION_KEY
    assert session.created_at == BASE_TIME
    assert session.last_activity_at == BASE_TIME
    assert session.expires_at == BASE_TIME + timedelta(
        minutes=DEFAULT_SESSION_TIMEOUT_MINUTES
    )


def test_session_ids_are_unique() -> None:
    manager = VaultSessionManager()

    first = manager.create_session(ENCRYPTION_KEY, now=BASE_TIME)
    second = manager.create_session(ENCRYPTION_KEY, now=BASE_TIME)

    assert first.session_id != second.session_id


def test_get_session_returns_valid_session() -> None:
    manager = VaultSessionManager()

    created = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    retrieved = manager.get_session(
        created.session_id,
        now=BASE_TIME + timedelta(minutes=1),
    )

    assert retrieved is created
    assert retrieved.encryption_key == ENCRYPTION_KEY


def test_get_session_refreshes_inactivity_timeout() -> None:
    manager = VaultSessionManager(timeout_minutes=15)

    created = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    activity_time = BASE_TIME + timedelta(minutes=5)

    retrieved = manager.get_session(
        created.session_id,
        now=activity_time,
    )

    assert retrieved.last_activity_at == activity_time
    assert retrieved.expires_at == activity_time + timedelta(minutes=15)


def test_get_session_can_skip_touching_activity() -> None:
    manager = VaultSessionManager(timeout_minutes=15)

    created = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    original_expiration = created.expires_at

    retrieved = manager.get_session(
        created.session_id,
        now=BASE_TIME + timedelta(minutes=5),
        touch=False,
    )

    assert retrieved.last_activity_at == BASE_TIME
    assert retrieved.expires_at == original_expiration


def test_expired_session_is_rejected() -> None:
    manager = VaultSessionManager(timeout_minutes=15)

    created = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    with pytest.raises(SessionExpiredError):
        manager.get_session(
            created.session_id,
            now=BASE_TIME + timedelta(minutes=15),
        )

    assert manager.active_session_count() == 0
    assert created.encryption_key == b""


def test_session_before_expiration_is_valid() -> None:
    manager = VaultSessionManager(timeout_minutes=15)

    created = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    retrieved = manager.get_session(
        created.session_id,
        now=BASE_TIME + timedelta(minutes=14, seconds=59),
    )

    assert retrieved.encryption_key == ENCRYPTION_KEY


def test_lock_session_removes_session_and_key() -> None:
    manager = VaultSessionManager()

    created = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    manager.lock_session(created.session_id)

    assert created.encryption_key == b""
    assert manager.active_session_count() == 0

    with pytest.raises(InvalidSessionError):
        manager.get_session(created.session_id)


def test_lock_unknown_session_fails() -> None:
    manager = VaultSessionManager()

    with pytest.raises(InvalidSessionError):
        manager.lock_session("unknown-session")


def test_unknown_session_fails() -> None:
    manager = VaultSessionManager()

    with pytest.raises(InvalidSessionError):
        manager.get_session("unknown-session")


def test_empty_session_id_fails() -> None:
    manager = VaultSessionManager()

    with pytest.raises(InvalidSessionError):
        manager.get_session("")


def test_empty_encryption_key_fails() -> None:
    manager = VaultSessionManager()

    with pytest.raises(ValueError):
        manager.create_session(b"", now=BASE_TIME)


def test_non_bytes_encryption_key_fails() -> None:
    manager = VaultSessionManager()

    with pytest.raises(TypeError):
        manager.create_session("not-a-key", now=BASE_TIME)  # type: ignore[arg-type]


def test_minimum_timeout_is_accepted() -> None:
    manager = VaultSessionManager(
        timeout_minutes=MIN_SESSION_TIMEOUT_MINUTES,
    )

    assert manager.timeout_minutes == MIN_SESSION_TIMEOUT_MINUTES


def test_maximum_timeout_is_accepted() -> None:
    manager = VaultSessionManager(
        timeout_minutes=MAX_SESSION_TIMEOUT_MINUTES,
    )

    assert manager.timeout_minutes == MAX_SESSION_TIMEOUT_MINUTES


def test_timeout_below_minimum_fails() -> None:
    with pytest.raises(ValueError):
        VaultSessionManager(
            timeout_minutes=MIN_SESSION_TIMEOUT_MINUTES - 1,
        )


def test_timeout_above_maximum_fails() -> None:
    with pytest.raises(ValueError):
        VaultSessionManager(
            timeout_minutes=MAX_SESSION_TIMEOUT_MINUTES + 1,
        )


def test_non_integer_timeout_fails() -> None:
    with pytest.raises(TypeError):
        VaultSessionManager(timeout_minutes=15.5)  # type: ignore[arg-type]


def test_clear_expired_sessions_removes_only_expired_sessions() -> None:
    manager = VaultSessionManager(timeout_minutes=15)

    first = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    second = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME + timedelta(minutes=10),
    )

    removed = manager.clear_expired_sessions(
        now=BASE_TIME + timedelta(minutes=15),
    )

    assert removed == 1
    assert first.encryption_key == b""
    assert second.encryption_key == ENCRYPTION_KEY
    assert manager.active_session_count() == 1


def test_clear_expired_sessions_returns_zero_when_none_expired() -> None:
    manager = VaultSessionManager()

    manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    removed = manager.clear_expired_sessions(
        now=BASE_TIME + timedelta(minutes=1),
    )

    assert removed == 0
    assert manager.active_session_count() == 1


def test_session_expiration_uses_utc_timestamps() -> None:
    manager = VaultSessionManager(timeout_minutes=10)

    session = manager.create_session(
        ENCRYPTION_KEY,
        now=BASE_TIME,
    )

    assert session.created_at.tzinfo == timezone.utc
    assert session.last_activity_at.tzinfo == timezone.utc
    assert session.expires_at.tzinfo == timezone.utc


def test_multiple_sessions_are_independent() -> None:
    manager = VaultSessionManager()

    first_key = b"a" * 32
    second_key = b"b" * 32

    first = manager.create_session(
        first_key,
        now=BASE_TIME,
    )

    second = manager.create_session(
        second_key,
        now=BASE_TIME,
    )

    manager.lock_session(first.session_id)

    assert first.encryption_key == b""
    assert second.encryption_key == second_key
    assert manager.active_session_count() == 1


def test_session_count_tracks_active_sessions() -> None:
    manager = VaultSessionManager()

    assert manager.active_session_count() == 0

    first = manager.create_session(ENCRYPTION_KEY, now=BASE_TIME)
    assert manager.active_session_count() == 1

    second = manager.create_session(ENCRYPTION_KEY, now=BASE_TIME)
    assert manager.active_session_count() == 2

    manager.lock_session(first.session_id)
    assert manager.active_session_count() == 1

    manager.lock_session(second.session_id)
    assert manager.active_session_count() == 0
