"""Secure in-memory session management for the password vault."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


DEFAULT_SESSION_TIMEOUT_MINUTES = 15
MIN_SESSION_TIMEOUT_MINUTES = 1
MAX_SESSION_TIMEOUT_MINUTES = 120


class SessionError(Exception):
    """Base exception for session management failures."""


class InvalidSessionError(SessionError):
    """Raised when a session does not exist or is no longer valid."""


class SessionExpiredError(SessionError):
    """Raised when a session has exceeded its allowed lifetime."""


@dataclass
class VaultSession:
    """Represent an authenticated vault session.

    The encryption key is held only in server-side process memory.
    It is never persisted to the database and must never be sent to
    the browser.
    """

    session_id: str
    encryption_key: bytes
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return whether the session has expired."""
        current_time = now or datetime.now(timezone.utc)
        return current_time >= self.expires_at

    def touch(
        self,
        *,
        now: datetime | None = None,
        timeout: timedelta | None = None,
    ) -> None:
        """Update activity time and extend the inactivity deadline."""
        current_time = now or datetime.now(timezone.utc)

        self.last_activity_at = current_time

        if timeout is not None:
            self.expires_at = current_time + timeout


class VaultSessionManager:
    """Manage authenticated vault sessions in process memory."""

    def __init__(
        self,
        *,
        timeout_minutes: int = DEFAULT_SESSION_TIMEOUT_MINUTES,
    ) -> None:
        self._validate_timeout(timeout_minutes)

        self._timeout = timedelta(minutes=timeout_minutes)
        self._sessions: dict[str, VaultSession] = {}
        self._lock = threading.RLock()

    @property
    def timeout_minutes(self) -> int:
        """Return the configured session timeout in minutes."""
        return int(self._timeout.total_seconds() // 60)

    def create_session(
        self,
        encryption_key: bytes,
        *,
        now: datetime | None = None,
    ) -> VaultSession:
        """Create an authenticated session for an encryption key."""
        if not isinstance(encryption_key, bytes):
            raise TypeError("Encryption key must be bytes.")

        if not encryption_key:
            raise ValueError("Encryption key cannot be empty.")

        current_time = now or datetime.now(timezone.utc)

        session_id = secrets.token_urlsafe(32)

        session = VaultSession(
            session_id=session_id,
            encryption_key=encryption_key,
            created_at=current_time,
            last_activity_at=current_time,
            expires_at=current_time + self._timeout,
        )

        with self._lock:
            self._sessions[session_id] = session

        return session

    def get_session(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
        touch: bool = True,
    ) -> VaultSession:
        """Return a valid session or raise an appropriate error."""
        if not isinstance(session_id, str) or not session_id:
            raise InvalidSessionError("Session ID is required.")

        with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                raise InvalidSessionError("Invalid or unknown session.")

            current_time = now or datetime.now(timezone.utc)

            if session.is_expired(current_time):
                self._destroy_session_locked(session_id)
                raise SessionExpiredError("Vault session has expired.")

            if touch:
                session.touch(
                    now=current_time,
                    timeout=self._timeout,
                )

            return session

    def lock_session(self, session_id: str) -> None:
        """Lock a session and remove its encryption key from the manager."""
        with self._lock:
            if session_id not in self._sessions:
                raise InvalidSessionError("Invalid or unknown session.")

            self._destroy_session_locked(session_id)

    def clear_expired_sessions(
        self,
        *,
        now: datetime | None = None,
    ) -> int:
        """Remove expired sessions and return the number removed."""
        current_time = now or datetime.now(timezone.utc)
        removed = 0

        with self._lock:
            expired_ids = [
                session_id
                for session_id, session in self._sessions.items()
                if session.is_expired(current_time)
            ]

            for session_id in expired_ids:
                self._destroy_session_locked(session_id)
                removed += 1

        return removed

    def active_session_count(self) -> int:
        """Return the number of currently stored sessions."""
        with self._lock:
            return len(self._sessions)

    def _destroy_session_locked(self, session_id: str) -> None:
        """Remove a session and overwrite its key reference before deletion."""
        session = self._sessions.pop(session_id, None)

        if session is not None:
            # Python does not provide guaranteed secure memory zeroization
            # for immutable bytes. Replacing the application reference with
            # an empty value ensures the manager no longer retains the key.
            session.encryption_key = b""

    @staticmethod
    def _validate_timeout(timeout_minutes: int) -> None:
        """Validate session timeout configuration."""
        if not isinstance(timeout_minutes, int):
            raise TypeError("Session timeout must be an integer.")

        if not (
            MIN_SESSION_TIMEOUT_MINUTES
            <= timeout_minutes
            <= MAX_SESSION_TIMEOUT_MINUTES
        ):
            raise ValueError(
                "Session timeout must be between "
                f"{MIN_SESSION_TIMEOUT_MINUTES} and "
                f"{MAX_SESSION_TIMEOUT_MINUTES} minutes."
            )


__all__ = [
    "DEFAULT_SESSION_TIMEOUT_MINUTES",
    "InvalidSessionError",
    "MAX_SESSION_TIMEOUT_MINUTES",
    "MIN_SESSION_TIMEOUT_MINUTES",
    "SessionError",
    "SessionExpiredError",
    "VaultSession",
    "VaultSessionManager",
]
