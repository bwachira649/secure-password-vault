"""Database configuration and session management for the password vault."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIR / "vault.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


def get_db() -> Generator[Session, None, None]:
    """Provide a database session and close it after use."""
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def init_database() -> None:
    """Create all registered database tables."""
    from password_vault.models import AuditEvent, Credential, VaultMetadata

    # Importing the models registers their tables with Base.metadata.
    _ = (AuditEvent, Credential, VaultMetadata)

    Base.metadata.create_all(bind=engine)


__all__ = [
    "Base",
    "DATABASE_PATH",
    "DATABASE_URL",
    "DATA_DIR",
    "SessionLocal",
    "engine",
    "get_db",
    "init_database",
]
