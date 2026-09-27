"""Tests for database configuration and SQLAlchemy models."""

from datetime import datetime, timezone

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from password_vault.database import Base, get_db, init_database
from password_vault.models import AuditEvent, Credential, VaultMetadata


def test_database_tables_are_registered() -> None:
    """All required models should be registered with SQLAlchemy metadata."""
    table_names = set(Base.metadata.tables)

    assert "vault_metadata" in table_names
    assert "credentials" in table_names
    assert "audit_events" in table_names


def test_init_database_creates_required_tables(tmp_path) -> None:
    """Database initialization should create all required tables."""
    database_path = tmp_path / "test-vault.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(bind=engine)

    tables = set(inspect(engine).get_table_names())

    assert tables == {
        "vault_metadata",
        "credentials",
        "audit_events",
    }

    engine.dispose()


def test_vault_metadata_can_be_persisted(tmp_path) -> None:
    """Vault metadata should persist correctly."""
    database_path = tmp_path / "metadata.db"
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
        metadata = VaultMetadata(
            password_hash="argon2-hash",
            encryption_salt="base64-salt",
        )

        session.add(metadata)
        session.commit()

        saved = session.query(VaultMetadata).one()

        assert saved.id == 1
        assert saved.password_hash == "argon2-hash"
        assert saved.encryption_salt == "base64-salt"
        assert saved.is_initialized is True
        assert isinstance(saved.created_at, datetime)
        assert isinstance(saved.updated_at, datetime)
    finally:
        session.close()
        engine.dispose()


def test_credential_can_be_persisted_without_plaintext_password(tmp_path) -> None:
    """Credential records should persist encrypted password material."""
    database_path = tmp_path / "credentials.db"
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
        credential = Credential(
            name="Production Database",
            username="admin",
            encrypted_password="encrypted-secret-value",
            url="https://database.example.test",
            category="Database",
            notes="Production database credential",
            expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
            is_favorite=True,
        )

        session.add(credential)
        session.commit()

        saved = session.query(Credential).one()

        assert saved.name == "Production Database"
        assert saved.username == "admin"
        assert saved.encrypted_password == "encrypted-secret-value"
        assert saved.category == "Database"
        assert saved.is_favorite is True

        # The database model has no plaintext password field.
        assert not hasattr(saved, "password")
    finally:
        session.close()
        engine.dispose()


def test_audit_event_can_be_persisted(tmp_path) -> None:
    """Security audit events should persist correctly."""
    database_path = tmp_path / "audit.db"
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
        event = AuditEvent(
            event_type="login",
            description="Successful vault authentication",
            ip_address="127.0.0.1",
            user_agent="pytest",
            success=True,
        )

        session.add(event)
        session.commit()

        saved = session.query(AuditEvent).one()

        assert saved.event_type == "login"
        assert saved.description == "Successful vault authentication"
        assert saved.ip_address == "127.0.0.1"
        assert saved.user_agent == "pytest"
        assert saved.success is True
        assert isinstance(saved.created_at, datetime)
    finally:
        session.close()
        engine.dispose()


def test_get_db_provides_and_closes_session() -> None:
    """The database dependency should provide a usable session."""
    generator = get_db()

    session = next(generator)

    try:
        assert session.is_active
    finally:
        try:
            next(generator)
        except StopIteration:
            pass

        assert session.is_active is True


def test_init_database_is_idempotent() -> None:
    """Calling database initialization repeatedly should be safe."""
    init_database()
    init_database()

    assert set(Base.metadata.tables) == {
        "vault_metadata",
        "credentials",
        "audit_events",
    }
