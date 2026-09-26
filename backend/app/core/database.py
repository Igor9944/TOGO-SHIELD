from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def ensure_production_schema() -> None:
    """Idempotent safety net for serverless deployments.

    Vercel does not run Alembic automatically. This makes the two required
    production schema changes self-healing: Telegram IDs must be BIGINT and
    file-analysis metadata columns must exist.
    """
    if settings.database_url.startswith("sqlite"):
        return

    with engine.begin() as connection:
        connection.execute(text("""
            ALTER TABLE scans
                ALTER COLUMN telegram_chat_id TYPE BIGINT,
                ALTER COLUMN telegram_user_id TYPE BIGINT,
                ALTER COLUMN telegram_message_id TYPE BIGINT
        """))
        connection.execute(text("""
            ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS file_name VARCHAR(255),
                ADD COLUMN IF NOT EXISTS file_type VARCHAR(64),
                ADD COLUMN IF NOT EXISTS file_size BIGINT,
                ADD COLUMN IF NOT EXISTS file_sha256 VARCHAR(64),
                ADD COLUMN IF NOT EXISTS extracted_text TEXT
        """))
        connection.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scans_file_sha256
            ON scans (file_sha256)
        """))
        # Keep Alembic's single revision marker aligned with the schema we just
        # ensured. The SQL is intentionally idempotent.
        connection.execute(text("""
            UPDATE alembic_version
            SET version_num = '0002_file_metadata'
            WHERE version_num IN ('0001', '20260925_telegram_ids_bigint')
        """))


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
