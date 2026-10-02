from collections.abc import Generator
from typing import Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

# Build engine configuration arguments
engine_kwargs: dict[str, Any] = {
    "pool_pre_ping": True,
    "echo": settings.DB_ECHO,
}

# Apply pool sizing and connection arguments for PostgreSQL
if not settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs.update(
        {
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
            "pool_recycle": settings.DB_POOL_RECYCLE,
            "connect_args": {"connect_timeout": settings.DB_CONNECT_TIMEOUT},
        }
    )

# SQLAlchemy 2.x Engine
engine = create_engine(
    settings.DATABASE_URL,
    **engine_kwargs,
)

# SQLAlchemy session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency generator that yields a database session and guarantees closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> tuple[bool, str | None]:
    """Internal health check verifying database connectivity with a lightweight ping (SELECT 1)."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:
        return False, str(exc)

