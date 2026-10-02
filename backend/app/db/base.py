from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models in MAILSENTINEL."""
    pass


# Import models so Base.metadata is fully populated with all entity tables
from app import models  # noqa: F401, E402

