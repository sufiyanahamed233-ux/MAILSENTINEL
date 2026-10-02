from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.email import Email


class URL(Base):
    """Stores URLs extracted from an email."""

    __tablename__ = "urls"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("emails.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    normalized_url: Mapped[str | None] = mapped_column(
        Text,
        index=True,
        nullable=True,
    )
    domain: Mapped[str | None] = mapped_column(
        String(255),
        index=True,
        nullable=True,
    )
    scheme: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )
    path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    reputation: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationship
    email: Mapped[Email] = relationship(
        "Email",
        back_populates="urls",
    )


class Domain(Base):
    """Stores domains associated with an email or investigation."""

    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("emails.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    domain: Mapped[str] = mapped_column(
        String(255),
        index=True,
        nullable=False,
    )
    registrar: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    reputation: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationship
    email: Mapped[Email | None] = relationship(
        "Email",
        back_populates="domains",
    )


class IPAddress(Base):
    """Stores IP addresses extracted from email headers and network infrastructure.

    Note:
        Geolocation fields represent approximate network/infrastructure geolocation,
        NOT exact physical attacker location.
    """

    __tablename__ = "ip_addresses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("emails.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(45),
        index=True,
        nullable=False,
    )
    version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    asn: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    organization: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    country: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    region: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    city: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    latitude: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    longitude: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    reputation: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationship
    email: Mapped[Email | None] = relationship(
        "Email",
        back_populates="ip_addresses",
    )
