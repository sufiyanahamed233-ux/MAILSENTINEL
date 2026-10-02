from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.case import Case
    from app.models.network import Domain, IPAddress, URL


class Email(Base):
    """Represents an analyzed email associated with a forensic investigation case."""

    __tablename__ = "emails"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    message_id: Mapped[str | None] = mapped_column(
        String(255),
        index=True,
        nullable=True,
    )
    subject: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    sender: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    sender_domain: Mapped[str | None] = mapped_column(
        String(255),
        index=True,
        nullable=True,
    )
    reply_to: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    raw_file_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    raw_file_hash: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    analysis_status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        index=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    case: Mapped[Case] = relationship(
        "Case",
        back_populates="emails",
    )
    headers: Mapped[list[EmailHeader]] = relationship(
        "EmailHeader",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    urls: Mapped[list[URL]] = relationship(
        "URL",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    domains: Mapped[list[Domain]] = relationship(
        "Domain",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    ip_addresses: Mapped[list[IPAddress]] = relationship(
        "IPAddress",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    attachments: Mapped[list[Attachment]] = relationship(
        "Attachment",
        back_populates="email",
        cascade="all, delete-orphan",
    )


class EmailHeader(Base):
    """Stores extracted technical email-header information."""

    __tablename__ = "email_headers"

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
    header_name: Mapped[str] = mapped_column(
        String(255),
        index=True,
        nullable=False,
    )
    header_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    header_order: Mapped[int | None] = mapped_column(
        Integer,
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
        back_populates="headers",
    )


class Attachment(Base):
    """Stores metadata for email attachments without binary storage in the database."""

    __tablename__ = "attachments"

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
    file_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    content_type: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    file_size: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
    )
    sha256: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    md5: Mapped[str | None] = mapped_column(
        String(32),
        index=True,
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
        back_populates="attachments",
    )
