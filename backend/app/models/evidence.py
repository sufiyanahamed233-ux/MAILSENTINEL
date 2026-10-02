from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.case import Case


class Evidence(Base):
    """Forensic evidence integrity and chain-of-custody records.

    Note:
        Blockchain verification references are exclusively for cryptographic audit
        proofs and integrity verification. Email contents and raw forensic payloads
        must never be stored on-chain.
    """

    __tablename__ = "evidence"

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
    evidence_type: Mapped[str] = mapped_column(
        String(100),
        index=True,
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    collected_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    blockchain_tx_id: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
        nullable=True,
    )
    blockchain_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationship
    case: Mapped[Case] = relationship(
        "Case",
        back_populates="evidence",
    )
