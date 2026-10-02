from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.case import Case


class ThreatIndicator(Base):
    """Normalized threat indicators discovered during forensic investigations."""

    __tablename__ = "threat_indicators"

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
    indicator_type: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )
    indicator_value: Mapped[str] = mapped_column(
        Text,
        index=True,
        nullable=False,
    )
    source: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    reputation: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    confidence: Mapped[int | None] = mapped_column(
        Integer,
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationship
    case: Mapped[Case] = relationship(
        "Case",
        back_populates="threat_indicators",
    )
