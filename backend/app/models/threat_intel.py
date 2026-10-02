from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.case import Case


class ThreatIntelligenceResult(Base):
    """External threat intelligence enrichment records (VirusTotal, AbuseIPDB, etc.).

    Stores external reputation lookups separate from observed forensic artifacts.
    """

    __tablename__ = "threat_intelligence_results"

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
        String(2048),
        index=True,
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )
    queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )
    reputation: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    malicious_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    suspicious_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    harmless_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    country: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    asn: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
    )
    organization: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    raw_response: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
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
        back_populates="threat_intelligence_results",
    )
