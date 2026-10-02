from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.ai_analysis import AIAnalysisResult
    from app.models.email import Email
    from app.models.evidence import Evidence
    from app.models.indicator import ThreatIndicator
    from app.models.investigation import InvestigationEvent
    from app.models.threat_intel import ThreatIntelligenceResult



class Case(Base):
    """Represents a forensic investigation case."""

    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    case_number: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="open",
        index=True,
        nullable=False,
    )
    priority: Mapped[str] = mapped_column(
        String(50),
        default="medium",
        index=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    emails: Mapped[list[Email]] = relationship(
        "Email",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    threat_indicators: Mapped[list[ThreatIndicator]] = relationship(
        "ThreatIndicator",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    evidence: Mapped[list[Evidence]] = relationship(
        "Evidence",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    investigation_events: Mapped[list[InvestigationEvent]] = relationship(
        "InvestigationEvent",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    threat_intelligence_results: Mapped[list[ThreatIntelligenceResult]] = relationship(
        "ThreatIntelligenceResult",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    ai_analysis_results: Mapped[list[AIAnalysisResult]] = relationship(
        "AIAnalysisResult",
        back_populates="case",
        cascade="all, delete-orphan",
    )

