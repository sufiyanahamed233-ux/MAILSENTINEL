from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
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


class AIAnalysisResult(Base):
    """AI-generated threat-analysis assessment for a forensic case.

    This model stores results produced by an AI analysis engine as a separate
    assessment layer.  AI conclusions are *never* authoritative replacements
    for observed forensic evidence or external threat-intelligence records.
    """

    __tablename__ = "ai_analysis_results"

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
    classification: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )
    risk_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    reasoning: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    threat_indicators: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        nullable=True,
    )
    supporting_evidence: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        nullable=True,
    )
    attack_techniques: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        nullable=True,
    )
    recommended_actions: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        nullable=True,
    )
    model: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    provider: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    prompt_version: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
        nullable=False,
    )

    # Relationship
    case: Mapped[Case] = relationship(
        "Case",
        back_populates="ai_analysis_results",
    )
