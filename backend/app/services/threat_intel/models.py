from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"


class EnrichmentStatus(str, Enum):
    SUCCESS = "success"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


class ReputationLevel(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class NormalizedThreatResult(BaseModel):
    """Normalized external threat intelligence enrichment result."""

    model_config = ConfigDict(from_attributes=True)

    provider: str
    indicator_type: str
    indicator_value: str
    status: str
    reputation: str | None = None
    confidence: float | None = None
    malicious_count: int | None = None
    suspicious_count: int | None = None
    harmless_count: int | None = None
    country: str | None = None
    asn: int | None = None
    organization: str | None = None
    queried_at: datetime
    raw_response: dict[str, Any] | None = None
    error_message: str | None = None


class CaseEnrichmentSummary(BaseModel):
    """Structured response for case threat intelligence enrichment."""

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID
    total_indicators: int
    total_queries: int
    cached_results: int
    fresh_results: int
    providers_used: list[str] = Field(default_factory=list)
    results: list[NormalizedThreatResult] = Field(default_factory=list)
