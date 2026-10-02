"""AI analysis orchestration service for MAILSENTINEL.

Coordinates the full AI threat-analysis pipeline for a given case:

1. Build deterministic forensic context from PostgreSQL via build_ai_context()
2. Invoke the configured AIProvider (GeminiProvider by default)
3. Validate the returned AIThreatAssessment via Pydantic v2
4. Persist a new AIAnalysisResult linked to the case

This service:
- Never modifies forensic evidence or threat-intelligence records
- Never logs or exposes API keys or raw email body content
- Keeps provider abstraction intact for easy swap to another provider
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.ai_analysis import AIAnalysisResult
from app.schemas.ai_analysis import AIAnalysisContext, AIThreatAssessment, AIThreatIndicator
from app.services.ai.context_builder import CaseNotFoundError, build_ai_context
from app.services.ai.exceptions import (
    AIAuthenticationError,
    AIConfigurationError,
    AINetworkError,
    AIProviderError,
    AIRateLimitError,
    AIResponseParsingError,
    AISchemaValidationError,
)
from app.services.ai.gemini import GeminiProvider
from app.services.ai.provider import AIProvider

logger = logging.getLogger(__name__)

# Prompt version — increment when system instruction or schema changes
PROMPT_VERSION = "v1.0.0"


# ---------------------------------------------------------------------------
# Service-level errors
# ---------------------------------------------------------------------------

class AIAnalysisServiceError(Exception):
    """Base class for orchestration-layer errors."""

    def __init__(self, message: str, *, http_status: int = 500) -> None:
        super().__init__(message)
        self.message = message
        self.http_status = http_status


class CaseNotFoundServiceError(AIAnalysisServiceError):
    """Raised when the target case does not exist."""

    def __init__(self, case_id: uuid.UUID) -> None:
        super().__init__(
            f"Case '{case_id}' not found.",
            http_status=404,
        )
        self.case_id = case_id


class ProviderNotConfiguredError(AIAnalysisServiceError):
    """Raised when the AI provider is not properly configured (e.g. missing API key)."""

    def __init__(self) -> None:
        super().__init__(
            "AI provider is not configured. Set GEMINI_API_KEY in the environment.",
            http_status=503,
        )


class ProviderUnavailableError(AIAnalysisServiceError):
    """Raised on transient provider errors (network, rate limit, server)."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            f"AI provider temporarily unavailable: {detail}",
            http_status=503,
        )


class ProviderResponseError(AIAnalysisServiceError):
    """Raised when the provider returns an invalid or non-conformant response."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            f"AI provider returned an invalid response: {detail}",
            http_status=502,
        )


class ProviderAuthError(AIAnalysisServiceError):
    """Raised on authentication failures with the provider."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            f"AI provider authentication failed: {detail}",
            http_status=503,
        )


# ---------------------------------------------------------------------------
# Field mapping helpers
# ---------------------------------------------------------------------------

def _indicators_to_jsonb(indicators: list[AIThreatIndicator]) -> list[dict]:
    """Serialize AIThreatIndicator list to a JSON-serializable list of dicts."""
    return [ind.model_dump() for ind in indicators]


def _list_to_jsonb(items: list[str]) -> list[str]:
    """Ensure a list of strings is JSON-serializable (identity for pure str lists)."""
    return list(items)


# ---------------------------------------------------------------------------
# Internal persistence helper
# ---------------------------------------------------------------------------

def _persist_assessment(
    db: Session,
    case_id: uuid.UUID,
    assessment: AIThreatAssessment,
    provider: AIProvider,
) -> AIAnalysisResult:
    """Map AIThreatAssessment fields into AIAnalysisResult and persist to PostgreSQL.

    Args:
        db: Active SQLAlchemy database session.
        case_id: UUID of the owning case.
        assessment: Validated Pydantic assessment model returned by the provider.
        provider: The AIProvider instance used to produce the assessment.

    Returns:
        The freshly committed AIAnalysisResult ORM row (id, created_at populated).
    """
    result = AIAnalysisResult(
        case_id=case_id,
        # Core assessment fields
        classification=assessment.classification,
        risk_score=assessment.risk_score,
        confidence=assessment.confidence,
        reasoning=assessment.reasoning,
        # JSONB list columns
        threat_indicators=_indicators_to_jsonb(assessment.threat_indicators),
        supporting_evidence=_list_to_jsonb(assessment.supporting_evidence),
        attack_techniques=_list_to_jsonb(assessment.attack_techniques),
        recommended_actions=_list_to_jsonb(assessment.recommended_actions),
        # Provider provenance — never include API keys
        model=provider.model_name,
        provider=provider.provider_name,
        prompt_version=PROMPT_VERSION,
    )

    db.add(result)
    db.commit()
    db.refresh(result)
    return result


# ---------------------------------------------------------------------------
# Public orchestration function
# ---------------------------------------------------------------------------

def run_ai_analysis(
    db: Session,
    case_id: uuid.UUID,
    provider: AIProvider | None = None,
) -> AIAnalysisResult:
    """Orchestrate the full AI threat-analysis pipeline for a case.

    Steps:
    1. Build deterministic forensic context from the database.
    2. Invoke the AI provider (sync).
    3. Persist the validated assessment as AIAnalysisResult.

    Args:
        db: Active SQLAlchemy session (used for context building and persistence).
        case_id: UUID of the case to analyse.
        provider: Optional AIProvider override; defaults to GeminiProvider.

    Returns:
        Freshly persisted AIAnalysisResult ORM row.

    Raises:
        CaseNotFoundServiceError: If case does not exist.
        ProviderNotConfiguredError: If the provider's API key is missing.
        ProviderAuthError: If the provider rejects credentials.
        ProviderUnavailableError: If a transient network/rate-limit error occurs.
        ProviderResponseError: If the provider response is empty, invalid JSON, or fails schema validation.
        AIAnalysisServiceError: On any other unexpected error.
    """
    # Step 0: Resolve provider
    if provider is None:
        provider = GeminiProvider()

    if not provider.is_configured():
        raise ProviderNotConfiguredError()

    # Step 1: Build forensic context (read-only DB access)
    logger.info("Building AI context for case_id=%s", case_id)
    try:
        context: AIAnalysisContext = build_ai_context(db, case_id)
    except CaseNotFoundError as exc:
        raise CaseNotFoundServiceError(case_id) from exc

    # Step 2: Invoke the AI provider
    logger.info(
        "Invoking AI provider '%s' (model=%s) for case_id=%s",
        provider.provider_name,
        provider.model_name,
        case_id,
    )
    try:
        assessment: AIThreatAssessment = provider.analyze(context)
    except AIConfigurationError as exc:
        raise ProviderNotConfiguredError() from exc
    except AIAuthenticationError as exc:
        # exc.message already sanitized by GeminiProvider
        raise ProviderAuthError(exc.message) from exc
    except (AIRateLimitError, AINetworkError) as exc:
        raise ProviderUnavailableError(exc.message) from exc
    except (AIResponseParsingError, AISchemaValidationError) as exc:
        raise ProviderResponseError(exc.message) from exc
    except AIProviderError as exc:
        raise ProviderUnavailableError(exc.message) from exc

    # Step 3: Persist (forensic records untouched)
    logger.info(
        "Persisting AI assessment for case_id=%s: classification=%s risk_score=%s",
        case_id,
        assessment.classification,
        assessment.risk_score,
    )
    return _persist_assessment(db, case_id, assessment, provider)


async def run_ai_analysis_async(
    db: Session,
    case_id: uuid.UUID,
    provider: AIProvider | None = None,
) -> AIAnalysisResult:
    """Asynchronous variant of run_ai_analysis.

    Args:
        db: Active SQLAlchemy session.
        case_id: UUID of the case to analyse.
        provider: Optional AIProvider override; defaults to GeminiProvider.

    Returns:
        Freshly persisted AIAnalysisResult ORM row.

    Raises:
        Same exceptions as run_ai_analysis.
    """
    if provider is None:
        provider = GeminiProvider()

    if not provider.is_configured():
        raise ProviderNotConfiguredError()

    # Step 1: Build context (read-only, sync)
    logger.info("Building AI context (async) for case_id=%s", case_id)
    try:
        context: AIAnalysisContext = build_ai_context(db, case_id)
    except CaseNotFoundError as exc:
        raise CaseNotFoundServiceError(case_id) from exc

    # Step 2: Async provider call
    logger.info(
        "Async invoking AI provider '%s' (model=%s) for case_id=%s",
        provider.provider_name,
        provider.model_name,
        case_id,
    )
    try:
        assessment: AIThreatAssessment = await provider.analyze_async(context)
    except AIConfigurationError as exc:
        raise ProviderNotConfiguredError() from exc
    except AIAuthenticationError as exc:
        raise ProviderAuthError(exc.message) from exc
    except (AIRateLimitError, AINetworkError) as exc:
        raise ProviderUnavailableError(exc.message) from exc
    except (AIResponseParsingError, AISchemaValidationError) as exc:
        raise ProviderResponseError(exc.message) from exc
    except AIProviderError as exc:
        raise ProviderUnavailableError(exc.message) from exc

    # Step 3: Persist
    logger.info(
        "Persisting AI assessment (async) for case_id=%s: classification=%s risk_score=%s",
        case_id,
        assessment.classification,
        assessment.risk_score,
    )
    return _persist_assessment(db, case_id, assessment, provider)
