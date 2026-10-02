"""Tests for Phase 4D — AI Analysis Orchestration, Persistence, and API.

Covers:
1.  Orchestrator: successful sync pipeline (build_context -> provider -> persist)
2.  Orchestrator: successful async pipeline
3.  Orchestrator: CaseNotFoundError -> CaseNotFoundServiceError
4.  Orchestrator: missing API key -> ProviderNotConfiguredError
5.  Orchestrator: provider AIAuthenticationError -> ProviderAuthError
6.  Orchestrator: provider AIRateLimitError -> ProviderUnavailableError
7.  Orchestrator: provider AINetworkError -> ProviderUnavailableError
8.  Orchestrator: provider AIResponseParsingError -> ProviderResponseError
9.  Orchestrator: provider AISchemaValidationError -> ProviderResponseError
10. Orchestrator: forensic/threat-intel records never modified
11. Persistence: all AIThreatAssessment fields mapped to AIAnalysisResult columns
12. Persistence: provider provenance (model, provider, prompt_version) recorded
13. API: POST /api/v1/cases/{case_id}/ai-analysis returns 201 with response schema
14. API: 404 when case does not exist
15. API: 503 when provider not configured
16. API: 503 when provider authentication fails
17. API: 503 when provider is rate-limited or network failure
18. API: 502 when provider returns invalid response
19. API: response excludes API keys and raw email bodies
20. Schema: AIAnalysisResultResponse Pydantic validation
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.ai_analysis import (
    AIAnalysisResultResponse,
    AIThreatAssessment,
    AIThreatIndicator,
)
from app.services.ai.exceptions import (
    AIAuthenticationError,
    AINetworkError,
    AIRateLimitError,
    AIResponseParsingError,
    AISchemaValidationError,
)
from app.services.ai.orchestrator import (
    AIAnalysisServiceError,
    CaseNotFoundServiceError,
    PROMPT_VERSION,
    ProviderAuthError,
    ProviderNotConfiguredError,
    ProviderResponseError,
    ProviderUnavailableError,
    _persist_assessment,
    run_ai_analysis,
    run_ai_analysis_async,
)
from app.services.ai.context_builder import CaseNotFoundError


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def make_assessment(
    classification: str = "malicious",
    risk_score: int = 88,
    confidence: float = 0.95,
    reasoning: str = "Phishing indicators detected.",
    threat_indicators: list | None = None,
    supporting_evidence: list | None = None,
    attack_techniques: list | None = None,
    recommended_actions: list | None = None,
) -> AIThreatAssessment:
    """Return a minimal valid AIThreatAssessment for testing."""
    return AIThreatAssessment(
        classification=classification,
        risk_score=risk_score,
        confidence=confidence,
        reasoning=reasoning,
        threat_indicators=threat_indicators or [
            AIThreatIndicator(
                indicator_type="domain",
                indicator_value="evil.example.com",
                threat_type="phishing",
                severity="high",
                description="VirusTotal flagged domain.",
            )
        ],
        supporting_evidence=supporting_evidence or ["Domain flagged by 15 VT vendors."],
        attack_techniques=attack_techniques or ["T1566.001 - Spearphishing Attachment"],
        recommended_actions=recommended_actions or ["Block domain on firewall."],
    )


def make_mock_provider(assessment: AIThreatAssessment | None = None) -> MagicMock:
    """Build a mock AIProvider that returns the given assessment."""
    a = assessment or make_assessment()
    provider = MagicMock()
    provider.is_configured.return_value = True
    provider.provider_name = "gemini"
    provider.model_name = "gemini-3.8-flash"
    provider.analyze.return_value = a
    provider.analyze_async = AsyncMock(return_value=a)
    return provider


def make_mock_db_result(assessment: AIThreatAssessment, case_id: uuid.UUID) -> MagicMock:
    """Build a MagicMock that mimics an AIAnalysisResult ORM row."""
    result = MagicMock()
    result.id = uuid.uuid4()
    result.case_id = case_id
    result.classification = assessment.classification
    result.risk_score = assessment.risk_score
    result.confidence = assessment.confidence
    result.reasoning = assessment.reasoning
    result.threat_indicators = [ind.model_dump() for ind in assessment.threat_indicators]
    result.supporting_evidence = list(assessment.supporting_evidence)
    result.attack_techniques = list(assessment.attack_techniques)
    result.recommended_actions = list(assessment.recommended_actions)
    result.model = "gemini-3.8-flash"
    result.provider = "gemini"
    result.prompt_version = PROMPT_VERSION
    result.created_at = datetime.now(timezone.utc)
    return result


# ---------------------------------------------------------------------------
# 1. Orchestrator: successful sync pipeline
# ---------------------------------------------------------------------------

def test_run_ai_analysis_success_sync():
    """Successful sync pipeline: build_context -> provider.analyze -> _persist_assessment."""
    case_id = uuid.uuid4()
    assessment = make_assessment()
    mock_provider = make_mock_provider(assessment)
    mock_context = MagicMock()

    with (
        patch("app.services.ai.orchestrator.build_ai_context", return_value=mock_context) as mock_build,
        patch("app.services.ai.orchestrator._persist_assessment") as mock_persist,
    ):
        mock_persist.return_value = make_mock_db_result(assessment, case_id)
        mock_db = MagicMock()

        result = run_ai_analysis(db=mock_db, case_id=case_id, provider=mock_provider)

        mock_build.assert_called_once_with(mock_db, case_id)
        mock_provider.analyze.assert_called_once_with(mock_context)
        mock_persist.assert_called_once()

        assert result.classification == "malicious"
        assert result.risk_score == 88


# ---------------------------------------------------------------------------
# 2. Orchestrator: successful async pipeline
# ---------------------------------------------------------------------------

def test_run_ai_analysis_success_async():
    """Successful async pipeline calls analyze_async and persists."""
    case_id = uuid.uuid4()
    assessment = make_assessment(classification="suspicious", risk_score=55)
    mock_provider = make_mock_provider(assessment)
    mock_context = MagicMock()

    with (
        patch("app.services.ai.orchestrator.build_ai_context", return_value=mock_context),
        patch("app.services.ai.orchestrator._persist_assessment") as mock_persist,
    ):
        mock_persist.return_value = make_mock_db_result(assessment, case_id)
        mock_db = MagicMock()

        result = asyncio.run(run_ai_analysis_async(db=mock_db, case_id=case_id, provider=mock_provider))

        mock_provider.analyze_async.assert_called_once_with(mock_context)
        mock_persist.assert_called_once()
        assert result.classification == "suspicious"
        assert result.risk_score == 55


# ---------------------------------------------------------------------------
# 3. CaseNotFoundError -> CaseNotFoundServiceError
# ---------------------------------------------------------------------------

def test_case_not_found_raises_service_error():
    """CaseNotFoundError from build_ai_context is mapped to CaseNotFoundServiceError."""
    case_id = uuid.uuid4()
    mock_provider = make_mock_provider()

    with patch(
        "app.services.ai.orchestrator.build_ai_context",
        side_effect=CaseNotFoundError(case_id),
    ):
        with pytest.raises(CaseNotFoundServiceError) as exc_info:
            run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)

        assert exc_info.value.http_status == 404
        assert str(case_id) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 4. Missing API key -> ProviderNotConfiguredError
# ---------------------------------------------------------------------------

def test_provider_not_configured_raises_error():
    """Provider with is_configured() == False raises ProviderNotConfiguredError immediately."""
    case_id = uuid.uuid4()
    mock_provider = MagicMock()
    mock_provider.is_configured.return_value = False

    with pytest.raises(ProviderNotConfiguredError) as exc_info:
        run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)

    assert exc_info.value.http_status == 503
    assert "not configured" in str(exc_info.value).lower()


def test_ai_configuration_error_from_provider():
    """AIConfigurationError raised during analyze() maps to ProviderNotConfiguredError."""
    from app.services.ai.exceptions import AIConfigurationError

    case_id = uuid.uuid4()
    mock_provider = make_mock_provider()
    mock_provider.analyze.side_effect = AIConfigurationError("API key missing")

    with patch("app.services.ai.orchestrator.build_ai_context", return_value=MagicMock()):
        with pytest.raises(ProviderNotConfiguredError):
            run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)


# ---------------------------------------------------------------------------
# 5. AIAuthenticationError -> ProviderAuthError
# ---------------------------------------------------------------------------

def test_authentication_error_maps_to_provider_auth_error():
    """AIAuthenticationError from provider maps to ProviderAuthError with http_status=503."""
    case_id = uuid.uuid4()
    mock_provider = make_mock_provider()
    mock_provider.analyze.side_effect = AIAuthenticationError("Gemini API authentication failed: API_KEY_INVALID")

    with patch("app.services.ai.orchestrator.build_ai_context", return_value=MagicMock()):
        with pytest.raises(ProviderAuthError) as exc_info:
            run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)

        assert exc_info.value.http_status == 503


# ---------------------------------------------------------------------------
# 6. AIRateLimitError -> ProviderUnavailableError
# ---------------------------------------------------------------------------

def test_rate_limit_maps_to_provider_unavailable():
    """AIRateLimitError from provider maps to ProviderUnavailableError."""
    case_id = uuid.uuid4()
    mock_provider = make_mock_provider()
    mock_provider.analyze.side_effect = AIRateLimitError("Gemini API rate limit exceeded")

    with patch("app.services.ai.orchestrator.build_ai_context", return_value=MagicMock()):
        with pytest.raises(ProviderUnavailableError) as exc_info:
            run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)

        assert exc_info.value.http_status == 503


# ---------------------------------------------------------------------------
# 7. AINetworkError -> ProviderUnavailableError
# ---------------------------------------------------------------------------

def test_network_error_maps_to_provider_unavailable():
    """AINetworkError from provider maps to ProviderUnavailableError."""
    case_id = uuid.uuid4()
    mock_provider = make_mock_provider()
    mock_provider.analyze.side_effect = AINetworkError("Gemini API request timed out")

    with patch("app.services.ai.orchestrator.build_ai_context", return_value=MagicMock()):
        with pytest.raises(ProviderUnavailableError) as exc_info:
            run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)

        assert exc_info.value.http_status == 503


# ---------------------------------------------------------------------------
# 8. AIResponseParsingError -> ProviderResponseError
# ---------------------------------------------------------------------------

def test_response_parsing_error_maps_to_provider_response_error():
    """AIResponseParsingError from provider maps to ProviderResponseError."""
    case_id = uuid.uuid4()
    mock_provider = make_mock_provider()
    mock_provider.analyze.side_effect = AIResponseParsingError("Gemini returned empty response")

    with patch("app.services.ai.orchestrator.build_ai_context", return_value=MagicMock()):
        with pytest.raises(ProviderResponseError) as exc_info:
            run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)

        assert exc_info.value.http_status == 502


# ---------------------------------------------------------------------------
# 9. AISchemaValidationError -> ProviderResponseError
# ---------------------------------------------------------------------------

def test_schema_validation_error_maps_to_provider_response_error():
    """AISchemaValidationError from provider maps to ProviderResponseError."""
    case_id = uuid.uuid4()
    mock_provider = make_mock_provider()
    mock_provider.analyze.side_effect = AISchemaValidationError("AIThreatAssessment validation failed")

    with patch("app.services.ai.orchestrator.build_ai_context", return_value=MagicMock()):
        with pytest.raises(ProviderResponseError) as exc_info:
            run_ai_analysis(db=MagicMock(), case_id=case_id, provider=mock_provider)

        assert exc_info.value.http_status == 502


# ---------------------------------------------------------------------------
# 10. Forensic/threat-intel records never modified
# ---------------------------------------------------------------------------

def test_forensic_records_not_modified():
    """Orchestrator must not call db.add/commit for forensic or threat-intel records."""
    case_id = uuid.uuid4()
    assessment = make_assessment()
    mock_provider = make_mock_provider(assessment)
    mock_db = MagicMock()

    with (
        patch("app.services.ai.orchestrator.build_ai_context", return_value=MagicMock()),
        patch("app.services.ai.orchestrator._persist_assessment") as mock_persist,
    ):
        mock_persist.return_value = make_mock_db_result(assessment, case_id)
        run_ai_analysis(db=mock_db, case_id=case_id, provider=mock_provider)

        # The only db.add() / db.commit() calls must come from _persist_assessment
        # build_ai_context is read-only; orchestrator itself does NOT call db.add/commit
        # _persist_assessment is mocked — so mock_db.add / mock_db.commit are NOT called
        mock_db.add.assert_not_called()
        mock_db.commit.assert_not_called()


# ---------------------------------------------------------------------------
# 11. Persistence: all fields mapped correctly
# ---------------------------------------------------------------------------

def test_persist_assessment_all_fields_mapped():
    """_persist_assessment maps all AIThreatAssessment fields to AIAnalysisResult."""
    case_id = uuid.uuid4()
    assessment = make_assessment()
    mock_provider = MagicMock()
    mock_provider.provider_name = "gemini"
    mock_provider.model_name = "gemini-3.8-flash"

    # Use a real SQLAlchemy session (with PostgreSQL)
    from app.db.session import SessionLocal
    from app.models.ai_analysis import AIAnalysisResult
    from app.models.case import Case

    with SessionLocal() as db:
        # Create a case to satisfy FK
        test_case = Case(
            id=case_id,
            case_number=f"CASE-4D-PERSIST-{uuid.uuid4().hex[:6].upper()}",
            title="Phase 4D Persistence Test",
            status="open",
            priority="high",
        )
        db.add(test_case)
        db.commit()

        try:
            result = _persist_assessment(db, case_id, assessment, mock_provider)

            # Verify all fields are correctly mapped
            assert result.case_id == case_id
            assert result.classification == "malicious"
            assert result.risk_score == 88
            assert abs(result.confidence - 0.95) < 0.01
            assert "Phishing" in result.reasoning
            assert isinstance(result.threat_indicators, list)
            assert len(result.threat_indicators) == 1
            assert result.threat_indicators[0]["indicator_type"] == "domain"
            assert result.threat_indicators[0]["indicator_value"] == "evil.example.com"
            assert result.threat_indicators[0]["severity"] == "high"
            assert isinstance(result.supporting_evidence, list)
            assert "Domain flagged" in result.supporting_evidence[0]
            assert isinstance(result.attack_techniques, list)
            assert "T1566.001" in result.attack_techniques[0]
            assert isinstance(result.recommended_actions, list)
            assert "Block domain" in result.recommended_actions[0]
            assert result.model == "gemini-3.8-flash"
            assert result.provider == "gemini"
            assert result.prompt_version == PROMPT_VERSION
            assert result.id is not None
            assert result.created_at is not None
        finally:
            # Cleanup: delete test case (cascades to AIAnalysisResult)
            db.delete(test_case)
            db.commit()


# ---------------------------------------------------------------------------
# 12. Persistence: provider provenance recorded
# ---------------------------------------------------------------------------

def test_persist_records_provider_provenance():
    """_persist_assessment records model, provider, and prompt_version correctly."""
    case_id = uuid.uuid4()
    assessment = make_assessment()
    mock_provider = MagicMock()
    mock_provider.provider_name = "test-provider"
    mock_provider.model_name = "test-model-v1"

    from app.db.session import SessionLocal
    from app.models.case import Case

    with SessionLocal() as db:
        test_case = Case(
            id=case_id,
            case_number=f"CASE-4D-PROV-{uuid.uuid4().hex[:6].upper()}",
            title="Phase 4D Provenance Test",
            status="open",
            priority="medium",
        )
        db.add(test_case)
        db.commit()

        try:
            result = _persist_assessment(db, case_id, assessment, mock_provider)

            assert result.provider == "test-provider"
            assert result.model == "test-model-v1"
            assert result.prompt_version == PROMPT_VERSION
        finally:
            db.delete(test_case)
            db.commit()


# ---------------------------------------------------------------------------
# API tests — use FastAPI TestClient with mocked orchestrator
# ---------------------------------------------------------------------------

client = TestClient(app)


def _mock_result(case_id: uuid.UUID, classification: str = "malicious") -> MagicMock:
    """Create a mock AIAnalysisResult for TestClient-based API tests."""
    result = MagicMock()
    result.id = uuid.uuid4()
    result.case_id = case_id
    result.classification = classification
    result.risk_score = 82
    result.confidence = 0.91
    result.reasoning = "Multiple phishing indicators."
    result.threat_indicators = [
        {
            "indicator_type": "domain",
            "indicator_value": "evil.example.com",
            "threat_type": "phishing",
            "severity": "high",
            "description": "High VT detection.",
        }
    ]
    result.supporting_evidence = ["Domain flagged by 15 VT vendors."]
    result.attack_techniques = ["T1566.001 - Spearphishing Attachment"]
    result.recommended_actions = ["Block domain."]
    result.model = "gemini-3.8-flash"
    result.provider = "gemini"
    result.prompt_version = PROMPT_VERSION
    result.created_at = datetime.now(timezone.utc)
    return result


# ---------------------------------------------------------------------------
# 13. API: POST /api/v1/cases/{case_id}/ai-analysis 201 success
# ---------------------------------------------------------------------------

def test_api_trigger_ai_analysis_success():
    """POST /api/v1/cases/{case_id}/ai-analysis returns 201 with AIAnalysisResultResponse."""
    case_id = uuid.uuid4()
    mock_result = _mock_result(case_id)

    with patch("app.api.v1.router.run_ai_analysis", return_value=mock_result):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    assert response.status_code == 201
    data = response.json()
    assert data["classification"] == "malicious"
    assert data["risk_score"] == 82
    assert abs(data["confidence"] - 0.91) < 0.01
    assert data["provider"] == "gemini"
    assert data["model"] == "gemini-3.8-flash"
    assert data["prompt_version"] == PROMPT_VERSION
    assert str(case_id) == data["case_id"]
    assert "id" in data
    assert "created_at" in data
    assert isinstance(data["threat_indicators"], list)
    assert isinstance(data["supporting_evidence"], list)
    assert isinstance(data["attack_techniques"], list)
    assert isinstance(data["recommended_actions"], list)


# ---------------------------------------------------------------------------
# 14. API: 404 when case does not exist
# ---------------------------------------------------------------------------

def test_api_returns_404_for_missing_case():
    """POST /api/v1/cases/{case_id}/ai-analysis returns 404 for non-existent case."""
    case_id = uuid.uuid4()

    with patch(
        "app.api.v1.router.run_ai_analysis",
        side_effect=CaseNotFoundServiceError(case_id),
    ):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    assert response.status_code == 404
    assert str(case_id) in response.json()["detail"]


# ---------------------------------------------------------------------------
# 15. API: 503 when provider not configured
# ---------------------------------------------------------------------------

def test_api_returns_503_for_provider_not_configured():
    """POST /api/v1/cases/{case_id}/ai-analysis returns 503 when provider not configured."""
    case_id = uuid.uuid4()

    with patch(
        "app.api.v1.router.run_ai_analysis",
        side_effect=ProviderNotConfiguredError(),
    ):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 16. API: 503 when provider authentication fails
# ---------------------------------------------------------------------------

def test_api_returns_503_for_auth_failure():
    """POST /api/v1/cases/{case_id}/ai-analysis returns 503 on provider auth failure."""
    case_id = uuid.uuid4()

    with patch(
        "app.api.v1.router.run_ai_analysis",
        side_effect=ProviderAuthError("API_KEY_INVALID"),
    ):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    assert response.status_code == 503
    assert "authentication failed" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 17. API: 503 on network / rate-limit errors
# ---------------------------------------------------------------------------

def test_api_returns_503_for_rate_limit():
    """POST /api/v1/cases/{case_id}/ai-analysis returns 503 on rate limit."""
    case_id = uuid.uuid4()

    with patch(
        "app.api.v1.router.run_ai_analysis",
        side_effect=ProviderUnavailableError("RESOURCE_EXHAUSTED"),
    ):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    assert response.status_code == 503


def test_api_returns_503_for_network_error():
    """POST /api/v1/cases/{case_id}/ai-analysis returns 503 on network failure."""
    case_id = uuid.uuid4()

    with patch(
        "app.api.v1.router.run_ai_analysis",
        side_effect=ProviderUnavailableError("Request timed out"),
    ):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    assert response.status_code == 503


# ---------------------------------------------------------------------------
# 18. API: 502 when provider returns invalid response
# ---------------------------------------------------------------------------

def test_api_returns_502_for_invalid_provider_response():
    """POST /api/v1/cases/{case_id}/ai-analysis returns 502 on invalid provider response."""
    case_id = uuid.uuid4()

    with patch(
        "app.api.v1.router.run_ai_analysis",
        side_effect=ProviderResponseError("Response is not valid JSON"),
    ):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    assert response.status_code == 502
    assert "invalid response" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 19. API response: no API keys or raw email bodies
# ---------------------------------------------------------------------------

def test_api_response_no_api_key_leakage():
    """API response must never include GEMINI_API_KEY or raw email body fields."""
    from app.core.config import settings

    case_id = uuid.uuid4()
    mock_result = _mock_result(case_id)

    with patch("app.api.v1.router.run_ai_analysis", return_value=mock_result):
        response = client.post(f"/api/v1/cases/{case_id}/ai-analysis")

    data = response.json()
    response_text = response.text

    # Must not include API key fields in response
    assert "api_key" not in response_text.lower()
    assert "gemini_api_key" not in response_text.lower()

    # Must not include raw email body content
    assert "body_plain" not in response_text.lower()
    assert "body_html" not in response_text.lower()
    assert "raw_response" not in response_text.lower()

    # Actual key value (if set) must not appear in response
    if settings.GEMINI_API_KEY:
        assert settings.GEMINI_API_KEY not in response_text


# ---------------------------------------------------------------------------
# 20. Schema: AIAnalysisResultResponse Pydantic validation
# ---------------------------------------------------------------------------

def test_ai_analysis_result_response_schema():
    """AIAnalysisResultResponse validates valid data and rejects invalid classification."""
    from pydantic import ValidationError

    valid_data = {
        "id": uuid.uuid4(),
        "case_id": uuid.uuid4(),
        "classification": "malicious",
        "risk_score": 88,
        "confidence": 0.95,
        "reasoning": "Evidence of phishing.",
        "threat_indicators": [
            {
                "indicator_type": "domain",
                "indicator_value": "evil.example.com",
                "threat_type": "phishing",
                "severity": "high",
                "description": "VirusTotal flagged.",
            }
        ],
        "supporting_evidence": ["Domain flagged by 15 VT vendors."],
        "attack_techniques": ["T1566.001 - Spearphishing Attachment"],
        "recommended_actions": ["Block domain."],
        "model": "gemini-3.8-flash",
        "provider": "gemini",
        "prompt_version": PROMPT_VERSION,
        "created_at": datetime.now(timezone.utc),
    }

    resp = AIAnalysisResultResponse.model_validate(valid_data)
    assert resp.classification == "malicious"
    assert resp.risk_score == 88
    assert resp.provider == "gemini"

    # Invalid classification
    invalid_data = dict(valid_data, classification="ultra_dangerous")
    with pytest.raises(ValidationError):
        AIAnalysisResultResponse.model_validate(invalid_data)
