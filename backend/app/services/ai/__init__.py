"""AI threat-analysis service package for MAILSENTINEL."""

from app.services.ai.context_builder import build_ai_context
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
from app.services.ai.orchestrator import (
    AIAnalysisServiceError,
    CaseNotFoundServiceError,
    ProviderAuthError,
    ProviderNotConfiguredError,
    ProviderResponseError,
    ProviderUnavailableError,
    run_ai_analysis,
    run_ai_analysis_async,
)
from app.services.ai.provider import AIProvider

__all__ = [
    "AIAnalysisServiceError",
    "AIAuthenticationError",
    "AIConfigurationError",
    "AINetworkError",
    "AIProvider",
    "AIProviderError",
    "AIRateLimitError",
    "AIResponseParsingError",
    "AISchemaValidationError",
    "CaseNotFoundServiceError",
    "GeminiProvider",
    "ProviderAuthError",
    "ProviderNotConfiguredError",
    "ProviderResponseError",
    "ProviderUnavailableError",
    "build_ai_context",
    "run_ai_analysis",
    "run_ai_analysis_async",
]
