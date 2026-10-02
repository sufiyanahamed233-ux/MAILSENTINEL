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
from app.services.ai.provider import AIProvider

__all__ = [
    "AIAuthenticationError",
    "AIConfigurationError",
    "AINetworkError",
    "AIProvider",
    "AIProviderError",
    "AIRateLimitError",
    "AIResponseParsingError",
    "AISchemaValidationError",
    "GeminiProvider",
    "build_ai_context",
]
