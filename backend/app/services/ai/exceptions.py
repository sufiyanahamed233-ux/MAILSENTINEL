"""Exceptions for AI threat-analysis provider services.

All exceptions inherit from ``AIProviderError`` to provide a unified
error hierarchy for callers.
"""


class AIProviderError(Exception):
    """Base exception for all AI threat-analysis errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class AIConfigurationError(AIProviderError):
    """Raised when provider configuration (e.g. API key, model) is missing or invalid."""

    pass


class AIAuthenticationError(AIProviderError):
    """Raised when authentication with the AI provider fails (e.g. 401/403)."""

    pass


class AIRateLimitError(AIProviderError):
    """Raised when provider rate limits are exceeded (e.g. 429 / resource exhausted)."""

    pass


class AINetworkError(AIProviderError):
    """Raised on network failures, timeouts, connection drops, or DNS errors."""

    pass


class AIResponseParsingError(AIProviderError):
    """Raised when the AI provider returns an empty, corrupted, or invalid JSON response."""

    pass


class AISchemaValidationError(AIProviderError):
    """Raised when the AI provider's response fails Pydantic schema validation."""

    pass
