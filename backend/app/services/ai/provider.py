"""Minimal provider abstraction for AI threat analysis.

Defines the core interface contract transforming structured forensic context
into validated threat assessments.
"""

from abc import ABC, abstractmethod

from app.schemas.ai_analysis import AIAnalysisContext, AIThreatAssessment


class AIProvider(ABC):
    """Abstract base class defining the AI threat-analysis provider interface.

    Implementations (such as GeminiProvider) encapsulate model-specific
    invocation logic, structured output parsing, error mapping, and guardrails
    without accessing databases or persisting results.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifying name of the AI provider (e.g. 'gemini')."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the underlying AI model (e.g. 'gemini-3.8-flash')."""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if the provider has all required credentials and configuration."""
        ...

    @abstractmethod
    def analyze(self, context: AIAnalysisContext) -> AIThreatAssessment:
        """Perform threat analysis on a structured forensic context.

        Args:
            context: Sanitized forensic context assembled from observed evidence
                     and external threat intelligence.

        Returns:
            AIThreatAssessment: Validated threat assessment adhering to the schema.

        Raises:
            AIConfigurationError: If the provider is not properly configured.
            AIAuthenticationError: If authentication with the provider fails.
            AIRateLimitError: If provider rate limits are exceeded.
            AINetworkError: If network connectivity or timeout occurs.
            AIResponseParsingError: If provider returns empty or invalid JSON.
            AISchemaValidationError: If output violates AIThreatAssessment schema.
            AIProviderError: On unexpected provider errors.
        """
        ...

    @abstractmethod
    async def analyze_async(self, context: AIAnalysisContext) -> AIThreatAssessment:
        """Asynchronously perform threat analysis on a structured forensic context.

        Args:
            context: Sanitized forensic context assembled from observed evidence
                     and external threat intelligence.

        Returns:
            AIThreatAssessment: Validated threat assessment adhering to the schema.

        Raises:
            AIProviderError: On any failure during analysis.
        """
        ...
