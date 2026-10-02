"""Pydantic schemas package."""

from app.schemas.email_analysis import (
    EmailAnalysisResponse,
    ParsedAttachment,
    ParsedDomain,
    ParsedEmailData,
    ParsedHeader,
    ParsedIP,
    ParsedURL,
)

__all__ = [
    "EmailAnalysisResponse",
    "ParsedAttachment",
    "ParsedDomain",
    "ParsedEmailData",
    "ParsedHeader",
    "ParsedIP",
    "ParsedURL",
]
