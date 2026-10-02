import base64
from datetime import datetime, timezone
import httpx

from app.core.config import settings
from app.services.threat_intel.models import (
    EnrichmentStatus,
    IndicatorType,
    NormalizedThreatResult,
    ReputationLevel,
)
from app.services.threat_intel.normalizer import normalize_virustotal_response


class VirusTotalProvider:
    """VirusTotal API v3 provider adapter.

    Performs read-only lookups for IPs, domains, URLs, and file hashes.
    Never submits URLs or uploads files.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None, timeout: int | None = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.timeout = timeout or settings.THREAT_INTEL_TIMEOUT_SECONDS

    def is_configured(self) -> bool:
        """Check if provider has a valid API key configured."""
        return bool(self.api_key and self.api_key.strip())

    async def lookup(self, indicator_type: IndicatorType, indicator_value: str) -> NormalizedThreatResult:
        """Query VirusTotal API v3 for an indicator."""
        if not self.is_configured():
            return NormalizedThreatResult(
                provider="virustotal",
                indicator_type=indicator_type.value,
                indicator_value=indicator_value,
                status=EnrichmentStatus.NOT_CONFIGURED.value,
                reputation=None,
                queried_at=datetime.now(timezone.utc),
                error_message="VirusTotal API key is not configured.",
            )

        endpoint = self._build_endpoint(indicator_type, indicator_value)
        headers = {
            "x-apikey": self.api_key.strip(),  # type: ignore[union-attr]
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(endpoint, headers=headers)

                if response.status_code == 200:
                    raw_json = response.json()
                    return normalize_virustotal_response(indicator_type, indicator_value, raw_json)

                if response.status_code == 404:
                    return NormalizedThreatResult(
                        provider="virustotal",
                        indicator_type=indicator_type.value,
                        indicator_value=indicator_value,
                        status=EnrichmentStatus.NOT_FOUND.value,
                        reputation=ReputationLevel.UNKNOWN.value,
                        queried_at=datetime.now(timezone.utc),
                        raw_response=response.json() if response.content else None,
                        error_message="Indicator not found in VirusTotal database.",
                    )

                if response.status_code in (401, 403):
                    return NormalizedThreatResult(
                        provider="virustotal",
                        indicator_type=indicator_type.value,
                        indicator_value=indicator_value,
                        status=EnrichmentStatus.ERROR.value,
                        queried_at=datetime.now(timezone.utc),
                        error_message=f"VirusTotal authentication failed (HTTP {response.status_code}).",
                    )

                if response.status_code == 429:
                    return NormalizedThreatResult(
                        provider="virustotal",
                        indicator_type=indicator_type.value,
                        indicator_value=indicator_value,
                        status=EnrichmentStatus.RATE_LIMITED.value,
                        queried_at=datetime.now(timezone.utc),
                        error_message="VirusTotal API rate limit exceeded (HTTP 429).",
                    )

                return NormalizedThreatResult(
                    provider="virustotal",
                    indicator_type=indicator_type.value,
                    indicator_value=indicator_value,
                    status=EnrichmentStatus.ERROR.value,
                    queried_at=datetime.now(timezone.utc),
                    error_message=f"VirusTotal server responded with HTTP {response.status_code}.",
                )

        except httpx.TimeoutException:
            return NormalizedThreatResult(
                provider="virustotal",
                indicator_type=indicator_type.value,
                indicator_value=indicator_value,
                status=EnrichmentStatus.ERROR.value,
                queried_at=datetime.now(timezone.utc),
                error_message=f"VirusTotal request timed out after {self.timeout} seconds.",
            )
        except httpx.RequestError as exc:
            return NormalizedThreatResult(
                provider="virustotal",
                indicator_type=indicator_type.value,
                indicator_value=indicator_value,
                status=EnrichmentStatus.ERROR.value,
                queried_at=datetime.now(timezone.utc),
                error_message=f"Network error querying VirusTotal: {str(exc)}",
            )
        except Exception as exc:
            return NormalizedThreatResult(
                provider="virustotal",
                indicator_type=indicator_type.value,
                indicator_value=indicator_value,
                status=EnrichmentStatus.ERROR.value,
                queried_at=datetime.now(timezone.utc),
                error_message=f"Unexpected error processing VirusTotal response: {str(exc)}",
            )

    def _build_endpoint(self, indicator_type: IndicatorType, indicator_value: str) -> str:
        if indicator_type == IndicatorType.IP:
            return f"{self.BASE_URL}/ip_addresses/{indicator_value.strip()}"
        if indicator_type == IndicatorType.DOMAIN:
            return f"{self.BASE_URL}/domains/{indicator_value.strip().lower()}"
        if indicator_type == IndicatorType.URL:
            # URL identifier is base64url encoded without padding
            url_id = base64.urlsafe_b64encode(indicator_value.strip().encode("utf-8")).decode("utf-8").strip("=")
            return f"{self.BASE_URL}/urls/{url_id}"
        if indicator_type == IndicatorType.FILE_HASH:
            return f"{self.BASE_URL}/files/{indicator_value.strip().lower()}"
        raise ValueError(f"Unsupported indicator type for VirusTotal: {indicator_type}")
