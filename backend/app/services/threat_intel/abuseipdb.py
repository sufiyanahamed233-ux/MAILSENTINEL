from datetime import datetime, timezone
import httpx

from app.core.config import settings
from app.services.threat_intel.models import (
    EnrichmentStatus,
    IndicatorType,
    NormalizedThreatResult,
)
from app.services.threat_intel.normalizer import normalize_abuseipdb_response


class AbuseIPDBProvider:
    """AbuseIPDB API v2 provider adapter.

    Performs read-only IP reputation lookups using the CHECK endpoint.
    Never reports or submits data.
    """

    CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str | None = None, timeout: int | None = None):
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.timeout = timeout or settings.THREAT_INTEL_TIMEOUT_SECONDS

    def is_configured(self) -> bool:
        """Check if provider has a valid API key configured."""
        return bool(self.api_key and self.api_key.strip())

    async def lookup_ip(self, ip_address: str) -> NormalizedThreatResult:
        """Query AbuseIPDB API v2 CHECK endpoint for an IP address."""
        if not self.is_configured():
            return NormalizedThreatResult(
                provider="abuseipdb",
                indicator_type=IndicatorType.IP.value,
                indicator_value=ip_address,
                status=EnrichmentStatus.NOT_CONFIGURED.value,
                reputation=None,
                queried_at=datetime.now(timezone.utc),
                error_message="AbuseIPDB API key is not configured.",
            )

        headers = {
            "Key": self.api_key.strip(),  # type: ignore[union-attr]
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip_address.strip(),
            "maxAgeInDays": "90",
            "verbose": "",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.CHECK_URL, headers=headers, params=params)

                if response.status_code == 200:
                    raw_json = response.json()
                    return normalize_abuseipdb_response(ip_address, raw_json)

                if response.status_code == 404:
                    return NormalizedThreatResult(
                        provider="abuseipdb",
                        indicator_type=IndicatorType.IP.value,
                        indicator_value=ip_address,
                        status=EnrichmentStatus.NOT_FOUND.value,
                        reputation=None,
                        queried_at=datetime.now(timezone.utc),
                        raw_response=response.json() if response.content else None,
                        error_message="IP address not found in AbuseIPDB database.",
                    )

                if response.status_code in (401, 403):
                    return NormalizedThreatResult(
                        provider="abuseipdb",
                        indicator_type=IndicatorType.IP.value,
                        indicator_value=ip_address,
                        status=EnrichmentStatus.ERROR.value,
                        queried_at=datetime.now(timezone.utc),
                        error_message=f"AbuseIPDB authentication failed (HTTP {response.status_code}).",
                    )

                if response.status_code == 429:
                    return NormalizedThreatResult(
                        provider="abuseipdb",
                        indicator_type=IndicatorType.IP.value,
                        indicator_value=ip_address,
                        status=EnrichmentStatus.RATE_LIMITED.value,
                        queried_at=datetime.now(timezone.utc),
                        error_message="AbuseIPDB API rate limit exceeded (HTTP 429).",
                    )

                return NormalizedThreatResult(
                    provider="abuseipdb",
                    indicator_type=IndicatorType.IP.value,
                    indicator_value=ip_address,
                    status=EnrichmentStatus.ERROR.value,
                    queried_at=datetime.now(timezone.utc),
                    error_message=f"AbuseIPDB server responded with HTTP {response.status_code}.",
                )

        except httpx.TimeoutException:
            return NormalizedThreatResult(
                provider="abuseipdb",
                indicator_type=IndicatorType.IP.value,
                indicator_value=ip_address,
                status=EnrichmentStatus.ERROR.value,
                queried_at=datetime.now(timezone.utc),
                error_message=f"AbuseIPDB request timed out after {self.timeout} seconds.",
            )
        except httpx.RequestError as exc:
            return NormalizedThreatResult(
                provider="abuseipdb",
                indicator_type=IndicatorType.IP.value,
                indicator_value=ip_address,
                status=EnrichmentStatus.ERROR.value,
                queried_at=datetime.now(timezone.utc),
                error_message=f"Network error querying AbuseIPDB: {str(exc)}",
            )
        except Exception as exc:
            return NormalizedThreatResult(
                provider="abuseipdb",
                indicator_type=IndicatorType.IP.value,
                indicator_value=ip_address,
                status=EnrichmentStatus.ERROR.value,
                queried_at=datetime.now(timezone.utc),
                error_message=f"Unexpected error processing AbuseIPDB response: {str(exc)}",
            )
