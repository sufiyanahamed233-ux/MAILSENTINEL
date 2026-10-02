from datetime import datetime, timezone
from typing import Any

from app.services.threat_intel.models import (
    EnrichmentStatus,
    IndicatorType,
    NormalizedThreatResult,
    ReputationLevel,
)


def normalize_virustotal_response(
    indicator_type: IndicatorType,
    indicator_value: str,
    raw_json: dict[str, Any],
) -> NormalizedThreatResult:
    """Normalize a VirusTotal API v3 response into NormalizedThreatResult."""
    data = raw_json.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected

    # Determine reputation level
    if malicious > 0:
        reputation = ReputationLevel.MALICIOUS.value
    elif suspicious > 0:
        reputation = ReputationLevel.SUSPICIOUS.value
    elif total_engines > 0 and (harmless > 0 or undetected > 0):
        reputation = ReputationLevel.CLEAN.value
    else:
        reputation = ReputationLevel.UNKNOWN.value

    # Compute confidence as proportion of detection engines or percentage
    confidence = None
    if total_engines > 0:
        confidence = round((malicious / total_engines) * 100.0, 2)

    country = attributes.get("country")
    asn = attributes.get("asn")
    org = attributes.get("as_owner") or attributes.get("network")

    return NormalizedThreatResult(
        provider="virustotal",
        indicator_type=indicator_type.value,
        indicator_value=indicator_value,
        status=EnrichmentStatus.SUCCESS.value,
        reputation=reputation,
        confidence=confidence,
        malicious_count=malicious,
        suspicious_count=suspicious,
        harmless_count=harmless,
        country=country,
        asn=asn if isinstance(asn, int) else None,
        organization=str(org) if org else None,
        queried_at=datetime.now(timezone.utc),
        raw_response=raw_json,
        error_message=None,
    )


def normalize_abuseipdb_response(
    indicator_value: str,
    raw_json: dict[str, Any],
) -> NormalizedThreatResult:
    """Normalize an AbuseIPDB API v2 response into NormalizedThreatResult."""
    data = raw_json.get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    total_reports = data.get("totalReports", 0)

    # Determine reputation level based on confidence score
    if score >= 50:
        reputation = ReputationLevel.MALICIOUS.value
    elif score > 0:
        reputation = ReputationLevel.SUSPICIOUS.value
    else:
        reputation = ReputationLevel.CLEAN.value

    country = data.get("countryCode")
    isp = data.get("isp")

    return NormalizedThreatResult(
        provider="abuseipdb",
        indicator_type=IndicatorType.IP.value,
        indicator_value=indicator_value,
        status=EnrichmentStatus.SUCCESS.value,
        reputation=reputation,
        confidence=float(score),
        malicious_count=total_reports,
        suspicious_count=None,
        harmless_count=None,
        country=country,
        asn=None,
        organization=isp,
        queried_at=datetime.now(timezone.utc),
        raw_response=raw_json,
        error_message=None,
    )
