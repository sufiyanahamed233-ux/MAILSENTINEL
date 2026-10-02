from datetime import datetime, timedelta, timezone
from typing import Any
import uuid
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.case import Case
from app.models.threat_intel import ThreatIntelligenceResult
from app.services.threat_intel.abuseipdb import AbuseIPDBProvider
from app.services.threat_intel.models import (
    CaseEnrichmentSummary,
    EnrichmentStatus,
    IndicatorType,
    NormalizedThreatResult,
)
from app.services.threat_intel.virustotal import VirusTotalProvider


class ThreatIntelService:
    """Orchestrates threat intelligence enrichment for forensic investigation cases."""

    def __init__(
        self,
        vt_provider: VirusTotalProvider | None = None,
        abuse_provider: AbuseIPDBProvider | None = None,
        cache_hours: int | None = None,
    ):
        self.vt = vt_provider or VirusTotalProvider()
        self.abuse = abuse_provider or AbuseIPDBProvider()
        self.cache_hours = cache_hours or settings.THREAT_INTEL_CACHE_HOURS

    async def enrich_indicator(
        self,
        db: Session,
        indicator_type: IndicatorType,
        indicator_value: str,
        case_id: uuid.UUID,
    ) -> list[NormalizedThreatResult]:
        """Enrich a single indicator against all applicable providers using DB cache when fresh."""
        applicable_providers: list[tuple[str, Any]] = []

        if indicator_type == IndicatorType.IP:
            applicable_providers.append(("virustotal", lambda: self.vt.lookup(IndicatorType.IP, indicator_value)))
            applicable_providers.append(("abuseipdb", lambda: self.abuse.lookup_ip(indicator_value)))
        elif indicator_type in (IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.FILE_HASH):
            applicable_providers.append(("virustotal", lambda: self.vt.lookup(indicator_type, indicator_value)))

        results: list[NormalizedThreatResult] = []

        for provider_name, lookup_callable in applicable_providers:
            # 1. Check PostgreSQL for fresh cached result
            cached_record = self._find_cached_result(
                db,
                provider=provider_name,
                indicator_type=indicator_type.value,
                indicator_value=indicator_value,
            )

            if cached_record:
                # Reuse cached record
                res = NormalizedThreatResult(
                    provider=cached_record.provider,
                    indicator_type=cached_record.indicator_type,
                    indicator_value=cached_record.indicator_value,
                    status=cached_record.status,
                    reputation=cached_record.reputation,
                    confidence=cached_record.confidence,
                    malicious_count=cached_record.malicious_count,
                    suspicious_count=cached_record.suspicious_count,
                    harmless_count=cached_record.harmless_count,
                    country=cached_record.country,
                    asn=cached_record.asn,
                    organization=cached_record.organization,
                    queried_at=cached_record.queried_at,
                    raw_response=cached_record.raw_response,
                    error_message=cached_record.error_message,
                )
                results.append(res)
                # If cached record is from another case, persist reference for this case too
                if cached_record.case_id != case_id:
                    self._persist_result(db, case_id, res)
            else:
                # 2. Query external provider
                fresh_res = await lookup_callable()
                results.append(fresh_res)
                # Persist to PostgreSQL if status is success or definitive not_found
                self._persist_result(db, case_id, fresh_res)

        return results

    async def enrich_case(self, db: Session, case_id: uuid.UUID) -> CaseEnrichmentSummary:
        """Enrich all observed indicators associated with a forensic investigation case."""
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case with ID '{case_id}' not found.")

        # Collect unique observed IoCs from all emails in this case
        unique_ips: set[str] = set()
        unique_domains: set[str] = set()
        unique_urls: set[str] = set()
        unique_hashes: set[str] = set()

        for email_item in case.emails:
            for ip_rec in email_item.ip_addresses:
                if ip_rec.ip_address:
                    unique_ips.add(ip_rec.ip_address.strip())
            for dom_rec in email_item.domains:
                if dom_rec.domain:
                    unique_domains.add(dom_rec.domain.strip())
            for url_rec in email_item.urls:
                if url_rec.url:
                    unique_urls.add(url_rec.url.strip())
            for att_rec in email_item.attachments:
                if att_rec.sha256:
                    unique_hashes.add(att_rec.sha256.strip().lower())

        total_indicators = len(unique_ips) + len(unique_domains) + len(unique_urls) + len(unique_hashes)

        all_results: list[NormalizedThreatResult] = []
        cached_count = 0
        fresh_count = 0
        providers_used: set[str] = set()

        # Enrich IPs
        for ip in unique_ips:
            res_list = await self.enrich_indicator(db, IndicatorType.IP, ip, case_id)
            for r in res_list:
                providers_used.add(r.provider)
                if self._is_cached_item(db, r):
                    cached_count += 1
                else:
                    fresh_count += 1
            all_results.extend(res_list)

        # Enrich Domains
        for domain in unique_domains:
            res_list = await self.enrich_indicator(db, IndicatorType.DOMAIN, domain, case_id)
            for r in res_list:
                providers_used.add(r.provider)
                if self._is_cached_item(db, r):
                    cached_count += 1
                else:
                    fresh_count += 1
            all_results.extend(res_list)

        # Enrich URLs
        for url in unique_urls:
            res_list = await self.enrich_indicator(db, IndicatorType.URL, url, case_id)
            for r in res_list:
                providers_used.add(r.provider)
                if self._is_cached_item(db, r):
                    cached_count += 1
                else:
                    fresh_count += 1
            all_results.extend(res_list)

        # Enrich Hashes
        for file_hash in unique_hashes:
            res_list = await self.enrich_indicator(db, IndicatorType.FILE_HASH, file_hash, case_id)
            for r in res_list:
                providers_used.add(r.provider)
                if self._is_cached_item(db, r):
                    cached_count += 1
                else:
                    fresh_count += 1
            all_results.extend(res_list)

        return CaseEnrichmentSummary(
            case_id=case_id,
            total_indicators=total_indicators,
            total_queries=len(all_results),
            cached_results=cached_count,
            fresh_results=fresh_count,
            providers_used=sorted(providers_used),
            results=all_results,
        )

    def _find_cached_result(
        self,
        db: Session,
        provider: str,
        indicator_type: str,
        indicator_value: str,
    ) -> ThreatIntelligenceResult | None:
        """Find recent successful enrichment result within cache freshness window."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.cache_hours)
        return (
            db.query(ThreatIntelligenceResult)
            .filter(
                ThreatIntelligenceResult.provider == provider,
                ThreatIntelligenceResult.indicator_type == indicator_type,
                ThreatIntelligenceResult.indicator_value == indicator_value,
                ThreatIntelligenceResult.status.in_([EnrichmentStatus.SUCCESS.value, EnrichmentStatus.NOT_FOUND.value]),
                ThreatIntelligenceResult.queried_at >= cutoff,
            )
            .order_by(ThreatIntelligenceResult.queried_at.desc())
            .first()
        )

    def _is_cached_item(self, db: Session, res: NormalizedThreatResult) -> bool:
        """Check if result was served from cache."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.cache_hours)
        return res.queried_at < cutoff or (
            datetime.now(timezone.utc) - res.queried_at
        ).total_seconds() > 5.0

    def _persist_result(
        self,
        db: Session,
        case_id: uuid.UUID,
        res: NormalizedThreatResult,
    ) -> ThreatIntelligenceResult:
        """Persist a normalized threat intelligence result to PostgreSQL."""
        record = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case_id,
            indicator_type=res.indicator_type,
            indicator_value=res.indicator_value,
            provider=res.provider,
            queried_at=res.queried_at,
            status=res.status,
            reputation=res.reputation,
            confidence=res.confidence,
            malicious_count=res.malicious_count,
            suspicious_count=res.suspicious_count,
            harmless_count=res.harmless_count,
            country=res.country,
            asn=res.asn,
            organization=res.organization,
            raw_response=res.raw_response,
            error_message=res.error_message,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
