import asyncio
import uuid
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import httpx

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.email import Attachment, Email
from app.models.network import Domain, IPAddress, URL
from app.models.threat_intel import ThreatIntelligenceResult
from app.services.threat_intel.abuseipdb import AbuseIPDBProvider
from app.services.threat_intel.models import (
    EnrichmentStatus,
    IndicatorType,
    ReputationLevel,
)
from app.services.threat_intel.normalizer import (
    normalize_abuseipdb_response,
    normalize_virustotal_response,
)
from app.services.threat_intel.service import ThreatIntelService
from app.services.threat_intel.virustotal import VirusTotalProvider


class TestThreatIntelligence(unittest.TestCase):
    """Test suite for external threat intelligence providers and service orchestration."""

    def setUp(self):
        self.vt = VirusTotalProvider(api_key="mock_vt_key", timeout=5)
        self.abuse = AbuseIPDBProvider(api_key="mock_abuse_key", timeout=5)

    def test_1_virustotal_ip_lookup_success(self):
        """1. VirusTotal IP lookup success."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 12,
                        "suspicious": 3,
                        "harmless": 45,
                        "undetected": 10,
                    },
                    "country": "US",
                    "asn": 15169,
                    "as_owner": "Google LLC",
                }
            }
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.vt.lookup(IndicatorType.IP, "8.8.8.8"))
            self.assertEqual(res.status, EnrichmentStatus.SUCCESS.value)
            self.assertEqual(res.reputation, ReputationLevel.MALICIOUS.value)
            self.assertEqual(res.malicious_count, 12)
            self.assertEqual(res.country, "US")
            self.assertEqual(res.asn, 15169)
            self.assertEqual(res.organization, "Google LLC")

    def test_2_virustotal_domain_lookup_success(self):
        """2. VirusTotal domain lookup success."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 65,
                        "undetected": 5,
                    }
                }
            }
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.vt.lookup(IndicatorType.DOMAIN, "example.com"))
            self.assertEqual(res.status, EnrichmentStatus.SUCCESS.value)
            self.assertEqual(res.reputation, ReputationLevel.CLEAN.value)
            self.assertEqual(res.malicious_count, 0)

    def test_3_virustotal_url_report_lookup_success(self):
        """3. VirusTotal URL report lookup success."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 1,
                        "harmless": 10,
                        "undetected": 2,
                    }
                }
            }
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.vt.lookup(IndicatorType.URL, "https://phish.net/login"))
            self.assertEqual(res.status, EnrichmentStatus.SUCCESS.value)
            self.assertEqual(res.reputation, ReputationLevel.MALICIOUS.value)
            self.assertEqual(res.malicious_count, 8)

    def test_4_virustotal_file_hash_lookup_success(self):
        """4. VirusTotal file-hash lookup success."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 2,
                        "harmless": 0,
                        "undetected": 15,
                    }
                }
            }
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            dummy_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            res = asyncio.run(self.vt.lookup(IndicatorType.FILE_HASH, dummy_hash))
            self.assertEqual(res.status, EnrichmentStatus.SUCCESS.value)
            self.assertEqual(res.reputation, ReputationLevel.MALICIOUS.value)
            self.assertEqual(res.malicious_count, 45)

    def test_5_abuseipdb_ip_lookup_success(self):
        """5. AbuseIPDB IP lookup success."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "198.51.100.12",
                "abuseConfidenceScore": 88,
                "totalReports": 34,
                "countryCode": "RU",
                "isp": "Bad Hosting Network",
            }
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.abuse.lookup_ip("198.51.100.12"))
            self.assertEqual(res.status, EnrichmentStatus.SUCCESS.value)
            self.assertEqual(res.reputation, ReputationLevel.MALICIOUS.value)
            self.assertEqual(res.confidence, 88.0)
            self.assertEqual(res.country, "RU")
            self.assertEqual(res.organization, "Bad Hosting Network")

    def test_6_provider_not_configured(self):
        """6. Provider not configured returns clear status without crashing."""
        unconfigured_vt = VirusTotalProvider(api_key="")
        unconfigured_abuse = AbuseIPDBProvider(api_key="")

        res_vt = asyncio.run(unconfigured_vt.lookup(IndicatorType.IP, "1.1.1.1"))
        self.assertEqual(res_vt.status, EnrichmentStatus.NOT_CONFIGURED.value)
        self.assertIn("not configured", res_vt.error_message or "")

        res_abuse = asyncio.run(unconfigured_abuse.lookup_ip("1.1.1.1"))
        self.assertEqual(res_abuse.status, EnrichmentStatus.NOT_CONFIGURED.value)
        self.assertIn("not configured", res_abuse.error_message or "")

    def test_7_http_404_not_found(self):
        """7. HTTP 404 indicates indicator not found in provider database."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b'{"error": "not found"}'
        mock_resp.json.return_value = {"error": "not found"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.vt.lookup(IndicatorType.DOMAIN, "unknown-new-site.xyz"))
            self.assertEqual(res.status, EnrichmentStatus.NOT_FOUND.value)
            self.assertEqual(res.reputation, ReputationLevel.UNKNOWN.value)

    def test_8_http_401_403_auth_failure(self):
        """8. HTTP 401/403 produces structured authentication error."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.vt.lookup(IndicatorType.IP, "8.8.8.8"))
            self.assertEqual(res.status, EnrichmentStatus.ERROR.value)
            self.assertIn("authentication failed", (res.error_message or "").lower())

    def test_9_http_429_rate_limited(self):
        """9. HTTP 429 produces structured rate_limited status."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.abuse.lookup_ip("198.51.100.1"))
            self.assertEqual(res.status, EnrichmentStatus.RATE_LIMITED.value)
            self.assertIn("rate limit exceeded", (res.error_message or "").lower())

    def test_10_http_5xx_server_error(self):
        """10. HTTP 5xx returns error status without crashing."""
        mock_resp = MagicMock()
        mock_resp.status_code = 502

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(self.vt.lookup(IndicatorType.IP, "8.8.8.8"))
            self.assertEqual(res.status, EnrichmentStatus.ERROR.value)
            self.assertIn("502", res.error_message or "")

    def test_11_network_timeout(self):
        """11. Network timeout produces structured error result."""
        with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timeout")):
            res = asyncio.run(self.vt.lookup(IndicatorType.IP, "8.8.8.8"))
            self.assertEqual(res.status, EnrichmentStatus.ERROR.value)
            self.assertIn("timed out", (res.error_message or "").lower())

    def test_12_normalization(self):
        """12. Normalization logic maps provider responses properly."""
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 1, "harmless": 20},
                    "country": "FR",
                    "asn": 1234,
                }
            }
        }
        res_vt = normalize_virustotal_response(IndicatorType.DOMAIN, "suspicious.fr", vt_data)
        self.assertEqual(res_vt.reputation, ReputationLevel.SUSPICIOUS.value)
        self.assertEqual(res_vt.country, "FR")
        self.assertEqual(res_vt.asn, 1234)

        abuse_data = {
            "data": {
                "abuseConfidenceScore": 0,
                "countryCode": "DE",
                "isp": "Clean Network Provider",
            }
        }
        res_abuse = normalize_abuseipdb_response("192.0.2.1", abuse_data)
        self.assertEqual(res_abuse.reputation, ReputationLevel.CLEAN.value)
        self.assertEqual(res_abuse.confidence, 0.0)
        self.assertEqual(res_abuse.country, "DE")

    def test_13_postgresql_persistence(self):
        """13. PostgreSQL persistence of threat intelligence results."""
        with SessionLocal() as db:
            test_case = Case(
                id=uuid.uuid4(),
                case_number=f"CASE-TEST-{uuid.uuid4().hex[:6].upper()}",
                title="Threat Intel Persistence Test",
                status="open",
                priority="medium",
            )
            db.add(test_case)
            db.commit()

            service = ThreatIntelService(vt_provider=self.vt, abuse_provider=self.abuse)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5, "harmless": 50},
                        "country": "US",
                    }
                }
            }

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
                results = asyncio.run(
                    service.enrich_indicator(db, IndicatorType.DOMAIN, "threat-test.com", test_case.id)
                )
                self.assertEqual(len(results), 1)

            # Query database to confirm row exists in threat_intelligence_results
            db_records = (
                db.query(ThreatIntelligenceResult)
                .filter(ThreatIntelligenceResult.case_id == test_case.id)
                .all()
            )
            self.assertEqual(len(db_records), 1)
            self.assertEqual(db_records[0].indicator_value, "threat-test.com")
            self.assertEqual(db_records[0].provider, "virustotal")
            self.assertEqual(db_records[0].reputation, "malicious")
            self.assertIsNotNone(db_records[0].raw_response)

    def test_14_case_with_multiple_iocs(self):
        """14. Case with multiple IoCs (IPs, domains, URLs, attachment hashes)."""
        with SessionLocal() as db:
            test_case = Case(
                id=uuid.uuid4(),
                case_number=f"CASE-MULTI-{uuid.uuid4().hex[:6].upper()}",
                title="Multi IoC Enrichment Test",
                status="open",
                priority="medium",
            )
            db.add(test_case)

            email_rec = Email(
                id=uuid.uuid4(),
                case_id=test_case.id,
                subject="Multi-IoC Test Email",
                analysis_status="parsed",
            )
            db.add(email_rec)

            db.add(IPAddress(id=uuid.uuid4(), email_id=email_rec.id, ip_address="203.0.113.55"))
            db.add(Domain(id=uuid.uuid4(), email_id=email_rec.id, domain="attack-server.net"))
            db.add(URL(id=uuid.uuid4(), email_id=email_rec.id, url="https://attack-server.net/payload"))
            db.add(
                Attachment(
                    id=uuid.uuid4(),
                    email_id=email_rec.id,
                    file_name="malware.bin",
                    sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
                )
            )
            db.commit()

            service = ThreatIntelService(vt_provider=self.vt, abuse_provider=self.abuse)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {
                    "attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 20}},
                    "abuseConfidenceScore": 25,
                    "countryCode": "US",
                }
            }

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
                summary = asyncio.run(service.enrich_case(db, test_case.id))
                # IP queries 2 providers (VT + AbuseIPDB), Domain queries VT, URL queries VT, Hash queries VT = 5 queries
                self.assertEqual(summary.total_indicators, 4)
                self.assertEqual(summary.total_queries, 5)
                self.assertIn("virustotal", summary.providers_used)
                self.assertIn("abuseipdb", summary.providers_used)

    def test_15_caching_no_duplicate_enrichment(self):
        """15. No duplicate external queries when cached result is still valid."""
        with SessionLocal() as db:
            test_case = Case(
                id=uuid.uuid4(),
                case_number=f"CASE-CACHE-{uuid.uuid4().hex[:6].upper()}",
                title="Cache Test",
                status="open",
                priority="medium",
            )
            db.add(test_case)
            db.commit()

            service = ThreatIntelService(vt_provider=self.vt, abuse_provider=self.abuse)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {
                    "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 50}}
                }
            }

            unique_domain = f"cache-{uuid.uuid4().hex[:8]}.example.com"
            mock_get = AsyncMock(return_value=mock_resp)
            with patch("httpx.AsyncClient.get", mock_get):
                # First call: hits provider
                results1 = asyncio.run(
                    service.enrich_indicator(db, IndicatorType.DOMAIN, unique_domain, test_case.id)
                )
                self.assertEqual(mock_get.call_count, 1)

                # Second call: must use cache, NOT call mock_get again!
                results2 = asyncio.run(
                    service.enrich_indicator(db, IndicatorType.DOMAIN, unique_domain, test_case.id)
                )
                # Call count remains 1!
                self.assertEqual(mock_get.call_count, 1)
                self.assertEqual(results2[0].indicator_value, unique_domain)


if __name__ == "__main__":
    unittest.main()
