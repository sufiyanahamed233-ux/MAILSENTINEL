import io
import unittest
from unittest.mock import MagicMock, patch
from email.message import EmailMessage
from datetime import datetime, timezone
import hashlib

from fastapi import UploadFile, HTTPException

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.network import Domain, IPAddress, URL
from app.services.forensic.extractors import (
    extract_domain_from_email,
    extract_ips,
    extract_urls,
    sanitize_filename,
)
from app.services.forensic.hashing import calculate_md5, calculate_sha256
from app.services.forensic.parser import parse_email
from app.services.forensic.eml_parser import parse_eml_bytes
from app.services.forensic.msg_parser import parse_msg_bytes
from app.services.forensic.persistence import persist_forensic_data
from app.api.v1.router import analyze_email


class TestForensicEmailParser(unittest.TestCase):
    """Comprehensive test suite for forensic .eml and .msg email parsing."""

    def test_hashing_utilities(self):
        """Test SHA-256 and MD5 hash calculations."""
        sample_bytes = b"Forensic email evidence test"
        expected_sha = hashlib.sha256(sample_bytes).hexdigest()
        expected_md5 = hashlib.md5(sample_bytes).hexdigest()

        self.assertEqual(calculate_sha256(sample_bytes), expected_sha)
        self.assertEqual(calculate_md5(sample_bytes), expected_md5)

    def test_extractors(self):
        """Test domain, IP, URL, and filename extractors."""
        # Domain from email
        self.assertEqual(extract_domain_from_email("Analyst <analyst@sentinel.org>"), "sentinel.org")
        self.assertEqual(extract_domain_from_email("threat@bad-actor.com"), "bad-actor.com")
        self.assertIsNone(extract_domain_from_email("invalid-email"))

        # IPs (IPv4 and IPv6)
        text_with_ips = (
            "Received: from mx1.threat.net (mx1.threat.net [198.51.100.45]) "
            "by mail.target.org with ESMTP; IPv6: 2001:db8::1"
        )
        ips = extract_ips(text_with_ips)
        ip_dict = {ip: ver for ip, ver in ips}
        self.assertIn("198.51.100.45", ip_dict)
        self.assertEqual(ip_dict["198.51.100.45"], 4)
        self.assertIn("2001:db8::1", ip_dict)
        self.assertEqual(ip_dict["2001:db8::1"], 6)

        # URL extraction and deduplication
        text_with_urls = (
            "Check this link: https://evil.com/phish?id=1 and again https://evil.com/phish?id=1 "
            "and also http://legit.org/index.html"
        )
        urls = extract_urls(text_with_urls)
        # Should be deduplicated to 2 URLs
        self.assertEqual(len(urls), 2)
        urls_by_norm = {u["normalized_url"]: u for u in urls}
        self.assertIn("https://evil.com/phish?id=1", urls_by_norm)
        self.assertEqual(urls_by_norm["https://evil.com/phish?id=1"]["domain"], "evil.com")

        # Filename sanitation
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("C:\\Windows\\System32\\calc.exe"), "calc.exe")
        self.assertEqual(sanitize_filename(None), "unnamed_attachment")

    def test_a_simple_eml(self):
        """A. Simple .eml parsing: From, Subject, Message-ID, Body."""
        eml_raw = (
            b"From: Security Team <security@corp.net>\r\n"
            b"To: Analyst <analyst@corp.net>\r\n"
            b"Subject: Incident Notification\r\n"
            b"Message-ID: <inc-12345@corp.net>\r\n"
            b"Date: Wed, 01 Oct 2026 10:00:00 +0000\r\n"
            b"\r\n"
            b"Suspicious login activity observed on workstation.\r\n"
        )
        parsed = parse_eml_bytes(eml_raw, "alert.eml")

        self.assertEqual(parsed.sender, "Security Team <security@corp.net>")
        self.assertEqual(parsed.sender_domain, "corp.net")
        self.assertEqual(parsed.subject, "Incident Notification")
        self.assertEqual(parsed.message_id, "<inc-12345@corp.net>")
        self.assertIn("Suspicious login activity", parsed.body_plain or "")
        self.assertEqual(parsed.raw_file_hash, hashlib.sha256(eml_raw).hexdigest())

    def test_b_multipart_eml(self):
        """B. Multipart .eml: Text body and HTML body."""
        msg = EmailMessage()
        msg["From"] = "info@updates.com"
        msg["To"] = "victim@target.org"
        msg["Subject"] = "Quarterly Summary"
        msg["Message-ID"] = "<part-999@updates.com>"
        msg.set_content("Plain text quarterly summary.")
        msg.add_alternative("<p>HTML formatted <b>quarterly</b> summary.</p>", subtype="html")

        eml_bytes = msg.as_bytes()
        parsed = parse_eml_bytes(eml_bytes, "quarterly.eml")

        self.assertIsNotNone(parsed.body_plain)
        self.assertIn("Plain text quarterly summary", parsed.body_plain)
        self.assertIsNotNone(parsed.body_html)
        self.assertIn("<b>quarterly</b>", parsed.body_html)

    def test_c_attachment_eml(self):
        """C. Email with attachment: filename, MIME, size, SHA-256, MD5 (no binary in DB)."""
        msg = EmailMessage()
        msg["From"] = "hacker@bad.net"
        msg["To"] = "target@victim.com"
        msg["Subject"] = "Invoice attached"
        msg.set_content("Please find attached invoice.")

        attachment_data = b"%PDF-1.4 Simulated malicious PDF invoice content"
        msg.add_attachment(
            attachment_data,
            maintype="application",
            subtype="pdf",
            filename="invoice_urgent.pdf",
        )

        eml_bytes = msg.as_bytes()
        parsed = parse_eml_bytes(eml_bytes, "invoice.eml")

        self.assertEqual(len(parsed.attachments), 1)
        att = parsed.attachments[0]
        self.assertEqual(att.file_name, "invoice_urgent.pdf")
        self.assertEqual(att.content_type, "application/pdf")
        self.assertEqual(att.file_size, len(attachment_data))
        self.assertEqual(att.sha256, hashlib.sha256(attachment_data).hexdigest())
        self.assertEqual(att.md5, hashlib.md5(attachment_data).hexdigest())

    def test_d_received_headers_and_ips(self):
        """D. Received headers: multiple headers and IP extraction."""
        eml_raw = (
            b"Received: from relay2.isp.net (relay2.isp.net [203.0.113.195]) by mx.target.com;\r\n"
            b"Received: from mail.attacker.org (mail.attacker.org [198.51.100.77]) by relay2.isp.net;\r\n"
            b"From: test@attacker.org\r\n"
            b"Subject: Test Received\r\n"
            b"\r\n"
            b"Hello world\r\n"
        )
        parsed = parse_eml_bytes(eml_raw, "received.eml")

        self.assertEqual(len(parsed.received_headers), 2)
        extracted_ip_strings = {ip.ip_address for ip in parsed.ip_addresses}
        self.assertIn("203.0.113.195", extracted_ip_strings)
        self.assertIn("198.51.100.77", extracted_ip_strings)

    def test_e_url_extraction(self):
        """E. URL extraction: multiple URLs and duplicate handling."""
        eml_raw = (
            b"From: promo@offers.com\r\n"
            b"Subject: Check these deals\r\n"
            b"\r\n"
            b"Visit https://store.deals.com/item1 and https://store.deals.com/item1 "
            b"or visit https://partner.org/signup?ref=promo\r\n"
        )
        parsed = parse_eml_bytes(eml_raw, "deals.eml")

        self.assertEqual(len(parsed.urls), 2)
        urls_set = {u.normalized_url for u in parsed.urls}
        self.assertIn("https://store.deals.com/item1", urls_set)
        self.assertIn("https://partner.org/signup?ref=promo", urls_set)

    def test_f_encoded_headers(self):
        """F. Encoded headers (RFC 2047)."""
        eml_raw = (
            b"From: =?UTF-8?B?U2VjdXJpdHkgT2ZmaWNlcg==?= <officer@secure.org>\r\n"
            b"Subject: =?UTF-8?B?Q3JpdGljYWwgQWxlcnQ6IOKAkSBVUkwgRGV0ZWN0ZWQ=?=\r\n"
            b"\r\n"
            b"Alert body\r\n"
        )
        parsed = parse_eml_bytes(eml_raw, "encoded.eml")

        self.assertIn("Security Officer", parsed.sender or "")
        self.assertIn("Critical Alert:", parsed.subject or "")

    def test_g_raw_email_sha256(self):
        """G. Raw email SHA-256 calculation matches input bytes exactly."""
        eml_raw = b"From: a@b.com\r\nSubject: Test\r\n\r\nSample body"
        expected_hash = hashlib.sha256(eml_raw).hexdigest()
        parsed = parse_eml_bytes(eml_raw, "test.eml")

        self.assertEqual(parsed.raw_file_hash, expected_hash)

    def test_h_invalid_unsupported_file_handling(self):
        """H. Invalid/unsupported file handling raises ValueError."""
        # Empty file
        with self.assertRaises(ValueError) as ctx_empty:
            parse_email(b"", "empty.eml")
        self.assertIn("empty", str(ctx_empty.exception).lower())

        # Unsupported file extension
        with self.assertRaises(ValueError) as ctx_ext:
            parse_email(b"%PDF-1.4 binary garbage without email headers", "document.pdf")
        self.assertIn("unsupported", str(ctx_ext.exception).lower())

    def test_i_msg_parsing_mocked_and_dispatched(self):
        """I. .msg parsing structure and dispatcher routing."""
        mock_msg = MagicMock()
        mock_msg.subject = "Urgent Financial Review"
        mock_msg.sender = "CEO <ceo@company.com>"
        mock_msg.messageId = "<ceo-msg-001@company.com>"
        mock_msg.date = datetime(2026, 10, 1, 14, 30, tzinfo=timezone.utc)
        mock_msg.replyTo = "finance@company.com"
        mock_msg.body = "Please review wire transfer at https://transfer.company.com/auth"
        mock_msg.htmlBody = None
        mock_msg.header = "From: CEO <ceo@company.com>\r\nSubject: Urgent Financial Review\r\n"

        # Mock attachment
        mock_att = MagicMock()
        mock_att.longFilename = "wire_instruction.pdf"
        mock_att.data = b"%PDF mock wire instructions content"
        mock_att.mimetype = "application/pdf"
        mock_msg.attachments = [mock_att]

        with patch("extract_msg.openMsg", return_value=mock_msg):
            dummy_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"dummy compound data"
            parsed = parse_msg_bytes(dummy_bytes, "urgent.msg")

            self.assertEqual(parsed.subject, "Urgent Financial Review")
            self.assertEqual(parsed.sender_domain, "company.com")
            self.assertEqual(parsed.reply_to, "finance@company.com")
            self.assertEqual(len(parsed.attachments), 1)
            self.assertEqual(parsed.attachments[0].file_name, "wire_instruction.pdf")
            self.assertEqual(len(parsed.urls), 1)
            self.assertEqual(parsed.urls[0].domain, "transfer.company.com")

            # Also verify parse_email dispatcher dispatches to parse_msg_bytes
            dispatched = parse_email(dummy_bytes, "urgent.msg")
            self.assertEqual(dispatched.subject, "Urgent Financial Review")

    def test_database_persistence(self):
        """Verify persistence of parsed email artifacts into PostgreSQL."""
        eml_raw = (
            b"From: Analyst <analyst@forensic.org>\r\n"
            b"To: Lead <lead@forensic.org>\r\n"
            b"Subject: Forensic Ingest Test\r\n"
            b"Message-ID: <test-db-persist-001@forensic.org>\r\n"
            b"Received: from gateway.isp.net ([203.0.113.88]) by forensic.org;\r\n"
            b"\r\n"
            b"Found IOC at http://malicious-domain.biz/payload.exe\r\n"
        )
        parsed = parse_eml_bytes(eml_raw, "ingest_test.eml")

        with SessionLocal() as db:
            case, email_rec = persist_forensic_data(db, parsed)
            self.assertIsNotNone(case.id)
            self.assertIsNotNone(email_rec.id)
            self.assertEqual(email_rec.case_id, case.id)

            # Query database directly to confirm records exist
            queried_headers = db.query(EmailHeader).filter(EmailHeader.email_id == email_rec.id).all()
            self.assertGreater(len(queried_headers), 0)

            queried_urls = db.query(URL).filter(URL.email_id == email_rec.id).all()
            self.assertEqual(len(queried_urls), 1)
            self.assertEqual(queried_urls[0].domain, "malicious-domain.biz")

            queried_domains = db.query(Domain).filter(Domain.email_id == email_rec.id).all()
            domain_names = {d.domain for d in queried_domains}
            self.assertIn("forensic.org", domain_names)
            self.assertIn("malicious-domain.biz", domain_names)

            queried_ips = db.query(IPAddress).filter(IPAddress.email_id == email_rec.id).all()
            ip_addrs = {ip.ip_address for ip in queried_ips}
            self.assertIn("203.0.113.88", ip_addrs)

    def test_analyze_email_endpoint(self):
        """Test POST /api/v1/analyze-email endpoint with valid .eml file."""
        import asyncio

        eml_bytes = (
            b"From: SecOps <secops@cyber.org>\r\n"
            b"Subject: Phishing Report\r\n"
            b"Message-ID: <phish-rep-101@cyber.org>\r\n"
            b"\r\n"
            b"Detected phish link: https://login.phishingsite.net/secure\r\n"
        )
        upload = UploadFile(
            file=io.BytesIO(eml_bytes),
            filename="suspicious.eml",
        )

        with SessionLocal() as db:
            response = asyncio.run(analyze_email(file=upload, case_id=None, db=db))
            self.assertEqual(response.raw_file_name, "suspicious.eml")
            self.assertEqual(response.subject, "Phishing Report")
            self.assertEqual(response.sender_domain, "cyber.org")
            self.assertEqual(response.urls_count, 1)
            self.assertIn("phishingsite.net", response.domains)


if __name__ == "__main__":
    unittest.main()
