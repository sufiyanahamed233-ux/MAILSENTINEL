import email
import io
from datetime import datetime, timezone
import extract_msg

from app.schemas.email_analysis import (
    ParsedAttachment,
    ParsedDomain,
    ParsedEmailData,
    ParsedHeader,
    ParsedIP,
    ParsedURL,
)
from app.services.forensic.extractors import (
    extract_domain_from_email,
    extract_domains,
    extract_ips,
    extract_urls,
    sanitize_filename,
)
from app.services.forensic.hashing import calculate_md5, calculate_sha256


def parse_msg_bytes(raw_bytes: bytes, filename: str) -> ParsedEmailData:
    """Parse raw bytes of an Outlook .msg email file into structured forensic data."""
    raw_file_hash = calculate_sha256(raw_bytes)

    # Use BytesIO with extract_msg.openMsg
    bio = io.BytesIO(raw_bytes)
    msg = extract_msg.openMsg(bio)

    try:
        subject = msg.subject.strip() if msg.subject else None
        sender = msg.sender.strip() if msg.sender else None
        sender_domain = extract_domain_from_email(sender)

        # Message ID
        message_id = None
        if hasattr(msg, "messageId") and msg.messageId:
            message_id = str(msg.messageId).strip()

        # Date / received_at
        received_at: datetime | None = None
        if msg.date:
            if isinstance(msg.date, datetime):
                received_at = msg.date
                if received_at.tzinfo is None:
                    received_at = received_at.replace(tzinfo=timezone.utc)
            elif isinstance(msg.date, str):
                try:
                    from email.utils import parsedate_to_datetime
                    received_at = parsedate_to_datetime(msg.date)
                    if received_at and received_at.tzinfo is None:
                        received_at = received_at.replace(tzinfo=timezone.utc)
                except Exception:
                    pass

        # Reply-To
        reply_to = None
        if hasattr(msg, "replyTo") and msg.replyTo:
            reply_to = str(msg.replyTo).strip()

        # Bodies
        body_plain = msg.body if msg.body else None

        body_html = None
        if hasattr(msg, "htmlBody") and msg.htmlBody:
            if isinstance(msg.htmlBody, bytes):
                try:
                    body_html = msg.htmlBody.decode("utf-8", errors="replace")
                except Exception:
                    body_html = msg.htmlBody.decode("latin1", errors="replace")
            else:
                body_html = str(msg.htmlBody)

        # Headers
        headers_list: list[ParsedHeader] = []
        received_headers: list[str] = []

        raw_header_str = getattr(msg, "header", None) or getattr(msg, "headers", None)
        if raw_header_str:
            parsed_headers = email.message_from_string(str(raw_header_str))
            for order, (h_name, h_val) in enumerate(parsed_headers.items()):
                val_str = str(h_val).strip()
                headers_list.append(
                    ParsedHeader(
                        header_name=h_name,
                        header_value=val_str,
                        header_order=order,
                    )
                )
                if h_name.lower() == "received":
                    received_headers.append(val_str)
                if not message_id and h_name.lower() == "message-id":
                    message_id = val_str
                if not reply_to and h_name.lower() == "reply-to":
                    reply_to = val_str
        else:
            # Construct synthetic headers if transport headers are absent in internal .msg
            order = 0
            if sender:
                headers_list.append(ParsedHeader(header_name="From", header_value=sender, header_order=order))
                order += 1
            if hasattr(msg, "to") and msg.to:
                headers_list.append(ParsedHeader(header_name="To", header_value=str(msg.to), header_order=order))
                order += 1
            if hasattr(msg, "cc") and msg.cc:
                headers_list.append(ParsedHeader(header_name="Cc", header_value=str(msg.cc), header_order=order))
                order += 1
            if subject:
                headers_list.append(ParsedHeader(header_name="Subject", header_value=subject, header_order=order))
                order += 1
            if received_at:
                headers_list.append(ParsedHeader(header_name="Date", header_value=received_at.isoformat(), header_order=order))
                order += 1
            if message_id:
                headers_list.append(ParsedHeader(header_name="Message-ID", header_value=message_id, header_order=order))
                order += 1

        # Attachments
        attachments: list[ParsedAttachment] = []
        if hasattr(msg, "attachments") and msg.attachments:
            for att in msg.attachments:
                # Get raw bytes
                data = getattr(att, "data", None)
                if data is None:
                    continue
                if not isinstance(data, bytes):
                    data = bytes(data)

                # Determine filename
                raw_filename = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or getattr(att, "filename", None)
                safe_fname = sanitize_filename(raw_filename or "unnamed_attachment")
                content_type = getattr(att, "mimetype", None) or "application/octet-stream"

                attachments.append(
                    ParsedAttachment(
                        file_name=safe_fname,
                        content_type=content_type,
                        file_size=len(data),
                        sha256=calculate_sha256(data),
                        md5=calculate_md5(data),
                    )
                )

        # URLs
        text_corpus = [body_plain or "", body_html or ""]
        extracted_url_dicts = extract_urls(" \n".join(text_corpus))
        urls: list[ParsedURL] = [
            ParsedURL(
                url=u["url"],  # type: ignore[arg-type]
                normalized_url=u["normalized_url"],  # type: ignore[arg-type]
                domain=u["domain"],
                scheme=u["scheme"],
                path=u["path"],
            )
            for u in extracted_url_dicts
        ]

        # IPs
        ip_corpus = " \n".join(received_headers) if received_headers else " \n".join(text_corpus)
        found_ips = extract_ips(ip_corpus)
        ip_addresses: list[ParsedIP] = [
            ParsedIP(ip_address=ip_str, version=version)
            for ip_str, version in found_ips
        ]

        # Domains
        domain_candidates: list[str] = []
        if sender_domain:
            domain_candidates.append(sender_domain)
        reply_to_domain = extract_domain_from_email(reply_to)
        if reply_to_domain:
            domain_candidates.append(reply_to_domain)
        for u in urls:
            if u.domain:
                domain_candidates.append(u.domain)
        unique_domains = extract_domains(domain_candidates)
        domains: list[ParsedDomain] = [ParsedDomain(domain=d) for d in unique_domains]

        return ParsedEmailData(
            message_id=message_id,
            subject=subject,
            sender=sender,
            sender_domain=sender_domain,
            reply_to=reply_to,
            received_at=received_at,
            raw_file_name=filename,
            raw_file_hash=raw_file_hash,
            body_plain=body_plain,
            body_html=body_html,
            headers=headers_list,
            received_headers=received_headers,
            urls=urls,
            domains=domains,
            ip_addresses=ip_addresses,
            attachments=attachments,
        )
    finally:
        msg.close()
