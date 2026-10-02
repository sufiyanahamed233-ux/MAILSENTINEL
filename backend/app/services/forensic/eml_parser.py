import email
from email import policy
from email.header import decode_header
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any

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


def decode_header_str(val: Any) -> str:
    """Safely decode an RFC 2047 encoded header string."""
    if val is None:
        return ""
    val_str = str(val)
    try:
        decoded_chunks = decode_header(val_str)
        result_parts = []
        for text_bytes, encoding in decoded_chunks:
            if isinstance(text_bytes, bytes):
                enc = encoding or "utf-8"
                try:
                    result_parts.append(text_bytes.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    result_parts.append(text_bytes.decode("latin1", errors="replace"))
            else:
                result_parts.append(str(text_bytes))
        return "".join(result_parts).strip()
    except Exception:
        return val_str.strip()


def parse_date_header(date_str: str | None) -> datetime | None:
    """Parse date header string to a timezone-aware datetime."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str.strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def parse_eml_bytes(raw_bytes: bytes, filename: str) -> ParsedEmailData:
    """Parse raw bytes of an .eml email message into structured forensic data."""
    raw_file_hash = calculate_sha256(raw_bytes)

    # Parse with default policy which handles basic RFC 2047 and modern email conventions
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    # 1. Extract all headers preserving sequence
    headers_list: list[ParsedHeader] = []
    received_headers: list[str] = []

    for order, (header_name, header_val) in enumerate(msg.items()):
        val_str = decode_header_str(header_val)
        headers_list.append(
            ParsedHeader(
                header_name=header_name,
                header_value=val_str,
                header_order=order,
            )
        )
        if header_name.lower() == "received":
            received_headers.append(val_str)

    # 2. General metadata
    message_id = decode_header_str(msg.get("Message-ID") or msg.get("Message-Id") or msg.get("message-id"))
    message_id = message_id.strip() if message_id else None

    subject = decode_header_str(msg.get("Subject"))
    subject = subject.strip() if subject else None

    sender = decode_header_str(msg.get("From"))
    sender = sender.strip() if sender else None
    sender_domain = extract_domain_from_email(sender)

    reply_to = decode_header_str(msg.get("Reply-To") or msg.get("reply-to"))
    reply_to = reply_to.strip() if reply_to else None

    # Received timestamp (try Date header first, then topmost Received header)
    received_at = parse_date_header(msg.get("Date"))
    if not received_at and received_headers:
        # Received headers often end with '; <date string>'
        for r_header in received_headers:
            if ";" in r_header:
                date_part = r_header.split(";")[-1].strip()
                received_at = parse_date_header(date_part)
                if received_at:
                    break

    # 3. Extract bodies and attachments
    plain_bodies: list[str] = []
    html_bodies: list[str] = []
    attachments: list[ParsedAttachment] = []

    for part in msg.walk():
        # Skip container multipart items
        if part.is_multipart():
            continue

        content_disposition = str(part.get_content_disposition() or "").lower()
        part_filename = part.get_filename()

        # Check if part is an attachment
        is_attachment = (
            content_disposition == "attachment"
            or (part_filename is not None and content_disposition != "inline")
            or (part_filename is not None and part.get_content_type() not in ("text/plain", "text/html"))
        )

        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            safe_fname = sanitize_filename(part_filename or "unnamed_attachment")
            att_sha256 = calculate_sha256(payload)
            att_md5 = calculate_md5(payload)
            content_type = str(part.get_content_type() or "application/octet-stream")

            attachments.append(
                ParsedAttachment(
                    file_name=safe_fname,
                    content_type=content_type,
                    file_size=len(payload),
                    sha256=att_sha256,
                    md5=att_md5,
                )
            )
        else:
            # Body part
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"

            try:
                decoded_text = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                decoded_text = payload.decode("latin1", errors="replace")

            if content_type == "text/plain":
                plain_bodies.append(decoded_text)
            elif content_type == "text/html":
                html_bodies.append(decoded_text)

    full_plain = "\n".join(plain_bodies) if plain_bodies else None
    full_html = "\n".join(html_bodies) if html_bodies else None

    # 4. Extract URLs from body & relevant headers
    text_corpus_for_urls = [full_plain or "", full_html or ""]
    for h in headers_list:
        if h.header_name.lower() in ("list-unsubscribe", "x-mailer", "x-originating-url"):
            text_corpus_for_urls.append(h.header_value)

    extracted_url_dicts = extract_urls(" \n".join(text_corpus_for_urls))
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

    # 5. Extract IP addresses (especially from Received headers)
    received_corpus = " \n".join(received_headers)
    found_ips = extract_ips(received_corpus)
    ip_addresses: list[ParsedIP] = [
        ParsedIP(ip_address=ip_str, version=version)
        for ip_str, version in found_ips
    ]

    # 6. Extract Domains
    domain_candidates: list[str] = []
    if sender_domain:
        domain_candidates.append(sender_domain)
    reply_to_domain = extract_domain_from_email(reply_to)
    if reply_to_domain:
        domain_candidates.append(reply_to_domain)
    for u in urls:
        if u.domain:
            domain_candidates.append(u.domain)
    # Also scan from Received headers for hostnames
    domain_candidates.extend(extract_domains(domain_candidates))
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
        body_plain=full_plain,
        body_html=full_html,
        headers=headers_list,
        received_headers=received_headers,
        urls=urls,
        domains=domains,
        ip_addresses=ip_addresses,
        attachments=attachments,
    )
