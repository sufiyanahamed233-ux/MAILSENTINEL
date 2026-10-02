import uuid
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.network import Domain, IPAddress, URL
from app.schemas.email_analysis import ParsedEmailData


def persist_forensic_data(
    db: Session,
    parsed: ParsedEmailData,
    case_id: uuid.UUID | None = None,
) -> tuple[Case, Email]:
    """Persist structured parsed email forensic indicators into PostgreSQL.

    Uses existing SQLAlchemy 2.x models without duplicating records.
    """
    # 1. Resolve or create Case
    case: Case | None = None
    if case_id:
        case = db.query(Case).filter(Case.id == case_id).first()

    if not case:
        case_num = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        case_title = f"Investigation: {parsed.subject or parsed.raw_file_name}"
        case_desc = f"Forensic analysis of email artifact: {parsed.raw_file_name}"
        case = Case(
            id=case_id or uuid.uuid4(),
            case_number=case_num,
            title=case_title,
            description=case_desc,
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

    # 2. Create Email record
    email_record = Email(
        id=uuid.uuid4(),
        case_id=case.id,
        message_id=parsed.message_id,
        subject=parsed.subject,
        sender=parsed.sender,
        sender_domain=parsed.sender_domain,
        reply_to=parsed.reply_to,
        received_at=parsed.received_at,
        raw_file_name=parsed.raw_file_name,
        raw_file_hash=parsed.raw_file_hash,
        analysis_status="parsed",
    )
    db.add(email_record)
    db.flush()

    # 3. Persist Headers
    for header in parsed.headers:
        header_record = EmailHeader(
            id=uuid.uuid4(),
            email_id=email_record.id,
            header_name=header.header_name,
            header_value=header.header_value,
            header_order=header.header_order,
        )
        db.add(header_record)

    # 4. Persist URLs (deduplicated by normalized URL)
    seen_urls: set[str] = set()
    for u in parsed.urls:
        if u.normalized_url not in seen_urls:
            seen_urls.add(u.normalized_url)
            url_record = URL(
                id=uuid.uuid4(),
                email_id=email_record.id,
                url=u.url,
                normalized_url=u.normalized_url,
                domain=u.domain,
                scheme=u.scheme,
                path=u.path,
                reputation=None,
            )
            db.add(url_record)

    # 5. Persist Domains (deduplicated)
    seen_domains: set[str] = set()
    for d in parsed.domains:
        if d.domain not in seen_domains:
            seen_domains.add(d.domain)
            domain_record = Domain(
                id=uuid.uuid4(),
                email_id=email_record.id,
                domain=d.domain,
                registrar=None,
                reputation=None,
            )
            db.add(domain_record)

    # 6. Persist IP Addresses (deduplicated)
    seen_ips: set[str] = set()
    for ip_item in parsed.ip_addresses:
        if ip_item.ip_address not in seen_ips:
            seen_ips.add(ip_item.ip_address)
            ip_record = IPAddress(
                id=uuid.uuid4(),
                email_id=email_record.id,
                ip_address=ip_item.ip_address,
                version=ip_item.version,
                reputation=None,
            )
            db.add(ip_record)

    # 7. Persist Attachments
    for att in parsed.attachments:
        attachment_record = Attachment(
            id=uuid.uuid4(),
            email_id=email_record.id,
            file_name=att.file_name,
            content_type=att.content_type,
            file_size=att.file_size,
            sha256=att.sha256,
            md5=att.md5,
        )
        db.add(attachment_record)

    db.commit()
    db.refresh(case)
    db.refresh(email_record)

    return case, email_record
