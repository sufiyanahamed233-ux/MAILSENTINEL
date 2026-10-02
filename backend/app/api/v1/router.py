import os
import uuid
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.email_analysis import (
    EmailAnalysisResponse,
    ParsedAttachment,
    ParsedURL,
)
from app.services.forensic.parser import parse_email
from app.services.forensic.persistence import persist_forensic_data
from app.services.threat_intel import CaseEnrichmentSummary, ThreatIntelService


api_router = APIRouter()

# Maximum allowed email file size: 25 MB
MAX_EMAIL_FILE_SIZE = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".eml", ".msg"}


@api_router.post(
    "/analyze-email",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and parse an email (.eml or .msg) for forensic analysis",
    tags=["Forensics"],
)
async def analyze_email(
    file: UploadFile = File(..., description="Raw email file (.eml or .msg)"),
    case_id: uuid.UUID | None = Form(None, description="Optional existing case UUID to associate evidence with"),
    db: Session = Depends(get_db),
) -> EmailAnalysisResponse:
    """Analyze an uploaded .eml or .msg email file, extract forensic artifacts,

    and persist them to the database.
    """
    filename = file.filename or "unknown.eml"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Only .eml and .msg files are supported.",
        )

    # Read uploaded bytes safely
    raw_bytes = await file.read()

    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes).",
        )

    if len(raw_bytes) > MAX_EMAIL_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed upload size of {MAX_EMAIL_FILE_SIZE // (1024 * 1024)} MB.",
        )

    # Parse raw bytes
    try:
        parsed_data = parse_email(raw_bytes, filename)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse email file: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Error processing email structure: {str(e)}",
        )

    # Persist forensic indicators into PostgreSQL
    case, email_record = persist_forensic_data(db, parsed_data, case_id=case_id)

    # Construct response
    return EmailAnalysisResponse(
        case_id=case.id,
        case_number=case.case_number,
        email_id=email_record.id,
        raw_file_name=email_record.raw_file_name or filename,
        raw_file_hash=email_record.raw_file_hash or parsed_data.raw_file_hash,
        message_id=email_record.message_id,
        subject=email_record.subject,
        sender=email_record.sender,
        sender_domain=email_record.sender_domain,
        reply_to=email_record.reply_to,
        received_at=email_record.received_at,
        analysis_status=email_record.analysis_status,
        created_at=email_record.created_at,
        headers_count=len(parsed_data.headers),
        urls_count=len(parsed_data.urls),
        domains_count=len(parsed_data.domains),
        ip_addresses_count=len(parsed_data.ip_addresses),
        attachments_count=len(parsed_data.attachments),
        urls=[
            ParsedURL(
                url=u.url,
                normalized_url=u.normalized_url,
                domain=u.domain,
                scheme=u.scheme,
                path=u.path,
            )
            for u in parsed_data.urls
        ],
        domains=[d.domain for d in parsed_data.domains],
        ip_addresses=[ip.ip_address for ip in parsed_data.ip_addresses],
        attachments=[
            ParsedAttachment(
                file_name=att.file_name,
                content_type=att.content_type,
                file_size=att.file_size,
                sha256=att.sha256,
                md5=att.md5,
            )
            for att in parsed_data.attachments
        ],
    )


@api_router.post(
    "/cases/{case_id}/threat-intelligence",
    response_model=CaseEnrichmentSummary,
    status_code=status.HTTP_200_OK,
    summary="Trigger threat intelligence enrichment for an existing investigation case",
    tags=["Threat Intelligence"],
)
async def enrich_case_threat_intelligence(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> CaseEnrichmentSummary:
    """Collect observed IoCs from an investigation case, query configured threat

    intelligence providers (VirusTotal, AbuseIPDB) or DB cache, persist the results,
    and return structured enrichment results.
    """
    service = ThreatIntelService()
    try:
        return await service.enrich_case(db=db, case_id=case_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing threat intelligence enrichment: {str(exc)}",
        )

