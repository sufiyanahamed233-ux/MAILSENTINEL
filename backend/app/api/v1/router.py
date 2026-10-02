import os
import uuid
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.ai_analysis import AIAnalysisResultResponse
from app.schemas.email_analysis import (
    EmailAnalysisResponse,
    ParsedAttachment,
    ParsedURL,
)
from app.schemas.investigation import CaseListResponse, CaseWorkspaceResponse
from app.schemas.investigation_detail import EmailDetailResponse
from app.schemas.evidence import (
    EvidenceListResponse,
    EventListResponse,
    IndicatorListResponse,
)
from app.schemas.report import CaseReportResponse
from app.services.ai.orchestrator import (
    CaseNotFoundServiceError,
    ProviderAuthError,
    ProviderNotConfiguredError,
    ProviderResponseError,
    ProviderUnavailableError,
    run_ai_analysis,
)
from app.services.forensic.parser import parse_email
from app.services.forensic.persistence import persist_forensic_data
from app.services.investigation import (
    CaseNotFoundError,
    EmailNotBelongToCaseError,
    EmailNotFoundError,
    generate_case_report,
    get_case_evidence,
    get_case_events,
    get_case_indicators,
    get_case_workspace,
    get_email_detail,
    list_cases,
)
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


@api_router.post(
    "/cases/{case_id}/ai-analysis",
    response_model=AIAnalysisResultResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Run AI threat analysis on an investigation case and persist the result",
    tags=["AI Analysis"],
)
def trigger_ai_analysis(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> AIAnalysisResultResponse:
    """Orchestrate AI threat analysis for an existing investigation case.

    Steps performed:
    1. Build deterministic forensic context from all evidence in the database.
    2. Invoke the configured Gemini AI provider to produce a structured assessment.
    3. Persist the validated AIThreatAssessment as a new AIAnalysisResult row.

    Returns the freshly persisted analysis.  Raw email content, email bodies,
    attachment binaries, and API keys are never included in the response.
    """
    try:
        result = run_ai_analysis(db=db, case_id=case_id)
        return AIAnalysisResultResponse.model_validate(result)

    except CaseNotFoundServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except ProviderNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except ProviderAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except ProviderUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except ProviderResponseError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error during AI analysis: {str(exc)}",
        )


@api_router.get(
    "/cases/{case_id}",
    response_model=CaseWorkspaceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get complete investigation case workspace",
    tags=["Investigation"],
)
def get_case(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> CaseWorkspaceResponse:
    """Retrieve the complete investigation workspace for a case.

    Includes all associated emails and observed forensic artifacts,
    external threat intelligence results, AI threat assessments,
    chronological audit events, and computed summary metrics.
    """
    try:
        return get_case_workspace(db=db, case_id=case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@api_router.get(
    "/cases",
    response_model=CaseListResponse,
    status_code=status.HTTP_200_OK,
    summary="List investigation cases (paginated)",
    tags=["Investigation"],
)
def list_investigation_cases(
    limit: int = Query(20, ge=1, le=100, description="Maximum number of cases to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> CaseListResponse:
    """Retrieve a paginated list of investigation cases, ordered newest first."""
    return list_cases(db=db, limit=limit, offset=offset)


@api_router.get(
    "/cases/{case_id}/emails/{email_id}",
    response_model=EmailDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detailed investigation evidence for a specific email",
    tags=["Investigation"],
)
def get_email_investigation_detail(
    case_id: uuid.UUID,
    email_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> EmailDetailResponse:
    """Retrieve detailed forensic artifacts, threat intelligence, and AI analysis for an email."""
    try:
        return get_email_detail(db=db, case_id=case_id, email_id=email_id)
    except (CaseNotFoundError, EmailNotFoundError, EmailNotBelongToCaseError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@api_router.get(
    "/cases/{case_id}/evidence",
    response_model=EvidenceListResponse,
    status_code=status.HTTP_200_OK,
    summary="List chain-of-custody evidence records for an investigation case",
    tags=["Evidence & Audit"],
)
def list_case_evidence(
    case_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
) -> EvidenceListResponse:
    """Return paginated forensic evidence records (chain-of-custody) for a case.

    Ordered by collected_at ASC, then id ASC for deterministic pagination.
    Returns 404 if the case does not exist.
    """
    try:
        return get_case_evidence(db=db, case_id=case_id, limit=limit, offset=offset)
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@api_router.get(
    "/cases/{case_id}/events",
    response_model=EventListResponse,
    status_code=status.HTTP_200_OK,
    summary="List chronological audit-trail events for an investigation case",
    tags=["Evidence & Audit"],
)
def list_case_events(
    case_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
) -> EventListResponse:
    """Return paginated, sanitized investigation audit events for a case.

    Event metadata is filtered to an allowlist of safe keys; credentials,
    raw email content, and provider secrets are never returned.
    Ordered by created_at ASC, then id ASC.
    Returns 404 if the case does not exist.
    """
    try:
        return get_case_events(db=db, case_id=case_id, limit=limit, offset=offset)
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@api_router.get(
    "/cases/{case_id}/indicators",
    response_model=IndicatorListResponse,
    status_code=status.HTTP_200_OK,
    summary="List normalized forensic threat indicators for an investigation case",
    tags=["Evidence & Audit"],
)
def list_case_indicators(
    case_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
) -> IndicatorListResponse:
    """Return paginated forensic threat indicators for a case.

    Note: ThreatIndicator (internally derived forensic IoCs) is distinct from
    ThreatIntelligenceResult (external enrichments from VirusTotal/AbuseIPDB).
    Ordered by created_at ASC, then id ASC.
    Returns 404 if the case does not exist.
    """
    try:
        return get_case_indicators(db=db, case_id=case_id, limit=limit, offset=offset)
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@api_router.get(
    "/cases/{case_id}/report",
    response_model=CaseReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate a structured forensic report for an investigation case",
    tags=["Reports"],
)
def get_case_report(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> CaseReportResponse:
    """Generate a structured, deterministic forensic report for an investigation case.

    Assembles existing persisted PostgreSQL data across 7 sections:
    1. Case Information
    2. Executive Summary
    3. Emails and Forensic Artifacts
    4. Threat Intelligence (external enrichments)
    5. AI Findings
    6. Evidence / Chain-of-Custody
    7. Investigation Audit Events

    Read-only: strictly excludes raw email bodies, HTML, raw MIME, attachment binaries,
    TI raw_response, API keys, credentials, and secrets.
    Does not call AI providers, threat intel APIs, or blockchain nodes.
    Returns 404 if the case does not exist.
    """
    try:
        return generate_case_report(db=db, case_id=case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

