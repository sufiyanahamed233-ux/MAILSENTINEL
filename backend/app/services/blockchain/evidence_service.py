"""Phase 6D — Evidence ↔ Blockchain Integration Service for MAILSENTINEL.

Connects the Evidence ORM model, canonical proof generation service,
and BlockchainProvider to anchor and verify persisted forensic evidence.

Architecture Rules:
- Abstract provider selection via get_blockchain_provider().
- Transactional database operations: commit on success, rollback on failure.
- Never mutates Evidence.sha256.
- Never puts raw email content, MIME, attachments, or secrets on-chain.
- Preserves separation between Evidence.sha256, proof_sha256, and blockchain_tx_id.
- Returns concise structured responses without secrets.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.evidence import Evidence
from app.services.blockchain.exceptions import (
    BlockchainAnchorError,
    BlockchainError,
    BlockchainNetworkError,
    BlockchainProviderNotConfiguredError,
    BlockchainTransactionNotFoundError,
    BlockchainUnsupportedOperationError,
    BlockchainVerificationError,
    InvalidProofPayloadError,
)
from app.services.blockchain.provider import BlockchainProvider, get_blockchain_provider
from app.services.investigation.evidence_proof import (
    CanonicalEvidenceProof,
    EvidenceNotFoundError,
    generate_canonical_evidence_proof,
)
from app.services.investigation.service import CaseNotFoundError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain Exceptions
# ---------------------------------------------------------------------------


class EvidenceNotBelongToCaseError(BlockchainError):
    """Raised when an evidence record does not belong to the specified case."""


class EvidenceAlreadyAnchoredError(BlockchainError):
    """Raised when evidence is already anchored with an existing blockchain_tx_id."""


class EvidenceNotAnchoredError(BlockchainError):
    """Raised when verifying evidence that has not yet been anchored to a blockchain."""


# ---------------------------------------------------------------------------
# Response Model
# ---------------------------------------------------------------------------


class EvidenceBlockchainResponse(BaseModel):
    """Structured response for evidence anchoring and verification operations."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    evidence_id: uuid.UUID = Field(..., description="Unique evidence record identifier")
    case_id: uuid.UUID = Field(..., description="Associated case identifier")
    proof_sha256: str = Field(..., description="SHA-256 hash of the canonical evidence proof")
    transaction_id: str = Field(..., description="Blockchain transaction identifier")
    network: str = Field(..., description="Target blockchain network name")
    provider: str = Field(..., description="Blockchain provider implementation name")
    status: str = Field(..., description="Status of the blockchain operation")
    blockchain_verified: bool = Field(..., description="Whether evidence integrity is verified on-chain")


# ---------------------------------------------------------------------------
# Helper: Ensure UUID
# ---------------------------------------------------------------------------


def _coerce_uuid(val: uuid.UUID | str) -> uuid.UUID:
    """Coerce string or UUID to uuid.UUID."""
    if isinstance(val, uuid.UUID):
        return val
    return uuid.UUID(str(val))


# ---------------------------------------------------------------------------
# Service Functions
# ---------------------------------------------------------------------------


def anchor_evidence_to_blockchain(
    db: Session,
    case_id: uuid.UUID | str,
    evidence_id: uuid.UUID | str,
    provider: BlockchainProvider | None = None,
) -> EvidenceBlockchainResponse:
    """Anchor a persisted evidence record onto the configured blockchain.

    Flow:
    1. Load Case and Evidence from database; verify relationship.
    2. Check that evidence has not already been anchored.
    3. Generate canonical evidence proof statement.
    4. Anchor proof via get_blockchain_provider().
    5. Persist returned transaction_id to Evidence.blockchain_tx_id.
    6. Ensure blockchain_verified remains False until explicit verification.
    7. Commit transaction on success; rollback on failure.

    Args:
        db: Active SQLAlchemy database session.
        case_id: UUID of the investigation case.
        evidence_id: UUID of the evidence record to anchor.
        provider: Optional explicit BlockchainProvider override (defaults to get_blockchain_provider()).

    Returns:
        EvidenceBlockchainResponse containing anchor details.

    Raises:
        CaseNotFoundError: If case_id does not exist.
        EvidenceNotFoundError: If evidence_id does not exist.
        EvidenceNotBelongToCaseError: If evidence does not belong to case_id.
        EvidenceAlreadyAnchoredError: If evidence already has a blockchain_tx_id.
        BlockchainProviderNotConfiguredError: If the provider is unconfigured.
        BlockchainAnchorError: If anchoring fails on-chain.
        BlockchainError: On general blockchain provider errors.
    """
    c_id = _coerce_uuid(case_id)
    e_id = _coerce_uuid(evidence_id)

    # 1. Load and validate Case
    case = db.execute(select(Case).where(Case.id == c_id)).scalar_one_or_none()
    if case is None:
        raise CaseNotFoundError(f"Case with ID '{c_id}' not found.")

    # 2. Load and validate Evidence
    evidence = db.execute(select(Evidence).where(Evidence.id == e_id)).scalar_one_or_none()
    if evidence is None:
        raise EvidenceNotFoundError(f"Evidence with ID '{e_id}' not found.")

    # 3. Verify evidence belongs to case
    if evidence.case_id != c_id:
        raise EvidenceNotBelongToCaseError(
            f"Evidence with ID '{e_id}' does not belong to case '{c_id}'."
        )

    # 4. Duplicate anchor protection
    if evidence.blockchain_tx_id:
        raise EvidenceAlreadyAnchoredError(
            f"Evidence with ID '{e_id}' is already anchored with transaction '{evidence.blockchain_tx_id}'."
        )

    # 5. Generate canonical evidence proof statement
    proof: CanonicalEvidenceProof = generate_canonical_evidence_proof(evidence)

    # 6. Retrieve blockchain provider
    active_provider = provider if provider is not None else get_blockchain_provider()

    # 7. Anchor proof and persist transactionally
    try:
        anchor_result = active_provider.anchor_evidence(proof)
        evidence.blockchain_tx_id = anchor_result.transaction_id
        evidence.blockchain_verified = False  # Requirement 9: remains False until explicit verification
        db.commit()
        db.refresh(evidence)
    except Exception:
        db.rollback()
        raise

    logger.info(
        "Successfully anchored evidence %s to blockchain (tx: %s, network: %s)",
        e_id,
        anchor_result.transaction_id,
        anchor_result.network,
    )

    return EvidenceBlockchainResponse(
        evidence_id=evidence.id,
        case_id=evidence.case_id,
        proof_sha256=proof.proof_sha256,
        transaction_id=anchor_result.transaction_id,
        network=anchor_result.network,
        provider=anchor_result.provider,
        status=anchor_result.status,
        blockchain_verified=evidence.blockchain_verified,
    )


def verify_evidence_on_blockchain(
    db: Session,
    case_id: uuid.UUID | str,
    evidence_id: uuid.UUID | str,
    provider: BlockchainProvider | None = None,
) -> EvidenceBlockchainResponse:
    """Verify a persisted evidence record against on-chain records.

    Flow:
    1. Load Case and Evidence from database; verify relationship.
    2. Ensure evidence has an existing blockchain_tx_id.
    3. Regenerate canonical evidence proof from the current Evidence record.
    4. Call provider.verify_evidence() using stored blockchain_tx_id.
    5. Update Evidence.blockchain_verified from verification result.
    6. Persist verification result safely; rollback on failure.

    Args:
        db: Active SQLAlchemy database session.
        case_id: UUID of the investigation case.
        evidence_id: UUID of the evidence record to verify.
        provider: Optional explicit BlockchainProvider override (defaults to get_blockchain_provider()).

    Returns:
        EvidenceBlockchainResponse containing verification details.

    Raises:
        CaseNotFoundError: If case_id does not exist.
        EvidenceNotFoundError: If evidence_id does not exist.
        EvidenceNotBelongToCaseError: If evidence does not belong to case_id.
        EvidenceNotAnchoredError: If evidence has not been anchored (no blockchain_tx_id).
        BlockchainProviderNotConfiguredError: If the provider is unconfigured.
        BlockchainVerificationError: If verification cannot be executed.
        BlockchainTransactionNotFoundError: If the anchored transaction is not found.
        BlockchainError: On general blockchain provider errors.
    """
    c_id = _coerce_uuid(case_id)
    e_id = _coerce_uuid(evidence_id)

    # 1. Load and validate Case
    case = db.execute(select(Case).where(Case.id == c_id)).scalar_one_or_none()
    if case is None:
        raise CaseNotFoundError(f"Case with ID '{c_id}' not found.")

    # 2. Load and validate Evidence
    evidence = db.execute(select(Evidence).where(Evidence.id == e_id)).scalar_one_or_none()
    if evidence is None:
        raise EvidenceNotFoundError(f"Evidence with ID '{e_id}' not found.")

    # 3. Verify evidence belongs to case
    if evidence.case_id != c_id:
        raise EvidenceNotBelongToCaseError(
            f"Evidence with ID '{e_id}' does not belong to case '{c_id}'."
        )

    # 4. Missing transaction ID protection
    if not evidence.blockchain_tx_id or not evidence.blockchain_tx_id.strip():
        raise EvidenceNotAnchoredError(
            f"Evidence with ID '{e_id}' has not been anchored to the blockchain yet (missing blockchain_tx_id)."
        )

    tx_id = evidence.blockchain_tx_id.strip()

    # 5. Regenerate canonical evidence proof from current Evidence record
    proof: CanonicalEvidenceProof = generate_canonical_evidence_proof(evidence)

    # 6. Retrieve blockchain provider
    active_provider = provider if provider is not None else get_blockchain_provider()

    # 7. Call provider.verify_evidence() and update blockchain_verified safely
    try:
        verification_result = active_provider.verify_evidence(
            proof,
            transaction_id=tx_id,
        )
        evidence.blockchain_verified = bool(verification_result.verified)
        db.commit()
        db.refresh(evidence)
    except Exception:
        db.rollback()
        raise

    logger.info(
        "Verification for evidence %s completed: verified=%s, status=%s",
        e_id,
        evidence.blockchain_verified,
        verification_result.status,
    )

    return EvidenceBlockchainResponse(
        evidence_id=evidence.id,
        case_id=evidence.case_id,
        proof_sha256=proof.proof_sha256,
        transaction_id=evidence.blockchain_tx_id,
        network=verification_result.network,
        provider=verification_result.provider,
        status=verification_result.status,
        blockchain_verified=evidence.blockchain_verified,
    )
