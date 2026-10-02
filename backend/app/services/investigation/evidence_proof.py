"""Phase 6A — Canonical Evidence Proof Generation for MAILSENTINEL.

Generates the deterministic canonical proof statement for chain-of-custody Evidence.
This canonical statement and its proof_sha256 hash represent the immutable integrity
commitment that is anchored to an external blockchain in downstream phases.

Separation of hashes:
- Evidence.sha256 identifies the underlying forensic artifact (e.g. raw EML file / attachment).
- proof_sha256 identifies the canonical evidence-integrity statement.
- Evidence.sha256 is NEVER modified or replaced by proof_sha256.

Canonical Payload Fields (Fixed by Architecture):
-------------------------------------------------
{
  "proof_version": "1.0",
  "evidence_id": "<Evidence.id>",
  "case_id": "<Evidence.case_id>",
  "evidence_type": "<Evidence.evidence_type>",
  "evidence_sha256": "<Evidence.sha256>",
  "collected_at": "<normalized UTC ISO-8601 timestamp>",
  "collected_by": "<Evidence.collected_by>"
}

Serialization rules:
- UTF-8 JSON
- Sorted keys
- Stable separators (',', ':') without insignificant whitespace
- Normalized UTC ISO-8601 timestamps
- Normalized lowercase hyphenated UUID strings
- Read-only: zero database writes, zero external calls
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence import Evidence

CANONICAL_PROOF_VERSION: str = "1.0"

CANONICAL_FIELD_SET: frozenset[str] = frozenset(
    {
        "proof_version",
        "evidence_id",
        "case_id",
        "evidence_type",
        "evidence_sha256",
        "collected_at",
        "collected_by",
    }
)


class EvidenceNotFoundError(Exception):
    """Raised when the requested Evidence record does not exist in the database."""


def normalize_timestamp(val: datetime | str) -> str:
    """Normalize a datetime object or ISO string to a canonical UTC ISO-8601 string.

    Rules:
    - If naive datetime, assumed to be in UTC.
    - If timezone-aware, converted to timezone.utc.
    - If string, parsed and converted to timezone.utc.
    - Formatted via dt.isoformat().
    """
    if isinstance(val, str):
        cleaned = val.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
    elif isinstance(val, datetime):
        dt = val
    else:
        raise ValueError(f"Invalid timestamp type '{type(val)}'; expected datetime or ISO string.")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    return dt.isoformat()


def normalize_uuid(val: uuid.UUID | str) -> str:
    """Normalize a UUID object or string to its canonical lowercase hyphenated string."""
    if isinstance(val, uuid.UUID):
        return str(val).lower()
    if isinstance(val, str):
        # Validate syntax and normalize
        return str(uuid.UUID(val.strip())).lower()
    raise ValueError(f"Invalid UUID value '{val}' of type '{type(val)}'.")


class CanonicalEvidenceProof(BaseModel):
    """Immutable result structure containing the canonical proof statement.

    Exposes canonical_payload, canonical_json, and proof_sha256.
    Supports both attribute access and dictionary subscription.
    """

    model_config = ConfigDict(from_attributes=True, frozen=True)

    evidence_id: str = Field(..., description="Canonical string UUID of Evidence.id")
    case_id: str = Field(..., description="Canonical string UUID of Evidence.case_id")
    canonical_payload: dict[str, Any] = Field(..., description="Exact 7-field canonical proof dictionary")
    canonical_json: str = Field(..., description="Deterministic UTF-8 canonical JSON string")
    proof_sha256: str = Field(..., description="Cryptographic SHA-256 hash of canonical_json UTF-8 bytes")

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


def build_canonical_payload(
    evidence_id: uuid.UUID | str,
    case_id: uuid.UUID | str,
    evidence_type: str,
    evidence_sha256: str,
    collected_at: datetime | str,
    collected_by: str | None,
    proof_version: str = CANONICAL_PROOF_VERSION,
) -> dict[str, Any]:
    """Build the exact 7-field canonical payload dictionary.

    Excludes all mutable, lifecycle, or sensitive fields (created_at, description,
    blockchain_tx_id, blockchain_verified, raw email, headers, attachments).
    """
    clean_ev_id = normalize_uuid(evidence_id)
    clean_case_id = normalize_uuid(case_id)
    clean_ev_type = str(evidence_type).strip()
    clean_sha256 = str(evidence_sha256).strip().lower()
    clean_collected_at = normalize_timestamp(collected_at)
    clean_collected_by = str(collected_by) if collected_by is not None else None

    payload: dict[str, Any] = {
        "proof_version": proof_version,
        "evidence_id": clean_ev_id,
        "case_id": clean_case_id,
        "evidence_type": clean_ev_type,
        "evidence_sha256": clean_sha256,
        "collected_at": clean_collected_at,
        "collected_by": clean_collected_by,
    }

    # Integrity assertion: ensure exactly the 7 canonical keys are present
    if frozenset(payload.keys()) != CANONICAL_FIELD_SET:
        raise ValueError(
            f"Canonical payload violation: expected fields {set(CANONICAL_FIELD_SET)}, got {set(payload.keys())}"
        )

    return payload


def serialize_canonical_json(payload: dict[str, Any]) -> str:
    """Serialize canonical payload deterministically as compact, key-sorted JSON string."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_canonical_proof_hash(canonical_json: str) -> str:
    """Compute the SHA-256 hex digest of the canonical JSON encoded as UTF-8 bytes."""
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest().lower()


def generate_canonical_evidence_proof(
    evidence: Any = None,
    *,
    evidence_id: uuid.UUID | str | None = None,
    case_id: uuid.UUID | str | None = None,
    evidence_type: str | None = None,
    evidence_sha256: str | None = None,
    collected_at: datetime | str | None = None,
    collected_by: str | None = None,
    proof_version: str = CANONICAL_PROOF_VERSION,
) -> CanonicalEvidenceProof:
    """Generate the canonical evidence proof statement and proof_sha256 hash.

    Can be called with:
    1. An Evidence model instance: `generate_canonical_evidence_proof(evidence_orm)`
    2. A dictionary with evidence fields
    3. Explicit keyword arguments

    Never modifies Evidence.sha256 or any database records.
    """
    # Extract values from evidence object/dict if provided
    if evidence is not None:
        if isinstance(evidence, dict):
            ev_id = evidence.get("evidence_id") or evidence.get("id") or evidence_id
            c_id = evidence.get("case_id") or case_id
            ev_type = evidence.get("evidence_type") or evidence_type
            ev_sha = evidence.get("evidence_sha256") or evidence.get("sha256") or evidence_sha256
            c_at = evidence.get("collected_at") or collected_at
            c_by = evidence.get("collected_by") if "collected_by" in evidence else collected_by
        else:
            # Model / object attributes
            ev_id = getattr(evidence, "id", None) or evidence_id
            c_id = getattr(evidence, "case_id", None) or case_id
            ev_type = getattr(evidence, "evidence_type", None) or evidence_type
            ev_sha = getattr(evidence, "sha256", None) or getattr(evidence, "evidence_sha256", None) or evidence_sha256
            c_at = getattr(evidence, "collected_at", None) or collected_at
            c_by = getattr(evidence, "collected_by", None) if collected_by is None else collected_by
    else:
        ev_id = evidence_id
        c_id = case_id
        ev_type = evidence_type
        ev_sha = evidence_sha256
        c_at = collected_at
        c_by = collected_by

    if ev_id is None or c_id is None or ev_type is None or ev_sha is None or c_at is None:
        raise ValueError(
            "Missing required canonical fields for evidence proof generation "
            f"(evidence_id={ev_id}, case_id={c_id}, evidence_type={ev_type}, "
            f"evidence_sha256={ev_sha}, collected_at={c_at})"
        )

    payload = build_canonical_payload(
        evidence_id=ev_id,
        case_id=c_id,
        evidence_type=ev_type,
        evidence_sha256=ev_sha,
        collected_at=c_at,
        collected_by=c_by,
        proof_version=proof_version,
    )

    canonical_json = serialize_canonical_json(payload)
    proof_sha256 = compute_canonical_proof_hash(canonical_json)

    return CanonicalEvidenceProof(
        evidence_id=normalize_uuid(ev_id),
        case_id=normalize_uuid(c_id),
        canonical_payload=payload,
        canonical_json=canonical_json,
        proof_sha256=proof_sha256,
    )


def generate_evidence_proof_for_id(db: Session, evidence_id: uuid.UUID) -> CanonicalEvidenceProof:
    """Fetch an Evidence row from PostgreSQL by UUID and compute its canonical proof.

    Read-only query: no database modifications performed.
    Raises EvidenceNotFoundError if no evidence row matches evidence_id.
    """
    evidence = db.execute(select(Evidence).where(Evidence.id == evidence_id)).scalar_one_or_none()
    if evidence is None:
        raise EvidenceNotFoundError(f"Evidence with ID '{evidence_id}' not found.")
    return generate_canonical_evidence_proof(evidence)


# Aliases for convenience
generate_canonical_proof = generate_canonical_evidence_proof
generate_evidence_proof = generate_canonical_evidence_proof
build_canonical_proof = generate_canonical_evidence_proof
