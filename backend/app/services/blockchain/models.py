"""Phase 6B — Blockchain Provider Response Models for MAILSENTINEL.

Defines Pydantic v2 models for:
- AnchorResult: Return value of anchor_evidence(proof)
- VerificationResult: Return value of verify_evidence(proof)
- TransactionResult: Return value of get_transaction(transaction_id)

Architecture rules:
- Provider-agnostic.
- Explicit typing.
- Preserves distinction between Evidence.sha256, proof_sha256, and transaction_id.
- No database or FastAPI dependencies.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_sha256_hex(val: str, field_name: str) -> str:
    cleaned = val.strip().lower()
    if len(cleaned) != 64 or not all(c in "0123456789abcdef" for c in cleaned):
        raise ValueError(f"{field_name} must be a 64-character hex string")
    return cleaned


class AnchorResult(BaseModel):
    """Result of anchoring a canonical evidence proof onto a blockchain."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    transaction_id: str = Field(..., description="Unique blockchain transaction identifier (e.g. tx hash)")
    proof_sha256: str = Field(..., description="SHA-256 hash of the canonical evidence proof statement")
    network: str = Field(..., description="Target blockchain network (e.g. 'ethereum-sepolia', 'polygon-amoy')")
    provider: str = Field(..., description="Blockchain provider implementation name (e.g. 'infura', 'alchemy')")
    anchored_at: datetime = Field(..., description="Timestamp when the anchoring transaction was committed")
    status: str = Field(..., description="Status of the anchoring operation (e.g. 'confirmed', 'pending')")

    @field_validator("transaction_id")
    @classmethod
    def validate_tx_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("transaction_id must not be empty")
        return v.strip()

    @field_validator("proof_sha256")
    @classmethod
    def validate_proof_hash(cls, v: str) -> str:
        return _validate_sha256_hex(v, "proof_sha256")


class VerificationResult(BaseModel):
    """Result of verifying a canonical evidence proof against on-chain records."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    transaction_id: str = Field(..., description="Blockchain transaction ID containing the anchor record")
    proof_sha256: str = Field(..., description="SHA-256 hash of the canonical evidence proof statement")
    verified: bool = Field(..., description="Whether the proof_sha256 matches the on-chain anchor")
    network: str = Field(..., description="Blockchain network queried")
    provider: str = Field(..., description="Blockchain provider implementation name")
    verified_at: datetime = Field(..., description="Timestamp when verification was performed")
    status: str = Field(..., description="Status of the verification (e.g. 'verified', 'mismatched', 'not_found')")

    @field_validator("transaction_id")
    @classmethod
    def validate_tx_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("transaction_id must not be empty")
        return v.strip()

    @field_validator("proof_sha256")
    @classmethod
    def validate_proof_hash(cls, v: str) -> str:
        return _validate_sha256_hex(v, "proof_sha256")


class TransactionResult(BaseModel):
    """Result of querying a transaction from the blockchain."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    transaction_id: str = Field(..., description="Unique blockchain transaction identifier")
    proof_sha256: str | None = Field(None, description="SHA-256 proof hash extracted from tx data, if available")
    network: str = Field(..., description="Blockchain network where transaction was recorded")
    provider: str = Field(..., description="Blockchain provider implementation name")
    status: str = Field(..., description="Transaction execution status (e.g. 'success', 'pending', 'failed')")
    timestamp: datetime | None = Field(None, description="Block timestamp when transaction was mined, if available")

    @field_validator("transaction_id")
    @classmethod
    def validate_tx_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("transaction_id must not be empty")
        return v.strip()

    @field_validator("proof_sha256")
    @classmethod
    def validate_optional_proof_hash(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_sha256_hex(v, "proof_sha256")
