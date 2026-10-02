"""Blockchain services package for MAILSENTINEL."""

from app.services.blockchain.ethereum import EthereumBlockchainProvider
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
from app.services.blockchain.evidence_service import (
    EvidenceAlreadyAnchoredError,
    EvidenceBlockchainResponse,
    EvidenceNotAnchoredError,
    EvidenceNotBelongToCaseError,
    anchor_evidence_to_blockchain,
    verify_evidence_on_blockchain,
)
from app.services.blockchain.models import (
    AnchorResult,
    TransactionResult,
    VerificationResult,
)
from app.services.blockchain.provider import (
    BlockchainProvider,
    UnconfiguredBlockchainProvider,
    extract_proof_hash,
    get_blockchain_provider,
)

__all__ = [
    "AnchorResult",
    "BlockchainAnchorError",
    "BlockchainError",
    "BlockchainNetworkError",
    "BlockchainProvider",
    "BlockchainProviderNotConfiguredError",
    "BlockchainTransactionNotFoundError",
    "BlockchainUnsupportedOperationError",
    "BlockchainVerificationError",
    "EthereumBlockchainProvider",
    "EvidenceAlreadyAnchoredError",
    "EvidenceBlockchainResponse",
    "EvidenceNotAnchoredError",
    "EvidenceNotBelongToCaseError",
    "InvalidProofPayloadError",
    "TransactionResult",
    "UnconfiguredBlockchainProvider",
    "VerificationResult",
    "anchor_evidence_to_blockchain",
    "extract_proof_hash",
    "get_blockchain_provider",
    "verify_evidence_on_blockchain",
]

