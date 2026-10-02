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
    "InvalidProofPayloadError",
    "TransactionResult",
    "UnconfiguredBlockchainProvider",
    "VerificationResult",
    "extract_proof_hash",
    "get_blockchain_provider",
]

