"""Phase 6B — Blockchain Provider Exceptions for MAILSENTINEL.

Defines a clean, domain-specific exception hierarchy for the blockchain provider abstraction.
No FastAPI dependencies, no blockchain SDK dependencies.
"""

from __future__ import annotations


class BlockchainError(Exception):
    """Base exception for all blockchain provider operations."""


class BlockchainProviderNotConfiguredError(BlockchainError):
    """Raised when a requested blockchain provider is not configured or disabled."""


class BlockchainUnsupportedOperationError(BlockchainError):
    """Raised when an operation is unsupported by the provider or target network."""


class BlockchainNetworkError(BlockchainError):
    """Raised when an RPC or transport-level network communication failure occurs."""


class BlockchainTransactionNotFoundError(BlockchainError):
    """Raised when a transaction ID cannot be found on the target blockchain network."""


class BlockchainVerificationError(BlockchainError):
    """Raised when cryptographic verification cannot be completed or fails."""


class BlockchainAnchorError(BlockchainError):
    """Raised when anchoring evidence proof to the blockchain fails."""


class InvalidProofPayloadError(BlockchainError, TypeError):
    """Raised when an invalid proof payload (or forbidden raw evidence/email) is provided."""
