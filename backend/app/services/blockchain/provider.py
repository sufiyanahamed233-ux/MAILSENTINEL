"""Phase 6B — Blockchain Provider Abstraction for MAILSENTINEL.

Defines a provider-agnostic abstract interface (BlockchainProvider) and validation utilities
to anchor and verify canonical evidence proofs.

Rules:
- Methods are explicit about input/output types.
- Never accepts raw email body, HTML, raw MIME, or raw Evidence ORM objects.
- Operates on proof_sha256 and canonical proof statements, preserving strict distinction
  between Evidence.sha256, proof_sha256, and blockchain transaction ID.
- No database access, no FastAPI dependencies, no external network calls, no blockchain SDK.
- Unsupported or unconfigured behavior raises explicit domain exceptions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.services.blockchain.exceptions import (
    BlockchainProviderNotConfiguredError,
    BlockchainUnsupportedOperationError,
    InvalidProofPayloadError,
)
from app.services.blockchain.models import (
    AnchorResult,
    TransactionResult,
    VerificationResult,
)
from app.services.investigation.evidence_proof import CanonicalEvidenceProof

FORBIDDEN_RAW_KEYS = frozenset(
    {
        "body",
        "body_plain",
        "body_html",
        "raw_email",
        "raw_file",
        "raw_mime",
        "attachment_binary",
        "raw_response",
    }
)


def extract_proof_hash(proof: Any) -> str:
    """Extract and validate the proof_sha256 hash from a canonical proof object.

    Strictly rejects raw Evidence ORM objects and any payload containing raw email bodies or MIME.
    Preserves separation between Evidence.sha256 and proof_sha256.
    """
    if proof is None:
        raise InvalidProofPayloadError("Proof cannot be None.")

    # Guard: Reject raw Evidence ORM model instances
    if type(proof).__name__ == "Evidence" or (
        hasattr(proof, "__tablename__") and getattr(proof, "__tablename__") == "evidence"
    ):
        raise InvalidProofPayloadError(
            "Raw Evidence ORM objects cannot be passed directly to the blockchain provider; "
            "provide a CanonicalEvidenceProof from Phase 6A."
        )

    # Guard: Reject dictionaries containing raw email content
    if isinstance(proof, dict):
        found_forbidden = FORBIDDEN_RAW_KEYS.intersection(proof.keys())
        if found_forbidden:
            raise InvalidProofPayloadError(
                f"Raw email/MIME content ({sorted(found_forbidden)}) must never be passed to the blockchain provider."
            )
        if "proof_sha256" in proof:
            hash_val = str(proof["proof_sha256"]).strip().lower()
        elif "sha256" in proof:
            raise InvalidProofPayloadError(
                "Evidence.sha256 is an artifact hash, not proof_sha256. "
                "Must provide a canonical proof statement containing 'proof_sha256'."
            )
        else:
            raise InvalidProofPayloadError("Missing required 'proof_sha256' in proof payload dictionary.")
        return _validate_hash_format(hash_val)

    # Check for CanonicalEvidenceProof or duck-typed proof object
    if isinstance(proof, CanonicalEvidenceProof) or hasattr(proof, "proof_sha256"):
        for attr in FORBIDDEN_RAW_KEYS:
            if getattr(proof, attr, None) is not None:
                raise InvalidProofPayloadError(
                    f"Forbidden attribute '{attr}' present on proof object; raw content must not be passed."
                )
        return _validate_hash_format(str(proof.proof_sha256).strip().lower())

    # Direct 64-char hex string
    if isinstance(proof, str):
        return _validate_hash_format(proof.strip().lower())

    raise InvalidProofPayloadError(
        f"Unsupported proof type '{type(proof).__name__}'. Expected CanonicalEvidenceProof or 64-char hex hash."
    )


def _validate_hash_format(h: str) -> str:
    if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
        raise InvalidProofPayloadError(f"proof_sha256 must be a 64-character lowercase hex string, got '{h}'.")
    return h


class BlockchainProvider(ABC):
    """Abstract, provider-agnostic interface for anchoring and verifying evidence proofs.

    Designed to be implemented by future Ethereum, Polygon, or other decentralized network providers.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the blockchain provider implementation (e.g. 'infura', 'alchemy', 'stub')."""

    @property
    @abstractmethod
    def network_name(self) -> str:
        """Name of the blockchain network (e.g. 'ethereum-mainnet', 'ethereum-sepolia')."""

    @abstractmethod
    def anchor_evidence(self, proof: CanonicalEvidenceProof) -> AnchorResult:
        """Anchor a canonical evidence proof onto the blockchain.

        Args:
            proof: Canonical evidence proof statement.

        Returns:
            AnchorResult containing transaction_id, proof_sha256, network, provider, timestamp, status.

        Raises:
            InvalidProofPayloadError: If proof contains forbidden raw email content or invalid format.
            BlockchainAnchorError: If the transaction submission fails.
            BlockchainProviderNotConfiguredError: If the provider is unconfigured.
        """

    @abstractmethod
    def verify_evidence(
        self,
        proof: CanonicalEvidenceProof,
        transaction_id: str | None = None,
    ) -> VerificationResult:
        """Verify that a canonical evidence proof exists and matches on-chain state.

        Args:
            proof: Canonical evidence proof to verify.
            transaction_id: Optional transaction ID where the proof was anchored.

        Returns:
            VerificationResult indicating whether the proof is verified on-chain.

        Raises:
            InvalidProofPayloadError: If proof is invalid.
            BlockchainVerificationError: If verification cannot be executed.
            BlockchainTransactionNotFoundError: If the transaction does not exist.
        """

    @abstractmethod
    def get_transaction(self, transaction_id: str) -> TransactionResult:
        """Query a transaction and its anchored proof from the blockchain network.

        Args:
            transaction_id: Unique blockchain transaction identifier.

        Returns:
            TransactionResult with status, network, provider, and optional extracted proof_sha256.

        Raises:
            BlockchainTransactionNotFoundError: If the transaction is not found.
            BlockchainNetworkError: If the network request fails.
        """


class UnconfiguredBlockchainProvider(BlockchainProvider):
    """Default provider used when no active blockchain provider is configured in environment.

    Raises BlockchainProviderNotConfiguredError on all operations rather than pretending success.
    """

    def __init__(self, provider_name: str = "unconfigured", network_name: str = "none") -> None:
        self._provider_name = provider_name
        self._network_name = network_name

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def network_name(self) -> str:
        return self._network_name

    def anchor_evidence(self, proof: CanonicalEvidenceProof) -> AnchorResult:
        if not isinstance(proof, CanonicalEvidenceProof):
            raise InvalidProofPayloadError(
                f"anchor_evidence requires a CanonicalEvidenceProof instance, got '{type(proof).__name__}'."
            )
        extract_proof_hash(proof)
        raise BlockchainProviderNotConfiguredError(
            f"Blockchain provider '{self.provider_name}' is not configured. "
            "Cannot anchor evidence proof to a blockchain network."
        )

    def verify_evidence(
        self,
        proof: CanonicalEvidenceProof,
        transaction_id: str | None = None,
    ) -> VerificationResult:
        if not isinstance(proof, CanonicalEvidenceProof):
            raise InvalidProofPayloadError(
                f"verify_evidence requires a CanonicalEvidenceProof instance, got '{type(proof).__name__}'."
            )
        extract_proof_hash(proof)
        raise BlockchainProviderNotConfiguredError(
            f"Blockchain provider '{self.provider_name}' is not configured. "
            "Cannot verify evidence proof on a blockchain network."
        )

    def get_transaction(self, transaction_id: str) -> TransactionResult:
        if not transaction_id or not transaction_id.strip():
            raise ValueError("transaction_id must not be empty.")
        raise BlockchainProviderNotConfiguredError(
            f"Blockchain provider '{self.provider_name}' is not configured. "
            "Cannot retrieve transaction from a blockchain network."
        )


def get_blockchain_provider(provider_name: str | None = None) -> BlockchainProvider:
    """Factory to retrieve a configured blockchain provider."""
    from app.core.config import settings

    target_provider = provider_name
    if not target_provider:
        if settings.BLOCKCHAIN_RPC_URL:
            target_provider = "ethereum"
        else:
            return UnconfiguredBlockchainProvider()

    clean_name = target_provider.strip().lower()
    if clean_name in ("none", "unconfigured", "disabled"):
        return UnconfiguredBlockchainProvider()

    if clean_name in ("ethereum", "sepolia", "ethereum-sepolia", "eth"):
        from app.services.blockchain.ethereum import EthereumBlockchainProvider

        provider = EthereumBlockchainProvider()
        if not provider.rpc_url:
            raise BlockchainProviderNotConfiguredError(
                f"Blockchain provider '{provider_name}' is not configured (missing BLOCKCHAIN_RPC_URL)."
            )
        return provider

    raise BlockchainProviderNotConfiguredError(
        f"Blockchain provider '{provider_name}' is not supported or not configured."
    )

