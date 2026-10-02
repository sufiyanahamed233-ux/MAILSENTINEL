"""Phase 6B — Tests for Blockchain Provider Abstraction in MAILSENTINEL.

Tests cover:
1.  Interface contract (BlockchainProvider abstract base class enforcement)
2.  Model validation — AnchorResult valid
3.  Model validation — VerificationResult valid
4.  Model validation — TransactionResult valid (including nullable fields)
5.  Model validation — Invalid and missing required fields
6.  Exception hierarchy (all inherit from BlockchainError)
7.  Unsupported / unconfigured provider behavior raises clear exceptions (no fake success)
8.  No database access from provider abstraction
9.  No network calls from provider abstraction
10. Strict rejection of raw email content, MIME, or raw Evidence ORM objects
11. Preservation of distinction: Evidence.sha256 vs proof_sha256 vs transaction_id
12. Concrete provider implementation conforming to interface contract
"""

from __future__ import annotations

import socket
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.models.evidence import Evidence
from app.services.blockchain import (
    AnchorResult,
    BlockchainAnchorError,
    BlockchainError,
    BlockchainNetworkError,
    BlockchainProvider,
    BlockchainProviderNotConfiguredError,
    BlockchainTransactionNotFoundError,
    BlockchainUnsupportedOperationError,
    BlockchainVerificationError,
    InvalidProofPayloadError,
    TransactionResult,
    UnconfiguredBlockchainProvider,
    VerificationResult,
    extract_proof_hash,
    get_blockchain_provider,
)
from app.services.investigation.evidence_proof import (
    CanonicalEvidenceProof,
    generate_canonical_evidence_proof,
)


# Helper: Valid 64-character lowercase SHA-256 hash
VALID_HASH_A = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
VALID_HASH_B = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
VALID_TX_ID = "0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"


def _make_sample_proof() -> CanonicalEvidenceProof:
    """Helper creating a valid CanonicalEvidenceProof from Phase 6A."""
    return generate_canonical_evidence_proof(
        evidence_id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        evidence_type="email_rfc822",
        evidence_sha256=VALID_HASH_A,
        collected_at=datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
        collected_by="investigator_alice",
    )


# ===========================================================================
# 1. Interface contract
# ===========================================================================

def test_01_interface_contract_cannot_instantiate_abstract_class():
    """1. BlockchainProvider is an abstract base class and cannot be directly instantiated."""
    with pytest.raises(TypeError) as exc_info:
        BlockchainProvider()  # type: ignore[abstract]
    assert "Can't instantiate abstract class BlockchainProvider" in str(exc_info.value)


def test_01b_subclass_must_implement_all_abstract_methods():
    """1b. Incomplete subclass raises TypeError on instantiation."""

    class IncompleteProvider(BlockchainProvider):
        @property
        def provider_name(self) -> str:
            return "incomplete"

    with pytest.raises(TypeError) as exc_info:
        IncompleteProvider()  # type: ignore[abstract]
    assert "without an implementation for abstract method" in str(exc_info.value)


# ===========================================================================
# 2. Model validation — AnchorResult valid
# ===========================================================================

def test_02_valid_anchor_result():
    """2. AnchorResult instantiates cleanly with valid parameters and is immutable."""
    now = datetime.now(timezone.utc)
    res = AnchorResult(
        transaction_id=VALID_TX_ID,
        proof_sha256=VALID_HASH_B,
        network="ethereum-sepolia",
        provider="infura",
        anchored_at=now,
        status="confirmed",
    )

    assert res.transaction_id == VALID_TX_ID
    assert res.proof_sha256 == VALID_HASH_B
    assert res.network == "ethereum-sepolia"
    assert res.provider == "infura"
    assert res.anchored_at == now
    assert res.status == "confirmed"

    # Frozen / immutable check
    with pytest.raises(ValidationError):
        res.status = "reverted"  # type: ignore[misc]

    # JSON serialization
    dumped = res.model_dump()
    assert dumped["transaction_id"] == VALID_TX_ID
    assert dumped["proof_sha256"] == VALID_HASH_B


# ===========================================================================
# 3. Model validation — VerificationResult valid
# ===========================================================================

def test_03_valid_verification_result():
    """3. VerificationResult instantiates cleanly with verified=True and verified=False."""
    now = datetime.now(timezone.utc)
    res_verified = VerificationResult(
        transaction_id=VALID_TX_ID,
        proof_sha256=VALID_HASH_A,
        verified=True,
        network="polygon-amoy",
        provider="alchemy",
        verified_at=now,
        status="verified",
    )
    assert res_verified.verified is True
    assert res_verified.status == "verified"

    res_unverified = VerificationResult(
        transaction_id=VALID_TX_ID,
        proof_sha256=VALID_HASH_A,
        verified=False,
        network="polygon-amoy",
        provider="alchemy",
        verified_at=now,
        status="mismatched",
    )
    assert res_unverified.verified is False
    assert res_unverified.status == "mismatched"


# ===========================================================================
# 4. Model validation — TransactionResult valid (including nullables)
# ===========================================================================

def test_04_valid_transaction_result():
    """4. TransactionResult supports both full details and nullable proof_sha256/timestamp."""
    now = datetime.now(timezone.utc)
    # Full transaction
    tx_full = TransactionResult(
        transaction_id=VALID_TX_ID,
        proof_sha256=VALID_HASH_B,
        network="ethereum-mainnet",
        provider="quicknode",
        status="success",
        timestamp=now,
    )
    assert tx_full.transaction_id == VALID_TX_ID
    assert tx_full.proof_sha256 == VALID_HASH_B
    assert tx_full.timestamp == now

    # Pending transaction without extracted proof or timestamp
    tx_pending = TransactionResult(
        transaction_id="0x9999",
        proof_sha256=None,
        network="ethereum-sepolia",
        provider="quicknode",
        status="pending",
        timestamp=None,
    )
    assert tx_pending.proof_sha256 is None
    assert tx_pending.timestamp is None
    assert tx_pending.status == "pending"


# ===========================================================================
# 5. Model validation — Invalid and missing required fields
# ===========================================================================

def test_05_model_validation_failures():
    """5. Pydantic v2 rejects empty transaction_id, missing fields, or malformed proof hashes."""
    now = datetime.now(timezone.utc)

    # Missing required field
    with pytest.raises(ValidationError):
        AnchorResult(
            transaction_id=VALID_TX_ID,
            proof_sha256=VALID_HASH_A,
            network="ethereum",
            # provider is missing
            anchored_at=now,
            status="confirmed",
        )  # type: ignore[call-arg]

    # Empty transaction_id
    with pytest.raises(ValidationError):
        AnchorResult(
            transaction_id="   ",
            proof_sha256=VALID_HASH_A,
            network="ethereum",
            provider="infura",
            anchored_at=now,
            status="confirmed",
        )

    # Malformed proof_sha256 (not 64 characters)
    with pytest.raises(ValidationError):
        AnchorResult(
            transaction_id=VALID_TX_ID,
            proof_sha256="tooshort",
            network="ethereum",
            provider="infura",
            anchored_at=now,
            status="confirmed",
        )

    # Malformed proof_sha256 (non-hex characters)
    with pytest.raises(ValidationError):
        VerificationResult(
            transaction_id=VALID_TX_ID,
            proof_sha256="z" * 64,
            verified=True,
            network="ethereum",
            provider="infura",
            verified_at=now,
            status="verified",
        )


# ===========================================================================
# 6. Exception hierarchy
# ===========================================================================

def test_06_exception_hierarchy():
    """6. All domain-specific blockchain exceptions inherit from BlockchainError."""
    exceptions = [
        BlockchainProviderNotConfiguredError("Not configured"),
        BlockchainUnsupportedOperationError("Unsupported"),
        BlockchainNetworkError("Network down"),
        BlockchainTransactionNotFoundError("Tx missing"),
        BlockchainVerificationError("Verify failed"),
        BlockchainAnchorError("Anchor failed"),
        InvalidProofPayloadError("Invalid payload"),
    ]

    for exc in exceptions:
        assert isinstance(exc, BlockchainError)
        assert isinstance(exc, Exception)

    # InvalidProofPayloadError is also a TypeError for semantic compatibility
    assert isinstance(InvalidProofPayloadError("Bad payload"), TypeError)


# ===========================================================================
# 7. Unsupported / unconfigured provider behavior (no fake success)
# ===========================================================================

def test_07_unconfigured_provider_behavior():
    """7. Unconfigured provider raises BlockchainProviderNotConfiguredError on all operations."""
    provider = UnconfiguredBlockchainProvider()
    proof = _make_sample_proof()

    # Anchor evidence raises
    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_anchor:
        provider.anchor_evidence(proof)
    assert "not configured" in str(exc_anchor.value).lower()

    # Verify evidence raises
    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_verify:
        provider.verify_evidence(proof, transaction_id=VALID_TX_ID)
    assert "not configured" in str(exc_verify.value).lower()

    # Get transaction raises
    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_get:
        provider.get_transaction(VALID_TX_ID)
    assert "not configured" in str(exc_get.value).lower()

    # Factory tests
    assert isinstance(get_blockchain_provider(None), UnconfiguredBlockchainProvider)
    assert isinstance(get_blockchain_provider("unconfigured"), UnconfiguredBlockchainProvider)
    with pytest.raises(BlockchainProviderNotConfiguredError):
        get_blockchain_provider("ethereum-sepolia")


# ===========================================================================
# 8. No database access from provider abstraction
# ===========================================================================

def test_08_no_database_access():
    """8. Provider abstraction modules never import or access SQLAlchemy or database sessions."""
    # Ensure blockchain provider module does not import db sessions
    import app.services.blockchain.exceptions as exc_mod
    import app.services.blockchain.models as models_mod
    import app.services.blockchain.provider as provider_mod

    for mod in (exc_mod, models_mod, provider_mod):
        mod_dict = mod.__dict__
        assert "Session" not in mod_dict
        assert "get_db" not in mod_dict
        assert "SessionLocal" not in mod_dict


# ===========================================================================
# 9. No network calls from provider abstraction
# ===========================================================================

def test_09_no_network_calls():
    """9. Instantiating or validating provider and models performs zero network/socket calls."""
    proof = _make_sample_proof()
    provider = UnconfiguredBlockchainProvider()

    # Mock socket.connect to catch any unexpected network traffic
    with patch.object(socket.socket, "connect", side_effect=RuntimeError("Unexpected network call")):
        # These should purely perform local validation and raise domain errors without sockets
        with pytest.raises(BlockchainProviderNotConfiguredError):
            provider.anchor_evidence(proof)

        with pytest.raises(BlockchainProviderNotConfiguredError):
            provider.verify_evidence(proof)


# ===========================================================================
# 10. Rejection of raw email content, MIME, or raw Evidence ORM objects
# ===========================================================================

def test_10_rejection_of_raw_email_or_evidence_orm():
    """10. Provider extraction strictly rejects raw Evidence ORM objects and payloads with raw email bodies."""
    # 1. Reject raw Evidence ORM model instance
    raw_evidence = Evidence(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        evidence_type="email_rfc822",
        sha256=VALID_HASH_A,
    )
    with pytest.raises(InvalidProofPayloadError) as exc_orm:
        extract_proof_hash(raw_evidence)
    assert "Raw Evidence ORM objects cannot be passed directly" in str(exc_orm.value)

    # 2. Reject dictionary containing raw email fields
    forbidden_payloads = [
        {"proof_sha256": VALID_HASH_A, "body": "Confidential email body"},
        {"proof_sha256": VALID_HASH_A, "body_plain": "Plain text body"},
        {"proof_sha256": VALID_HASH_A, "body_html": "<p>HTML body</p>"},
        {"proof_sha256": VALID_HASH_A, "raw_email": b"From: alice@test.com"},
        {"proof_sha256": VALID_HASH_A, "raw_mime": "Content-Type: message/rfc822"},
        {"proof_sha256": VALID_HASH_A, "attachment_binary": b"\x00\x01\x02"},
        {"proof_sha256": VALID_HASH_A, "raw_response": {"token": "secret"}},
    ]
    for p in forbidden_payloads:
        with pytest.raises(InvalidProofPayloadError) as exc_forbidden:
            extract_proof_hash(p)
        assert "Raw email/MIME content" in str(exc_forbidden.value)


# ===========================================================================
# 11. Distinction: Evidence.sha256 vs proof_sha256 vs transaction_id
# ===========================================================================

def test_11_distinction_between_hashes_and_transaction_id():
    """11. Preserves clear distinction between Evidence.sha256, proof_sha256, and transaction_id."""
    evidence_artifact_hash = "1111111111111111111111111111111111111111111111111111111111111111"
    proof = generate_canonical_evidence_proof(
        evidence_id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        evidence_type="email_file",
        evidence_sha256=evidence_artifact_hash,
        collected_at=datetime.now(timezone.utc),
        collected_by="analyst",
    )

    proof_hash = proof.proof_sha256

    # 1. Evidence.sha256 is the artifact hash; proof_sha256 is the integrity statement hash
    assert evidence_artifact_hash != proof_hash

    # 2. Passing a dict with only "sha256" (artifact hash) fails because proof_sha256 is required
    with pytest.raises(InvalidProofPayloadError) as exc_hash:
        extract_proof_hash({"sha256": evidence_artifact_hash})
    assert "Evidence.sha256 is an artifact hash, not proof_sha256" in str(exc_hash.value)

    # 3. Transaction ID is an on-chain receipt identifier and is not confused with proof_sha256
    tx_id = "0x" + "a" * 64
    assert tx_id != proof_hash


# ===========================================================================
# 12. Concrete mock provider implementation conforming to contract
# ===========================================================================

def test_12_concrete_provider_implementation():
    """12. A conforming concrete provider implements all methods and returns valid model instances."""

    class MockEthereumProvider(BlockchainProvider):
        @property
        def provider_name(self) -> str:
            return "mock-ethereum"

        @property
        def network_name(self) -> str:
            return "ethereum-sepolia"

        def anchor_evidence(self, proof: CanonicalEvidenceProof) -> AnchorResult:
            if not isinstance(proof, CanonicalEvidenceProof):
                raise InvalidProofPayloadError("Expected CanonicalEvidenceProof.")
            proof_hash = extract_proof_hash(proof)
            return AnchorResult(
                transaction_id=VALID_TX_ID,
                proof_sha256=proof_hash,
                network=self.network_name,
                provider=self.provider_name,
                anchored_at=datetime.now(timezone.utc),
                status="confirmed",
            )

        def verify_evidence(
            self,
            proof: CanonicalEvidenceProof,
            transaction_id: str | None = None,
        ) -> VerificationResult:
            if not isinstance(proof, CanonicalEvidenceProof):
                raise InvalidProofPayloadError("Expected CanonicalEvidenceProof.")
            proof_hash = extract_proof_hash(proof)
            tx_id = transaction_id or VALID_TX_ID
            return VerificationResult(
                transaction_id=tx_id,
                proof_sha256=proof_hash,
                verified=True,
                network=self.network_name,
                provider=self.provider_name,
                verified_at=datetime.now(timezone.utc),
                status="verified",
            )

        def get_transaction(self, transaction_id: str) -> TransactionResult:
            if not transaction_id:
                raise BlockchainTransactionNotFoundError(f"Tx '{transaction_id}' not found.")
            return TransactionResult(
                transaction_id=transaction_id,
                proof_sha256=VALID_HASH_A,
                network=self.network_name,
                provider=self.provider_name,
                status="success",
                timestamp=datetime.now(timezone.utc),
            )

    provider = MockEthereumProvider()
    proof = _make_sample_proof()

    # Anchor test
    anchor_res = provider.anchor_evidence(proof)
    assert isinstance(anchor_res, AnchorResult)
    assert anchor_res.proof_sha256 == proof.proof_sha256
    assert anchor_res.status == "confirmed"

    # Verify test
    verify_res = provider.verify_evidence(proof, transaction_id=VALID_TX_ID)
    assert isinstance(verify_res, VerificationResult)
    assert verify_res.verified is True
    assert verify_res.proof_sha256 == proof.proof_sha256

    # Get transaction test
    tx_res = provider.get_transaction(VALID_TX_ID)
    assert isinstance(tx_res, TransactionResult)
    assert tx_res.transaction_id == VALID_TX_ID
    assert tx_res.status == "success"

    # Rejection of arbitrary strings as direct input to anchor_evidence and verify_evidence
    with pytest.raises(InvalidProofPayloadError):
        provider.anchor_evidence("arbitrary_string")  # type: ignore[arg-type]

    with pytest.raises(InvalidProofPayloadError):
        provider.verify_evidence("arbitrary_string")  # type: ignore[arg-type]

    # Unconfigured provider also rejects non-CanonicalEvidenceProof
    unconfigured = UnconfiguredBlockchainProvider()
    with pytest.raises(InvalidProofPayloadError):
        unconfigured.anchor_evidence("arbitrary_string")  # type: ignore[arg-type]

    with pytest.raises(InvalidProofPayloadError):
        unconfigured.verify_evidence("arbitrary_string")  # type: ignore[arg-type]
