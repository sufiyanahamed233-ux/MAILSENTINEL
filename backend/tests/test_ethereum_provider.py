"""Phase 6C — Unit Tests for Ethereum Sepolia Blockchain Provider.

Tests cover:
1.  Interface contract & properties (BlockchainProvider compliance)
2.  Configuration validation (valid, invalid private key, invalid anchor address, mainnet rejection)
3.  Private key and wallet address matching & mismatch detection
4.  Secret & private key redaction (repr, str, error sanitization, URL token masking)
5.  Unconfigured provider behavior (explicit error raising without fake success)
6.  Chain ID verification (Sepolia 11155111 vs remote RPC chain ID mismatch)
7.  Deterministic calldata construction (strictly 32 bytes proof hash, value=0, no raw email/JSON)
8.  Successful anchor with mocked Web3 transaction & receipt
9.  Anchor with 0 confirmations (pending status)
10. Anchor failure on reverted transaction (status=0)
11. Transaction retrieval (get_transaction extracting proof hash, block timestamp, receipt status)
12. Transaction not found mapping (BlockchainTransactionNotFoundError)
13. Transaction retrieval with malformed/empty calldata (proof_sha256=None)
14. Evidence verification — matching proof hash (verified=True, status="verified")
15. Evidence verification — mismatched proof hash (verified=False, status="mismatched")
16. Evidence verification — malformed on-chain calldata (verified=False, status="malformed_calldata")
17. Evidence verification — missing transaction_id (BlockchainVerificationError)
18. Strict rejection of raw evidence ORM and email payloads (InvalidProofPayloadError)
19. RPC & network failure exception mapping (BlockchainNetworkError)
20. Zero real network calls guarantee (socket interception)
"""

from __future__ import annotations

import socket
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from hexbytes import HexBytes
from web3.exceptions import (
    ProviderConnectionError,
    TimeExhausted,
    TransactionNotFound,
    Web3RPCError,
)

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
    EthereumBlockchainProvider,
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

# Test Constants
SAMPLE_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f360318"
SAMPLE_WALLET_ADDRESS = "0xCfD4D4c0c4A5CBeF1632Af0553776dFB72bdFDE9"
SAMPLE_ANCHOR_ADDRESS = "0x000000000000000000000000000000000000dEaD"
SAMPLE_RPC_URL = "https://sepolia.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"
SAMPLE_SEPOLIA_CHAIN_ID = 11155111

SAMPLE_PROOF_HASH = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
SAMPLE_TX_HASH = "0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
SAMPLE_TX_HASH_BYTES = HexBytes(SAMPLE_TX_HASH)


def _make_sample_proof(proof_hash: str = SAMPLE_PROOF_HASH) -> CanonicalEvidenceProof:
    """Helper creating a valid CanonicalEvidenceProof."""
    return generate_canonical_evidence_proof(
        evidence_id=uuid.UUID("12345678-1234-5678-1234-567812345678"),
        case_id=uuid.UUID("87654321-4321-8765-4321-876543210987"),
        evidence_type="email_rfc822",
        evidence_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        collected_at=datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
        collected_by="investigator_test",
    )


def _build_mock_web3(
    chain_id: int = SAMPLE_SEPOLIA_CHAIN_ID,
    nonce: int = 5,
    gas_estimate: int = 21000,
    gas_price: int = 20000000000,
    send_tx_hash: HexBytes = SAMPLE_TX_HASH_BYTES,
    receipt_status: int = 1,
    block_timestamp: int = 1790942400,
) -> MagicMock:
    """Helper building a fully mocked Web3 instance for testing."""
    mock_w3 = MagicMock()
    mock_w3.eth.chain_id = chain_id
    mock_w3.eth.get_transaction_count.return_value = nonce
    mock_w3.eth.estimate_gas.return_value = gas_estimate
    mock_w3.eth.gas_price = gas_price
    mock_w3.eth.max_priority_fee = 1000000000
    mock_w3.eth.get_block.return_value = {
        "baseFeePerGas": 10000000000,
        "timestamp": block_timestamp,
    }
    mock_w3.eth.send_raw_transaction.return_value = send_tx_hash
    mock_w3.eth.wait_for_transaction_receipt.return_value = {
        "status": receipt_status,
        "blockNumber": 123456,
        "transactionHash": send_tx_hash,
    }
    mock_w3.eth.get_transaction_receipt.return_value = {
        "status": receipt_status,
        "blockNumber": 123456,
    }
    return mock_w3


# ===========================================================================
# 1. Interface contract & properties
# ===========================================================================

def test_01_interface_contract_and_properties():
    """1. EthereumBlockchainProvider implements BlockchainProvider and exposes expected properties."""
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        network="sepolia",
        chain_id=SAMPLE_SEPOLIA_CHAIN_ID,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
    )
    assert isinstance(provider, BlockchainProvider)
    assert provider.provider_name == "ethereum"
    assert provider.network_name == "ethereum-sepolia"
    assert provider.chain_id == SAMPLE_SEPOLIA_CHAIN_ID
    assert provider.wallet_address == SAMPLE_WALLET_ADDRESS
    assert provider.anchor_address == SAMPLE_ANCHOR_ADDRESS


# ===========================================================================
# 2. Configuration validation
# ===========================================================================

def test_02_configuration_validation_valid_and_invalid():
    """2. Configuration validations reject invalid keys, invalid addresses, and mainnet."""
    # Valid
    p = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
    )
    assert p.wallet_address == SAMPLE_WALLET_ADDRESS

    # Invalid private key (too short)
    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_pk:
        EthereumBlockchainProvider(
            rpc_url=SAMPLE_RPC_URL,
            private_key="0x1234",
            anchor_address=SAMPLE_ANCHOR_ADDRESS,
        )
    assert "Invalid BLOCKCHAIN_PRIVATE_KEY format" in str(exc_pk.value)

    # Invalid private key (non-hex)
    with pytest.raises(BlockchainProviderNotConfiguredError):
        EthereumBlockchainProvider(
            rpc_url=SAMPLE_RPC_URL,
            private_key="z" * 64,
            anchor_address=SAMPLE_ANCHOR_ADDRESS,
        )

    # Invalid anchor address
    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_addr:
        EthereumBlockchainProvider(
            rpc_url=SAMPLE_RPC_URL,
            private_key=SAMPLE_PRIVATE_KEY,
            anchor_address="0xInvalidEthereumAddress12345",
        )
    assert "Invalid BLOCKCHAIN_ANCHOR_ADDRESS" in str(exc_addr.value)

    # Rejection of Ethereum mainnet
    with pytest.raises(BlockchainUnsupportedOperationError) as exc_mainnet:
        EthereumBlockchainProvider(
            rpc_url=SAMPLE_RPC_URL,
            private_key=SAMPLE_PRIVATE_KEY,
            network="mainnet",
            chain_id=1,
            anchor_address=SAMPLE_ANCHOR_ADDRESS,
        )
    assert "mainnet is not supported" in str(exc_mainnet.value).lower()


# ===========================================================================
# 3. Private key and wallet address matching & mismatch
# ===========================================================================

def test_03_private_key_address_matching_and_mismatch():
    """3. Verifies that expected wallet address matches derived private key address."""
    # Match succeeds
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        wallet_address=SAMPLE_WALLET_ADDRESS,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
    )
    assert provider.wallet_address == SAMPLE_WALLET_ADDRESS

    # Mismatch raises BlockchainProviderNotConfiguredError
    wrong_address = "0x1111111111111111111111111111111111111111"
    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_mismatch:
        EthereumBlockchainProvider(
            rpc_url=SAMPLE_RPC_URL,
            private_key=SAMPLE_PRIVATE_KEY,
            wallet_address=wrong_address,
            anchor_address=SAMPLE_ANCHOR_ADDRESS,
        )
    assert "does not match expected wallet address" in str(exc_mismatch.value)

    # Malformed expected wallet address raises
    with pytest.raises(BlockchainProviderNotConfiguredError):
        EthereumBlockchainProvider(
            rpc_url=SAMPLE_RPC_URL,
            private_key=SAMPLE_PRIVATE_KEY,
            wallet_address="not-an-address",
            anchor_address=SAMPLE_ANCHOR_ADDRESS,
        )


# ===========================================================================
# 4. Secret & private key redaction
# ===========================================================================

def test_04_secret_and_private_key_redaction():
    """4. Private keys and RPC secrets are strictly redacted in string representation."""
    provider = EthereumBlockchainProvider(
        rpc_url="https://sepolia.infura.io/v3/mySecretApiKey12345",
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
    )
    repr_str = repr(provider)
    str_str = str(provider)

    # Raw private key must never appear
    raw_key_no_prefix = SAMPLE_PRIVATE_KEY[2:]
    assert SAMPLE_PRIVATE_KEY not in repr_str
    assert raw_key_no_prefix not in repr_str
    assert "[REDACTED]" in repr_str
    assert "[REDACTED]" in str_str

    # Infura API key is masked
    assert "mySecretApiKey12345" not in repr_str
    assert "******2345" in repr_str or "***" in repr_str


# ===========================================================================
# 5. Unconfigured provider behavior
# ===========================================================================

def test_05_unconfigured_provider_behavior():
    """5. Unconfigured provider instance raises domain exceptions without network calls."""
    proof = _make_sample_proof()

    # Empty provider with no RPC or keys
    provider = EthereumBlockchainProvider(rpc_url=None, private_key=None, anchor_address=None)

    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_anchor:
        provider.anchor_evidence(proof)
    assert "not configured" in str(exc_anchor.value).lower()

    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_tx:
        provider.get_transaction(SAMPLE_TX_HASH)
    assert "not configured" in str(exc_tx.value).lower()

    with pytest.raises(BlockchainProviderNotConfiguredError) as exc_ver:
        provider.verify_evidence(proof, transaction_id=SAMPLE_TX_HASH)
    assert "not configured" in str(exc_ver.value).lower()

    # Factory when unconfigured in settings returns UnconfiguredBlockchainProvider
    with patch("app.core.config.settings.BLOCKCHAIN_RPC_URL", None):
        assert isinstance(get_blockchain_provider(None), UnconfiguredBlockchainProvider)
        with pytest.raises(BlockchainProviderNotConfiguredError):
            get_blockchain_provider("ethereum-sepolia")


# ===========================================================================
# 6. Chain ID verification
# ===========================================================================

def test_06_chain_id_verification_and_mismatch():
    """6. Verifies chain ID against remote RPC and aborts on mismatch."""
    mock_w3 = _build_mock_web3(chain_id=1)  # RPC claims Ethereum Mainnet (chain ID 1)

    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        chain_id=SAMPLE_SEPOLIA_CHAIN_ID,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        w3=mock_w3,
    )
    proof = _make_sample_proof()

    # Anchoring fails because remote chain_id != 11155111
    with pytest.raises(BlockchainNetworkError) as exc_chain:
        provider.anchor_evidence(proof)
    assert "Chain ID mismatch" in str(exc_chain.value)

    # RPC failure querying chain ID
    type(mock_w3.eth).chain_id = PropertyMock(side_effect=Web3RPCError("Connection refused"))
    with pytest.raises(BlockchainNetworkError) as exc_rpc:
        provider.anchor_evidence(proof)
    assert "Failed to query chain ID" in str(exc_rpc.value)



# ===========================================================================
# 7. Deterministic calldata containing exact 32-byte proof hash
# ===========================================================================

def test_07_deterministic_calldata_contains_exact_32_byte_proof_hash():
    """7. EVM transaction calldata is strictly the 32-byte proof SHA-256 with 0 value."""
    mock_w3 = _build_mock_web3()
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        w3=mock_w3,
    )
    proof = _make_sample_proof()
    expected_calldata_bytes = bytes.fromhex(proof.proof_sha256)
    assert len(expected_calldata_bytes) == 32

    with patch.object(mock_w3.eth.account, "sign_transaction", wraps=mock_w3.eth.account.sign_transaction) as mock_sign:
        result = provider.anchor_evidence(proof)

        assert mock_sign.called
        signed_args = mock_sign.call_args[0][0]
        assert signed_args["to"] == SAMPLE_ANCHOR_ADDRESS
        assert signed_args["value"] == 0
        assert signed_args["data"] == expected_calldata_bytes
        assert len(signed_args["data"]) == 32
        assert signed_args["chainId"] == SAMPLE_SEPOLIA_CHAIN_ID
        assert result.proof_sha256 == proof.proof_sha256


# ===========================================================================
# 8. Successful anchor with mocked transaction
# ===========================================================================

def test_08_successful_anchor_with_mocked_web3():
    """8. Anchor returns a valid AnchorResult with confirmed status."""
    mock_w3 = _build_mock_web3()
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        confirmations=1,
        w3=mock_w3,
    )
    proof = _make_sample_proof()

    res = provider.anchor_evidence(proof)
    assert isinstance(res, AnchorResult)
    assert res.transaction_id == SAMPLE_TX_HASH
    assert res.proof_sha256 == proof.proof_sha256
    assert res.network == "ethereum-sepolia"
    assert res.provider == "ethereum"
    assert res.status == "confirmed"
    assert isinstance(res.anchored_at, datetime)


# ===========================================================================
# 9. Anchor with 0 confirmations (pending status)
# ===========================================================================

def test_09_anchor_with_zero_confirmations():
    """9. Anchor with confirmations=0 returns status='pending' without waiting for receipt."""
    mock_w3 = _build_mock_web3()
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        confirmations=0,
        w3=mock_w3,
    )
    proof = _make_sample_proof()

    res = provider.anchor_evidence(proof)
    assert res.status == "pending"
    mock_w3.eth.wait_for_transaction_receipt.assert_not_called()


# ===========================================================================
# 10. Anchor failure on reverted transaction
# ===========================================================================

def test_10_anchor_transaction_revert_raises_anchor_error():
    """10. Receipt with status=0 raises BlockchainAnchorError."""
    mock_w3 = _build_mock_web3(receipt_status=0)
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        confirmations=1,
        w3=mock_w3,
    )
    proof = _make_sample_proof()

    with pytest.raises(BlockchainAnchorError) as exc_revert:
        provider.anchor_evidence(proof)
    assert "reverted on-chain" in str(exc_revert.value)


# ===========================================================================
# 11. Transaction retrieval
# ===========================================================================

def test_11_transaction_retrieval_success():
    """11. get_transaction retrieves transaction details and extracts proof hash from calldata."""
    mock_w3 = _build_mock_web3()
    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": HexBytes(SAMPLE_PROOF_HASH),
        "blockNumber": 123456,
    }

    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        w3=mock_w3,
    )

    tx_res = provider.get_transaction(SAMPLE_TX_HASH)
    assert isinstance(tx_res, TransactionResult)
    assert tx_res.transaction_id == SAMPLE_TX_HASH
    assert tx_res.proof_sha256 == SAMPLE_PROOF_HASH
    assert tx_res.status == "success"
    assert tx_res.network == "ethereum-sepolia"
    assert tx_res.provider == "ethereum"
    assert tx_res.timestamp is not None


# ===========================================================================
# 12. Transaction not found
# ===========================================================================

def test_12_transaction_retrieval_not_found():
    """12. get_transaction raises BlockchainTransactionNotFoundError when tx is not found."""
    mock_w3 = _build_mock_web3()
    mock_w3.eth.get_transaction.side_effect = TransactionNotFound("Transaction not found")

    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        w3=mock_w3,
    )

    with pytest.raises(BlockchainTransactionNotFoundError) as exc_missing:
        provider.get_transaction(SAMPLE_TX_HASH)
    assert "not found" in str(exc_missing.value).lower()


# ===========================================================================
# 13. Transaction retrieval with malformed or empty calldata
# ===========================================================================

def test_13_transaction_retrieval_malformed_calldata():
    """13. get_transaction handles empty or non-32-byte calldata gracefully."""
    mock_w3 = _build_mock_web3()
    provider = EthereumBlockchainProvider(rpc_url=SAMPLE_RPC_URL, w3=mock_w3)

    # Empty calldata
    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": HexBytes(b""),
        "blockNumber": 123456,
    }
    res_empty = provider.get_transaction(SAMPLE_TX_HASH)
    assert res_empty.proof_sha256 is None

    # Too short calldata (e.g. 10 bytes)
    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": HexBytes("0x1234567890"),
        "blockNumber": 123456,
    }
    res_short = provider.get_transaction(SAMPLE_TX_HASH)
    assert res_short.proof_sha256 is None

    # Non-hex string
    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": "non_hex_garbage_calldata",
        "blockNumber": 123456,
    }
    res_garbage = provider.get_transaction(SAMPLE_TX_HASH)
    assert res_garbage.proof_sha256 is None


# ===========================================================================
# 14. Evidence verification — Matching proof hash
# ===========================================================================

def test_14_verify_evidence_matching_success():
    """14. verify_evidence returns verified=True when on-chain hash matches proof hash."""
    mock_w3 = _build_mock_web3()
    proof = _make_sample_proof()

    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": HexBytes(proof.proof_sha256),
        "blockNumber": 123456,
    }

    provider = EthereumBlockchainProvider(rpc_url=SAMPLE_RPC_URL, w3=mock_w3)
    ver_res = provider.verify_evidence(proof, transaction_id=SAMPLE_TX_HASH)

    assert isinstance(ver_res, VerificationResult)
    assert ver_res.verified is True
    assert ver_res.status == "verified"
    assert ver_res.proof_sha256 == proof.proof_sha256
    assert ver_res.transaction_id == SAMPLE_TX_HASH


# ===========================================================================
# 15. Evidence verification — Mismatched proof hash
# ===========================================================================

def test_15_verify_evidence_mismatched():
    """15. verify_evidence returns verified=False and status='mismatched' on hash difference."""
    mock_w3 = _build_mock_web3()
    proof = _make_sample_proof()
    different_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": HexBytes(different_hash),
        "blockNumber": 123456,
    }

    provider = EthereumBlockchainProvider(rpc_url=SAMPLE_RPC_URL, w3=mock_w3)
    ver_res = provider.verify_evidence(proof, transaction_id=SAMPLE_TX_HASH)

    assert ver_res.verified is False
    assert ver_res.status == "mismatched"
    assert ver_res.proof_sha256 == proof.proof_sha256


# ===========================================================================
# 16. Evidence verification — Malformed on-chain calldata
# ===========================================================================

def test_16_verify_evidence_malformed_calldata():
    """16. verify_evidence returns verified=False and status='malformed_calldata' when calldata is invalid."""
    mock_w3 = _build_mock_web3()
    proof = _make_sample_proof()

    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": HexBytes(b"invalid"),
        "blockNumber": 123456,
    }

    provider = EthereumBlockchainProvider(rpc_url=SAMPLE_RPC_URL, w3=mock_w3)
    ver_res = provider.verify_evidence(proof, transaction_id=SAMPLE_TX_HASH)

    assert ver_res.verified is False
    assert ver_res.status == "malformed_calldata"


# ===========================================================================
# 17. Evidence verification — Missing transaction_id
# ===========================================================================

def test_17_verify_evidence_missing_transaction_id():
    """17. verify_evidence requires transaction_id and raises BlockchainVerificationError if missing."""
    provider = EthereumBlockchainProvider(rpc_url=SAMPLE_RPC_URL, w3=_build_mock_web3())
    proof = _make_sample_proof()

    with pytest.raises(BlockchainVerificationError) as exc_missing_tx:
        provider.verify_evidence(proof, transaction_id=None)
    assert "transaction_id is required" in str(exc_missing_tx.value)

    with pytest.raises(BlockchainVerificationError):
        provider.verify_evidence(proof, transaction_id="   ")


# ===========================================================================
# 18. Strict rejection of raw evidence ORM and email payloads
# ===========================================================================

def test_18_rejection_of_raw_evidence_and_email_content():
    """18. Provider strictly rejects raw Evidence ORM objects and dictionaries with email content."""
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        w3=_build_mock_web3(),
    )

    # Raw ORM instance
    raw_evidence = Evidence(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        evidence_type="email_rfc822",
        sha256=SAMPLE_PROOF_HASH,
    )
    with pytest.raises(InvalidProofPayloadError):
        provider.anchor_evidence(raw_evidence)  # type: ignore[arg-type]

    with pytest.raises(InvalidProofPayloadError):
        provider.verify_evidence(raw_evidence, transaction_id=SAMPLE_TX_HASH)  # type: ignore[arg-type]

    # Non-CanonicalEvidenceProof string
    with pytest.raises(InvalidProofPayloadError):
        provider.anchor_evidence("some_random_string")  # type: ignore[arg-type]

    with pytest.raises(InvalidProofPayloadError):
        provider.verify_evidence("some_random_string", transaction_id=SAMPLE_TX_HASH)  # type: ignore[arg-type]


# ===========================================================================
# 19. RPC & network failure exception mapping
# ===========================================================================

def test_19_rpc_and_network_failures():
    """19. RPC, connection, and timeout errors map to BlockchainNetworkError."""
    mock_w3 = _build_mock_web3()
    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        w3=mock_w3,
    )
    proof = _make_sample_proof()

    # Nonce query failure
    mock_w3.eth.get_transaction_count.side_effect = ProviderConnectionError("RPC node unreachable")
    with pytest.raises(BlockchainNetworkError) as exc_conn:
        provider.anchor_evidence(proof)
    assert "Failed to retrieve transaction count" in str(exc_conn.value)

    # Broadcast failure
    mock_w3.eth.get_transaction_count.side_effect = None
    mock_w3.eth.get_transaction_count.return_value = 1
    mock_w3.eth.send_raw_transaction.side_effect = Web3RPCError("Nonce too low")
    with pytest.raises(BlockchainNetworkError) as exc_broadcast:
        provider.anchor_evidence(proof)
    assert "Failed to broadcast raw transaction" in str(exc_broadcast.value)

    # Receipt timeout failure
    mock_w3.eth.send_raw_transaction.side_effect = None
    mock_w3.eth.send_raw_transaction.return_value = SAMPLE_TX_HASH_BYTES
    mock_w3.eth.wait_for_transaction_receipt.side_effect = TimeExhausted("Confirmation timed out")
    with pytest.raises(BlockchainNetworkError) as exc_timeout:
        provider.anchor_evidence(proof)
    assert "Failed waiting for transaction confirmation" in str(exc_timeout.value)

    # Query network error
    mock_w3.eth.get_transaction.side_effect = ProviderConnectionError("Socket disconnected")
    with pytest.raises(BlockchainNetworkError) as exc_query:
        provider.get_transaction(SAMPLE_TX_HASH)
    assert "RPC error querying transaction" in str(exc_query.value)


# ===========================================================================
# 20. Zero real network calls guarantee
# ===========================================================================

def test_20_zero_real_network_calls():
    """20. Unit testing makes zero real socket/HTTP network calls."""
    proof = _make_sample_proof()
    mock_w3 = _build_mock_web3()
    mock_w3.eth.get_transaction.return_value = {
        "hash": SAMPLE_TX_HASH_BYTES,
        "input": HexBytes(proof.proof_sha256),
        "blockNumber": 123456,
    }

    provider = EthereumBlockchainProvider(
        rpc_url=SAMPLE_RPC_URL,
        private_key=SAMPLE_PRIVATE_KEY,
        anchor_address=SAMPLE_ANCHOR_ADDRESS,
        w3=mock_w3,
    )

    with patch.object(socket.socket, "connect", side_effect=RuntimeError("Real socket call forbidden")):
        # All of these succeed purely with mock objects without opening network sockets
        anchor_res = provider.anchor_evidence(proof)
        assert anchor_res.status == "confirmed"

        tx_res = provider.get_transaction(SAMPLE_TX_HASH)
        assert tx_res.proof_sha256 == proof.proof_sha256

        ver_res = provider.verify_evidence(proof, transaction_id=SAMPLE_TX_HASH)
        assert ver_res.verified is True

