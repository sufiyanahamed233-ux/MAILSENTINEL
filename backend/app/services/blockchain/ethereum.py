"""Phase 6C — Ethereum Sepolia Blockchain Provider for MAILSENTINEL.

Implements the BlockchainProvider abstraction for Ethereum Sepolia using web3.py.

Rules & Security Constraints:
- Operates on Ethereum Sepolia testnet only.
- Never logs or exposes BLOCKCHAIN_PRIVATE_KEY.
- Anchors ONLY proof.proof_sha256 (32 bytes calldata in a 0-value transaction).
- Never puts raw email content, MIME, headers, attachments, raw TI responses, or canonical JSON on-chain.
- Verifies configured chain ID against remote RPC before broadcasting.
- No database writes, no FastAPI endpoints, no evidence model changes.
- Maps all Web3/RPC/signing/calldata errors to domain blockchain exceptions.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from eth_account import Account
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import (
    ProviderConnectionError,
    TimeExhausted,
    TransactionNotFound,
    Web3RPCError,
)

from app.core.config import settings
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
from app.services.blockchain.provider import BlockchainProvider, extract_proof_hash
from app.services.investigation.evidence_proof import CanonicalEvidenceProof

logger = logging.getLogger(__name__)

SEPOLIA_CHAIN_ID = 11155111


def _mask_url(url: str | None) -> str:
    """Mask sensitive tokens or keys in RPC URLs for safe logging and repr."""
    if not url:
        return "none"
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")
        # If the path has a key (e.g. Infura /v3/<key>), mask it
        if len(path_parts) > 1 and path_parts[0] in ("v3", "v2"):
            masked_path = f"/{path_parts[0]}/" + "*" * 6 + path_parts[-1][-4:] if len(path_parts[-1]) > 4 else f"/{path_parts[0]}/***"
            return f"{parsed.scheme}://{parsed.netloc}{masked_path}"
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception:
        return "***"


class EthereumBlockchainProvider(BlockchainProvider):
    """Ethereum Sepolia blockchain provider implementation using web3.py."""

    def __init__(
        self,
        rpc_url: str | None = None,
        private_key: str | None = None,
        network: str | None = None,
        chain_id: int | None = None,
        anchor_address: str | None = None,
        confirmations: int | None = None,
        wallet_address: str | None = None,
        w3: Web3 | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.rpc_url = (rpc_url or settings.BLOCKCHAIN_RPC_URL or "").strip() or None
        self.private_key = (private_key or settings.BLOCKCHAIN_PRIVATE_KEY or "").strip() or None
        self.network = (network or settings.BLOCKCHAIN_NETWORK or "sepolia").strip().lower()
        self.chain_id = int(chain_id if chain_id is not None else settings.BLOCKCHAIN_CHAIN_ID)
        self.anchor_address_raw = (anchor_address or settings.BLOCKCHAIN_ANCHOR_ADDRESS or "").strip() or None
        self.confirmations = int(confirmations if confirmations is not None else settings.BLOCKCHAIN_CONFIRMATIONS)
        self.expected_wallet_address = (wallet_address or "").strip() or None
        self.timeout_seconds = timeout_seconds

        # Phase 6C strictly targets Sepolia (or testnets with Sepolia chain ID)
        if self.network in ("mainnet", "ethereum-mainnet", "homestead") or self.chain_id == 1:
            raise BlockchainUnsupportedOperationError(
                "Ethereum mainnet is not supported in Phase 6C; target Sepolia only."
            )

        # Validate anchor address if configured
        if self.anchor_address_raw:
            if not Web3.is_address(self.anchor_address_raw):
                raise BlockchainProviderNotConfiguredError(
                    f"Invalid BLOCKCHAIN_ANCHOR_ADDRESS: '{self.anchor_address_raw}'."
                )
            self.anchor_address: str | None = Web3.to_checksum_address(self.anchor_address_raw)
        else:
            self.anchor_address = None

        # Validate private key and derive wallet address if provided
        if self.private_key:
            pk_clean = self.private_key[2:] if self.private_key.startswith(("0x", "0X")) else self.private_key
            if len(pk_clean) != 64 or not all(c in "0123456789abcdefABCDEF" for c in pk_clean):
                raise BlockchainProviderNotConfiguredError(
                    "Invalid BLOCKCHAIN_PRIVATE_KEY format: must be 32 bytes (64 hex characters)."
                )
            try:
                account = Account.from_key(self.private_key)
                self.wallet_address: str | None = account.address
            except Exception as e:
                raise BlockchainProviderNotConfiguredError(
                    "Failed to derive wallet address from BLOCKCHAIN_PRIVATE_KEY."
                ) from e

            if self.expected_wallet_address:
                if not Web3.is_address(self.expected_wallet_address):
                    raise BlockchainProviderNotConfiguredError(
                        f"Invalid expected wallet address: '{self.expected_wallet_address}'."
                    )
                if Web3.to_checksum_address(self.expected_wallet_address) != self.wallet_address:
                    raise BlockchainProviderNotConfiguredError(
                        f"Private key derived address '{self.wallet_address}' does not match "
                        f"expected wallet address '{self.expected_wallet_address}'."
                    )
        else:
            self.wallet_address = None

        # Web3 RPC Client initialization
        if w3 is not None:
            self.w3: Web3 | None = w3
        elif self.rpc_url:
            self.w3 = Web3(
                Web3.HTTPProvider(
                    self.rpc_url,
                    request_kwargs={"timeout": self.timeout_seconds},
                )
            )
        else:
            self.w3 = None

    @property
    def provider_name(self) -> str:
        return "ethereum"

    @property
    def network_name(self) -> str:
        if self.network in ("sepolia", "ethereum-sepolia"):
            return "ethereum-sepolia"
        return self.network

    def __repr__(self) -> str:
        return (
            f"EthereumBlockchainProvider(network='{self.network_name}', "
            f"chain_id={self.chain_id}, rpc_url='{_mask_url(self.rpc_url)}', "
            f"wallet_address='{self.wallet_address}', "
            f"anchor_address='{self.anchor_address}', "
            f"private_key='[REDACTED]')"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def _ensure_configured_for_write(self) -> None:
        """Verify all parameters needed for anchoring transactions are configured."""
        if not self.w3 or not self.rpc_url:
            raise BlockchainProviderNotConfiguredError(
                "Ethereum provider BLOCKCHAIN_RPC_URL is not configured."
            )
        if not self.private_key or not self.wallet_address:
            raise BlockchainProviderNotConfiguredError(
                "Ethereum provider BLOCKCHAIN_PRIVATE_KEY is not configured."
            )
        if not self.anchor_address:
            raise BlockchainProviderNotConfiguredError(
                "Ethereum provider BLOCKCHAIN_ANCHOR_ADDRESS is not configured."
            )

    def _ensure_configured_for_read(self) -> None:
        """Verify parameters needed for query / read operations are configured."""
        if not self.w3:
            raise BlockchainProviderNotConfiguredError(
                "Ethereum provider BLOCKCHAIN_RPC_URL is not configured."
            )

    def _verify_chain_id(self) -> None:
        """Query chain ID from remote RPC node and assert it matches configured chain ID."""
        if not self.w3:
            raise BlockchainProviderNotConfiguredError("Web3 provider is not initialized.")
        try:
            remote_chain_id = self.w3.eth.chain_id
        except Exception as e:
            raise BlockchainNetworkError(
                f"Failed to query chain ID from RPC endpoint '{_mask_url(self.rpc_url)}': {e}"
            ) from e

        if remote_chain_id != self.chain_id:
            raise BlockchainNetworkError(
                f"Chain ID mismatch: configured chain ID is {self.chain_id} ({self.network_name}), "
                f"but RPC node returned chain ID {remote_chain_id}."
            )

    def _extract_proof_from_calldata(self, calldata: Any) -> str | None:
        """Extract and validate the 32-byte (64 hex char) proof hash from transaction calldata."""
        if calldata is None:
            return None
        if isinstance(calldata, (bytes, bytearray, HexBytes)):
            hex_str = calldata.hex()
        elif isinstance(calldata, str):
            hex_str = calldata[2:] if calldata.startswith(("0x", "0X")) else calldata
        else:
            return None

        hex_str = hex_str.strip().lower()
        if len(hex_str) == 64 and all(c in "0123456789abcdef" for c in hex_str):
            return hex_str
        return None

    def anchor_evidence(self, proof: CanonicalEvidenceProof) -> AnchorResult:
        """Anchor a canonical evidence proof onto Ethereum Sepolia.

        Creates a 0-value transaction with the 32-byte proof hash in calldata,
        signs it locally with BLOCKCHAIN_PRIVATE_KEY, and broadcasts it to Sepolia.
        """
        if not isinstance(proof, CanonicalEvidenceProof):
            raise InvalidProofPayloadError(
                f"anchor_evidence requires a CanonicalEvidenceProof instance, got '{type(proof).__name__}'."
            )

        proof_hash = extract_proof_hash(proof)
        self._ensure_configured_for_write()
        assert self.w3 is not None
        assert self.wallet_address is not None
        assert self.anchor_address is not None
        assert self.private_key is not None

        # Verify chain ID before broadcasting
        self._verify_chain_id()

        # Calldata is exactly the 32-byte proof SHA-256 hash
        calldata_bytes = bytes.fromhex(proof_hash)

        # Get current transaction count (nonce)
        try:
            nonce = self.w3.eth.get_transaction_count(self.wallet_address, "pending")
        except Exception as e:
            raise BlockchainNetworkError(
                f"Failed to retrieve transaction count for wallet {self.wallet_address}: {e}"
            ) from e

        tx_dict: dict[str, Any] = {
            "from": self.wallet_address,
            "to": self.anchor_address,
            "value": 0,
            "data": calldata_bytes,
            "nonce": nonce,
            "chainId": self.chain_id,
        }

        # Gas Limit Estimation
        try:
            estimated_gas = self.w3.eth.estimate_gas(tx_dict)
            tx_dict["gas"] = int(estimated_gas * 1.2)
        except Exception:
            tx_dict["gas"] = 100000

        # Gas Pricing: EIP-1559 or Legacy
        try:
            latest_block = self.w3.eth.get_block("latest")
            if "baseFeePerGas" in latest_block and latest_block["baseFeePerGas"] is not None:
                base_fee = latest_block["baseFeePerGas"]
                priority_fee = self.w3.eth.max_priority_fee
                tx_dict["maxFeePerGas"] = (base_fee * 2) + priority_fee
                tx_dict["maxPriorityFeePerGas"] = priority_fee
            else:
                tx_dict["gasPrice"] = self.w3.eth.gas_price
        except Exception:
            try:
                tx_dict["gasPrice"] = self.w3.eth.gas_price
            except Exception:
                tx_dict["gasPrice"] = 20_000_000_000  # 20 gwei fallback

        # Sign transaction locally
        try:
            signed_tx = self.w3.eth.account.sign_transaction(tx_dict, private_key=self.private_key)
        except Exception as e:
            raise BlockchainAnchorError(f"Failed to sign transaction: {e}") from e

        # Broadcast raw transaction
        try:
            raw_tx = getattr(signed_tx, "raw_transaction", None) or getattr(signed_tx, "rawTransaction", None)
            tx_hash_bytes = self.w3.eth.send_raw_transaction(raw_tx)
        except Exception as e:
            raise BlockchainNetworkError(f"Failed to broadcast raw transaction to RPC: {e}") from e

        tx_hash_hex = tx_hash_bytes.hex() if hasattr(tx_hash_bytes, "hex") else str(tx_hash_bytes)
        if not tx_hash_hex.startswith("0x"):
            tx_hash_hex = "0x" + tx_hash_hex

        anchored_at = datetime.now(timezone.utc)
        status = "pending"

        # Wait for receipt if confirmations requested
        if self.confirmations > 0:
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(
                    tx_hash_bytes,
                    timeout=self.timeout_seconds,
                )
                r_status = receipt.get("status") if hasattr(receipt, "get") else getattr(receipt, "status", None)
                if r_status == 0:
                    raise BlockchainAnchorError(f"Transaction {tx_hash_hex} reverted on-chain.")
                status = "confirmed"

                block_number = (
                    receipt.get("blockNumber") if hasattr(receipt, "get") else getattr(receipt, "blockNumber", None)
                )
                if block_number is not None:
                    try:
                        block = self.w3.eth.get_block(block_number)
                        b_ts = block.get("timestamp") if hasattr(block, "get") else getattr(block, "timestamp", None)
                        if b_ts:
                            anchored_at = datetime.fromtimestamp(b_ts, tz=timezone.utc)
                    except Exception:
                        pass
            except BlockchainAnchorError:
                raise
            except Exception as e:
                raise BlockchainNetworkError(
                    f"Failed waiting for transaction confirmation '{tx_hash_hex}': {e}"
                ) from e

        return AnchorResult(
            transaction_id=tx_hash_hex,
            proof_sha256=proof_hash,
            network=self.network_name,
            provider=self.provider_name,
            anchored_at=anchored_at,
            status=status,
        )

    def get_transaction(self, transaction_id: str) -> TransactionResult:
        """Query a transaction from Ethereum Sepolia and extract anchored proof hash."""
        if not transaction_id or not transaction_id.strip():
            raise ValueError("transaction_id must not be empty.")

        tx_id = transaction_id.strip()
        self._ensure_configured_for_read()
        assert self.w3 is not None

        try:
            tx = self.w3.eth.get_transaction(tx_id)
        except Exception as e:
            err_name = type(e).__name__.lower()
            err_msg = str(e).lower()
            if "not found" in err_msg or "transactionnotfound" in err_name:
                raise BlockchainTransactionNotFoundError(
                    f"Transaction '{tx_id}' not found on {self.network_name}."
                ) from e
            raise BlockchainNetworkError(
                f"RPC error querying transaction '{tx_id}': {e}"
            ) from e

        if tx is None:
            raise BlockchainTransactionNotFoundError(
                f"Transaction '{tx_id}' not found on {self.network_name}."
            )

        calldata = tx.get("input") if hasattr(tx, "get") else getattr(tx, "input", None)
        if calldata is None:
            calldata = tx.get("data") if hasattr(tx, "get") else getattr(tx, "data", None)

        extracted_proof_sha256 = self._extract_proof_from_calldata(calldata)

        status = "pending"
        timestamp: datetime | None = None
        block_number = tx.get("blockNumber") if hasattr(tx, "get") else getattr(tx, "blockNumber", None)

        if block_number is not None:
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_id)
                r_status = receipt.get("status") if hasattr(receipt, "get") else getattr(receipt, "status", None)
                if r_status == 1:
                    status = "success"
                elif r_status == 0:
                    status = "failed"
                else:
                    status = "confirmed"
            except Exception:
                status = "confirmed"

            try:
                block = self.w3.eth.get_block(block_number)
                b_ts = block.get("timestamp") if hasattr(block, "get") else getattr(block, "timestamp", None)
                if b_ts is not None:
                    timestamp = datetime.fromtimestamp(b_ts, tz=timezone.utc)
            except Exception:
                pass

        return TransactionResult(
            transaction_id=tx_id,
            proof_sha256=extracted_proof_sha256,
            network=self.network_name,
            provider=self.provider_name,
            status=status,
            timestamp=timestamp,
        )

    def verify_evidence(
        self,
        proof: CanonicalEvidenceProof,
        transaction_id: str | None = None,
    ) -> VerificationResult:
        """Verify that a canonical evidence proof matches on-chain calldata in transaction_id."""
        if not isinstance(proof, CanonicalEvidenceProof):
            raise InvalidProofPayloadError(
                f"verify_evidence requires a CanonicalEvidenceProof instance, got '{type(proof).__name__}'."
            )

        proof_hash = extract_proof_hash(proof)

        if not transaction_id or not transaction_id.strip():
            raise BlockchainVerificationError(
                "transaction_id is required to verify evidence on Ethereum."
            )

        tx_id = transaction_id.strip()
        tx_result = self.get_transaction(tx_id)
        now = datetime.now(timezone.utc)

        if tx_result.proof_sha256 is None:
            verified = False
            status = "malformed_calldata"
        elif tx_result.proof_sha256 == proof_hash:
            verified = True
            status = "verified"
        else:
            verified = False
            status = "mismatched"

        return VerificationResult(
            transaction_id=tx_id,
            proof_sha256=proof_hash,
            verified=verified,
            network=self.network_name,
            provider=self.provider_name,
            verified_at=now,
            status=status,
        )
