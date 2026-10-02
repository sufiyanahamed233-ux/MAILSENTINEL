"""Phase 6E — Manual End-to-End Verification Script for Ethereum Sepolia.

Validates the full Evidence -> Canonical Proof -> Ethereum Sepolia -> Verification flow
against the live Sepolia testnet.

SAFETY AND SECURITY RULES:
- NEVER logs, prints, or persists BLOCKCHAIN_PRIVATE_KEY or any private keys.
- NEVER exposes raw RPC credentials or access tokens (masks RPC URLs).
- NEVER logs raw signed transaction bytecode.
- Operates on a synthetic, in-memory CanonicalEvidenceProof statement.
- NEVER handles or transmits real email bodies, HTML, raw MIME, or attachment binaries.
- NEVER calls or targets Ethereum mainnet (chain_id 1).
- Does not modify any database records.

Usage:
    cd backend
    python scripts/verify_sepolia_blockchain.py
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Load .env file
from dotenv import load_dotenv

env_path = BACKEND_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)

from eth_account import Account
from web3 import Web3

from app.core.config import settings
from app.services.blockchain.ethereum import (
    EthereumBlockchainProvider,
    _mask_url,
)
from app.services.blockchain.exceptions import (
    BlockchainAnchorError,
    BlockchainError,
    BlockchainNetworkError,
    BlockchainProviderNotConfiguredError,
    BlockchainTransactionNotFoundError,
    BlockchainUnsupportedOperationError,
    BlockchainVerificationError,
)
from app.services.investigation.evidence_proof import generate_canonical_evidence_proof

SEPOLIA_CHAIN_ID = 11155111


def _print_header(title: str) -> None:
    print(f"\n{'=' * 65}")
    print(f"  {title}")
    print(f"{'=' * 65}")


def _print_step(step_num: int, description: str) -> None:
    print(f"\n[Step {step_num}] {description}")


def main() -> None:
    _print_header("MAILSENTINEL -- Phase 6E: Ethereum Sepolia E2E Validation")

    # -----------------------------------------------------------------------
    # Step 1: Configuration Validation
    # -----------------------------------------------------------------------
    _print_step(1, "Validating Environment Configuration...")

    rpc_url = (settings.BLOCKCHAIN_RPC_URL or "").strip()
    private_key = (settings.BLOCKCHAIN_PRIVATE_KEY or "").strip()
    network = (settings.BLOCKCHAIN_NETWORK or "sepolia").strip().lower()
    chain_id = int(settings.BLOCKCHAIN_CHAIN_ID or 0)
    anchor_address = (settings.BLOCKCHAIN_ANCHOR_ADDRESS or "").strip()
    confirmations = int(settings.BLOCKCHAIN_CONFIRMATIONS or 1)

    if not rpc_url:
        print("\n[ERROR] BLOCKCHAIN_RPC_URL is not set in backend/.env.")
        print("Please configure BLOCKCHAIN_RPC_URL (e.g. Infura / Alchemy Sepolia endpoint) and re-run.")
        sys.exit(1)

    if not private_key:
        print("\n[ERROR] BLOCKCHAIN_PRIVATE_KEY is not set in backend/.env.")
        print("Please configure BLOCKCHAIN_PRIVATE_KEY for a funded Sepolia test account.")
        sys.exit(1)

    # Strictly Sepolia check
    if network not in ("sepolia", "ethereum-sepolia"):
        print(f"\n[ERROR] BLOCKCHAIN_NETWORK is '{network}'.")
        print("This verification script strictly requires Sepolia testnet ('sepolia').")
        sys.exit(1)

    if chain_id != SEPOLIA_CHAIN_ID:
        print(f"\n[ERROR] Configured chain ID is {chain_id}.")
        print(f"Mainnet or incorrect testnet rejected! Sepolia chain ID must be {SEPOLIA_CHAIN_ID}.")
        sys.exit(1)

    print(f"  Network:            {network}")
    print(f"  Configured Chain:   {chain_id} (Sepolia)")
    print(f"  RPC Endpoint:       {_mask_url(rpc_url)}")
    print(f"  Confirmations:      {confirmations}")

    # -----------------------------------------------------------------------
    # Step 2: RPC Connectivity & Chain ID Verification
    # -----------------------------------------------------------------------
    _print_step(2, "Verifying RPC Connectivity & Node Chain ID...")

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30.0}))
    if not w3.is_connected():
        print(f"\n[ERROR] Failed to establish connection to RPC node: {_mask_url(rpc_url)}")
        sys.exit(1)

    try:
        remote_chain_id = w3.eth.chain_id
    except Exception as e:
        print(f"\n[ERROR] Failed to query chain ID from RPC node: {e}")
        sys.exit(1)

    if remote_chain_id != SEPOLIA_CHAIN_ID:
        print(f"\n[ERROR] Remote RPC node returned chain ID {remote_chain_id}, expected Sepolia ({SEPOLIA_CHAIN_ID})!")
        if remote_chain_id == 1:
            print("CRITICAL: Remote node is Ethereum Mainnet! Aborting immediately.")
        sys.exit(1)

    latest_block = w3.eth.block_number
    print(f"  RPC Status:         Connected")
    print(f"  Remote Chain ID:    {remote_chain_id} (Matches Sepolia)")
    print(f"  Current Block:      #{latest_block}")

    # -----------------------------------------------------------------------
    # Step 3: Wallet Validation & Balance Check
    # -----------------------------------------------------------------------
    _print_step(3, "Deriving Wallet Address & Checking Sepolia Balance...")

    try:
        account = Account.from_key(private_key)
        derived_address = account.address
    except Exception as e:
        print(f"\n[ERROR] Failed to derive Ethereum address from configured private key: {e}")
        sys.exit(1)

    # Optional expected wallet validation
    expected_wallet = getattr(settings, "BLOCKCHAIN_WALLET_ADDRESS", None)
    if expected_wallet:
        checksum_expected = Web3.to_checksum_address(expected_wallet)
        if checksum_expected != derived_address:
            print(f"\n[ERROR] Derived address '{derived_address}' does not match expected '{checksum_expected}'.")
            sys.exit(1)

    # Anchor target address
    if not anchor_address:
        # Default self-anchor for testnet verification
        target_anchor = derived_address
        print(f"  Target Anchor:      {target_anchor} (Using sender address as anchor sink)")
    else:
        if not Web3.is_address(anchor_address):
            print(f"\n[ERROR] Invalid BLOCKCHAIN_ANCHOR_ADDRESS: '{anchor_address}'.")
            sys.exit(1)
        target_anchor = Web3.to_checksum_address(anchor_address)
        print(f"  Target Anchor:      {target_anchor}")

    balance_wei = w3.eth.get_balance(derived_address)
    balance_eth = w3.from_wei(balance_wei, "ether")

    print(f"  Sender Address:     {derived_address}")
    print(f"  Sepolia Balance:    {balance_eth:.6f} ETH")

    if balance_wei == 0:
        print(f"\n[ERROR] Wallet {derived_address} has 0.0 Sepolia ETH.")
        print("Please fund this testnet wallet using a Sepolia faucet before running this test.")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Step 4: Synthetic Proof Generation (In-Memory Only)
    # -----------------------------------------------------------------------
    _print_step(4, "Creating Synthetic Canonical Evidence Proof (In-Memory)...")

    synthetic_evidence_id = uuid.uuid4()
    synthetic_case_id = uuid.uuid4()
    synthetic_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    proof = generate_canonical_evidence_proof(
        evidence_id=synthetic_evidence_id,
        case_id=synthetic_case_id,
        evidence_type="email_rfc822",
        evidence_sha256=synthetic_sha256,
        collected_at=datetime.now(timezone.utc),
        collected_by="sepolia_e2e_verifier",
    )

    print(f"  Evidence UUID:      {synthetic_evidence_id}")
    print(f"  Case UUID:          {synthetic_case_id}")
    print(f"  Evidence SHA-256:   {synthetic_sha256}")
    print(f"  Proof SHA-256:      {proof.proof_sha256}")

    # -----------------------------------------------------------------------
    # Step 5: Initialize Provider & Anchor Proof to Sepolia
    # -----------------------------------------------------------------------
    _print_step(5, "Anchoring Proof to Ethereum Sepolia...")

    provider = EthereumBlockchainProvider(
        rpc_url=rpc_url,
        private_key=private_key,
        network=network,
        chain_id=chain_id,
        anchor_address=target_anchor,
        confirmations=confirmations,
        wallet_address=derived_address,
        timeout_seconds=180.0,
    )

    try:
        print("  Broadcasting 0-value transaction with 32-byte proof calldata...")
        anchor_result = provider.anchor_evidence(proof)
    except BlockchainAnchorError as e:
        print(f"\n[ERROR] Anchoring transaction failed: {e}")
        sys.exit(1)
    except BlockchainNetworkError as e:
        print(f"\n[ERROR] RPC Network failure during anchor: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error during anchor: {e}")
        sys.exit(1)

    print(f"  Transaction ID:     {anchor_result.transaction_id}")
    print(f"  Status:             {anchor_result.status}")
    print(f"  Anchored At:        {anchor_result.anchored_at.isoformat()}")

    # -----------------------------------------------------------------------
    # Step 6: Query Transaction from Sepolia
    # -----------------------------------------------------------------------
    _print_step(6, "Querying On-Chain Transaction Record...")

    try:
        tx_result = provider.get_transaction(anchor_result.transaction_id)
    except BlockchainTransactionNotFoundError as e:
        print(f"\n[ERROR] Transaction not found on Sepolia: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Error querying transaction: {e}")
        sys.exit(1)

    print(f"  Query Status:       {tx_result.status}")
    print(f"  Extracted Proof:    {tx_result.proof_sha256}")
    print(f"  Block Timestamp:    {tx_result.timestamp}")

    # -----------------------------------------------------------------------
    # Step 7: Verify Evidence On-Chain
    # -----------------------------------------------------------------------
    _print_step(7, "Verifying Evidence Proof Against On-Chain State...")

    try:
        verify_result = provider.verify_evidence(
            proof,
            transaction_id=anchor_result.transaction_id,
        )
    except Exception as e:
        print(f"\n[ERROR] Error verifying evidence: {e}")
        sys.exit(1)

    print(f"  Verified:           {verify_result.verified}")
    print(f"  Status:             {verify_result.status}")
    print(f"  Verified At:        {verify_result.verified_at.isoformat()}")

    # -----------------------------------------------------------------------
    # Final Summary (Strictly Safe Fields Only)
    # -----------------------------------------------------------------------
    _print_header("Sepolia E2E Validation Results")
    print(f"  Network:              {anchor_result.network}")
    print(f"  Sender Address:       {derived_address}")
    print(f"  Transaction ID:       {anchor_result.transaction_id}")
    print(f"  Proof SHA-256:        {anchor_result.proof_sha256}")
    print(f"  Confirmation Status:  {anchor_result.status}")
    print(f"  Verification Result:  {verify_result.verified} ({verify_result.status})")
    print(f"{'=' * 65}")

    if verify_result.verified:
        print("\n>>> Phase 6E SUCCESS: Real Ethereum Sepolia anchor & verify succeeded! <<<\n")
    else:
        print("\n>>> Phase 6E FAILURE: Verification did not confirm matching hash! <<<\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
