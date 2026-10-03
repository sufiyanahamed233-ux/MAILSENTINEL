"""Phase 6F — Real MAILSENTINEL Evidence → Ethereum Sepolia E2E Script.

Full pipeline:
  Real .eml fixture
  → forensic parse (existing eml_parser)
  → persist Case + Email to PostgreSQL (existing persistence)
  → create Evidence record linked to that Case with Evidence.sha256 = SHA-256 of .eml bytes
  → generate canonical proof (existing evidence_proof)
  → anchor to Ethereum Sepolia (existing Phase 6D evidence_service)
  → persist blockchain_tx_id (via service)
  → verify on-chain (existing verify service)
  → blockchain_verified = True in PostgreSQL
  → print all key values; never print secrets.

SAFETY AND SECURITY RULES:
- NEVER logs, prints, or exposes BLOCKCHAIN_PRIVATE_KEY.
- NEVER puts raw email body, MIME, headers, or attachment bytes on-chain.
- Only proof_sha256 (32-byte calldata) is anchored.
- Strictly Sepolia (chain_id 11155111) only — mainnet rejected.
- Cleans up test data from PostgreSQL after completion (best-effort).

Usage:
    cd backend
    python scripts/run_phase6f_e2e.py
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap: add backend root to sys.path and load .env
# ---------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent.parent
FIXTURE_PATH = BACKEND_DIR / "scripts" / "fixtures" / "phase6f_sample.eml"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from dotenv import load_dotenv  # noqa: E402

env_path = BACKEND_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)

# ---------------------------------------------------------------------------
# Application imports (after sys.path is set)
# ---------------------------------------------------------------------------

from app.core.config import settings  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.models.case import Case  # noqa: E402
from app.models.evidence import Evidence  # noqa: E402
from app.services.blockchain.ethereum import _mask_url  # noqa: E402
from app.services.blockchain.evidence_service import (  # noqa: E402
    anchor_evidence_to_blockchain,
    verify_evidence_on_blockchain,
)
from app.services.forensic.eml_parser import parse_eml_bytes  # noqa: E402
from app.services.forensic.hashing import calculate_sha256  # noqa: E402
from app.services.forensic.persistence import persist_forensic_data  # noqa: E402

SEPOLIA_CHAIN_ID = 11155111


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def _step(n: int, desc: str) -> None:
    print(f"\n[Step {n}] {desc}")


def _check_config() -> None:
    """Validate all required blockchain settings are present."""
    rpc_url = (settings.BLOCKCHAIN_RPC_URL or "").strip()
    private_key = (settings.BLOCKCHAIN_PRIVATE_KEY or "").strip()
    network = (settings.BLOCKCHAIN_NETWORK or "").strip().lower()
    chain_id = int(settings.BLOCKCHAIN_CHAIN_ID or 0)

    if not rpc_url:
        print("[ERROR] BLOCKCHAIN_RPC_URL is not set in backend/.env")
        sys.exit(1)
    if not private_key:
        print("[ERROR] BLOCKCHAIN_PRIVATE_KEY is not set in backend/.env")
        sys.exit(1)
    if network not in ("sepolia", "ethereum-sepolia"):
        print(f"[ERROR] BLOCKCHAIN_NETWORK='{network}' — Sepolia required.")
        sys.exit(1)
    if chain_id != SEPOLIA_CHAIN_ID:
        print(f"[ERROR] BLOCKCHAIN_CHAIN_ID={chain_id} — must be {SEPOLIA_CHAIN_ID} (Sepolia).")
        sys.exit(1)

    print(f"  Network:          {network}")
    print(f"  Chain ID:         {chain_id} (Sepolia ✓)")
    print(f"  RPC Endpoint:     {_mask_url(rpc_url)}")
    print(f"  Anchor Address:   {settings.BLOCKCHAIN_ANCHOR_ADDRESS or '(self)'}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    _header("MAILSENTINEL — Phase 6F: Real Evidence → Ethereum Sepolia E2E")

    # -----------------------------------------------------------------------
    # Step 1: Configuration
    # -----------------------------------------------------------------------
    _step(1, "Validating blockchain configuration...")
    _check_config()

    # -----------------------------------------------------------------------
    # Step 2: Load and hash the real .eml fixture
    # -----------------------------------------------------------------------
    _step(2, f"Loading real .eml fixture: {FIXTURE_PATH.name}")
    if not FIXTURE_PATH.exists():
        print(f"[ERROR] Fixture not found: {FIXTURE_PATH}")
        sys.exit(1)

    eml_bytes = FIXTURE_PATH.read_bytes()
    eml_sha256 = calculate_sha256(eml_bytes)  # This becomes Evidence.sha256

    print(f"  Fixture file:     {FIXTURE_PATH.name}")
    print(f"  File size:        {len(eml_bytes)} bytes")
    print(f"  Evidence SHA-256: {eml_sha256}")  # SHA-256 of raw .eml bytes

    # -----------------------------------------------------------------------
    # Step 3: Forensic parse
    # -----------------------------------------------------------------------
    _step(3, "Running forensic EML parser...")
    parsed = parse_eml_bytes(eml_bytes, FIXTURE_PATH.name)
    print(f"  Subject:          {parsed.subject}")
    print(f"  Sender:           {parsed.sender}")
    print(f"  Message-ID:       {parsed.message_id}")
    print(f"  Parsed hash:      {parsed.raw_file_hash}")
    # Confirm parsed hash matches direct hash (both omit BOM-stripping effect on the hash)
    # Note: parse_eml_bytes hashes *before* BOM stripping, so should match eml_sha256
    assert parsed.raw_file_hash == eml_sha256, (
        f"Hash mismatch: parser={parsed.raw_file_hash}, direct={eml_sha256}"
    )
    print("  Hash consistency: ✓ (parsed hash matches direct SHA-256)")

    # -----------------------------------------------------------------------
    # Step 4: Persist Case + Email to PostgreSQL
    # -----------------------------------------------------------------------
    _step(4, "Persisting Case + Email to PostgreSQL...")
    db = SessionLocal()
    case_id_for_cleanup = None
    evidence_id_for_cleanup = None

    try:
        case, email_record = persist_forensic_data(db, parsed)
        case_id_for_cleanup = case.id
        print(f"  Case ID:          {case.id}")
        print(f"  Case Number:      {case.case_number}")
        print(f"  Email ID:         {email_record.id}")
        print(f"  Email Subject:    {email_record.subject}")

        # -----------------------------------------------------------------------
        # Step 5: Create Evidence record linked to Case
        # -----------------------------------------------------------------------
        _step(5, "Creating Evidence record with Evidence.sha256 = .eml SHA-256...")
        evidence = Evidence(
            id=uuid.uuid4(),
            case_id=case.id,
            evidence_type="email_rfc822",
            description="Phase 6F E2E test: real .eml anchor to Ethereum Sepolia",
            sha256=eml_sha256,        # Evidence.sha256 = SHA-256 of the real .eml bytes
            collected_at=datetime.now(timezone.utc),
            collected_by="mailsentinel_phase6f_runner",
            blockchain_tx_id=None,
            blockchain_verified=False,
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        evidence_id_for_cleanup = evidence.id

        print(f"  Evidence ID:      {evidence.id}")
        print(f"  Evidence SHA-256: {evidence.sha256}")  # == eml_sha256
        print(f"  Collected at:     {evidence.collected_at.isoformat()}")
        print(f"  blockchain_tx_id: {evidence.blockchain_tx_id!r} (None before anchor)")
        print(f"  blockchain_verified: {evidence.blockchain_verified} (False before anchor)")

        # -----------------------------------------------------------------------
        # Step 6: Anchor to Ethereum Sepolia via Phase 6D service
        # -----------------------------------------------------------------------
        _step(6, "Anchoring Evidence to Ethereum Sepolia (real network call)...")
        print("  Broadcasting 0-value transaction with 32-byte proof calldata...")
        print("  Waiting for confirmation (this may take 10–60 seconds)...")

        anchor_response = anchor_evidence_to_blockchain(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
        )

        print(f"  proof_sha256:     {anchor_response.proof_sha256}")
        print(f"  transaction_id:   {anchor_response.transaction_id}")
        print(f"  network:          {anchor_response.network}")
        print(f"  provider:         {anchor_response.provider}")
        print(f"  status:           {anchor_response.status}")
        print(f"  blockchain_verified: {anchor_response.blockchain_verified} (False — pending verification)")

        # Confirm blockchain_tx_id is now persisted
        db.refresh(evidence)
        assert evidence.blockchain_tx_id == anchor_response.transaction_id, (
            "blockchain_tx_id not persisted correctly"
        )
        assert evidence.blockchain_verified is False, (
            "blockchain_verified must remain False until explicit verification"
        )
        print("  DB persistence:   ✓ (blockchain_tx_id persisted, blockchain_verified=False)")

        # -----------------------------------------------------------------------
        # Step 7: Verify on Ethereum Sepolia
        # -----------------------------------------------------------------------
        _step(7, "Verifying Evidence proof against on-chain transaction...")

        verify_response = verify_evidence_on_blockchain(
            db=db,
            case_id=case.id,
            evidence_id=evidence.id,
        )

        print(f"  proof_sha256:     {verify_response.proof_sha256}")
        print(f"  transaction_id:   {verify_response.transaction_id}")
        print(f"  network:          {verify_response.network}")
        print(f"  status:           {verify_response.status}")
        print(f"  blockchain_verified: {verify_response.blockchain_verified}")

        # Confirm blockchain_verified is now True in PostgreSQL
        db.refresh(evidence)
        assert evidence.blockchain_verified is True, (
            f"Expected blockchain_verified=True, got {evidence.blockchain_verified}"
        )
        print("  DB persistence:   ✓ (blockchain_verified=True in PostgreSQL)")

        # -----------------------------------------------------------------------
        # Final Summary
        # -----------------------------------------------------------------------
        _header("Phase 6F — E2E Results Summary")
        print(f"  case_id:             {case.id}")
        print(f"  evidence_id:         {evidence.id}")
        print(f"  Evidence.sha256:     {evidence.sha256}")
        print(f"  proof_sha256:        {verify_response.proof_sha256}")
        print(f"  transaction_id:      {verify_response.transaction_id}")
        print(f"  confirmation status: {anchor_response.status}")
        print(f"  verification status: {verify_response.status}")
        print(f"  blockchain_verified: {evidence.blockchain_verified}")
        print(f"{'=' * 70}")

        if verify_response.blockchain_verified:
            print("\n>>> Phase 6F SUCCESS: Real .eml → Sepolia anchor & verify complete! <<<\n")
        else:
            print("\n>>> Phase 6F FAILURE: blockchain_verified is not True! <<<\n")
            sys.exit(1)

    except Exception as exc:
        print(f"\n[ERROR] Phase 6F failed: {exc}")
        db.rollback()
        raise
    finally:
        # Best-effort cleanup: remove test evidence and cascade-delete case
        try:
            if evidence_id_for_cleanup:
                ev = db.get(Evidence, evidence_id_for_cleanup)
                if ev:
                    db.delete(ev)
                    db.commit()
            if case_id_for_cleanup:
                c = db.get(Case, case_id_for_cleanup)
                if c:
                    db.delete(c)
                    db.commit()
            print("\n  [Cleanup] Test Case + Evidence removed from PostgreSQL.")
        except Exception as cleanup_exc:
            print(f"\n  [Cleanup Warning] Could not fully clean test data: {cleanup_exc}")
        finally:
            db.close()


if __name__ == "__main__":
    main()
