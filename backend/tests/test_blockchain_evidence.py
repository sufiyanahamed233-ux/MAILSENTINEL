"""Phase 6D — Evidence ↔ Blockchain Integration Tests for MAILSENTINEL.

Comprehensive test suite verifying:
1. Successful anchor (service & API)
2. Evidence / Case mismatch (service & API)
3. Duplicate anchor protection (service & API)
4. Provider failure + DB rollback (service & API)
5. Successful verification (service & API)
6. Failed/mismatched verification (service & API)
7. Missing transaction ID (service & API)
8. Proof regeneration before verification
9. Blockchain_verified persistence across sessions
10. Evidence.sha256 unchanged
11. No raw evidence content sent to provider
12. Unconfigured provider behavior (service & API)
13. No secrets or private keys in responses
14. Transaction not found during verification (service & API)

All tests use mocked BlockchainProvider instances. Zero external network calls.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.case import Case
from app.models.evidence import Evidence
from app.services.blockchain.evidence_service import (
    EvidenceAlreadyAnchoredError,
    EvidenceBlockchainResponse,
    EvidenceNotAnchoredError,
    EvidenceNotBelongToCaseError,
    anchor_evidence_to_blockchain,
    verify_evidence_on_blockchain,
)
from app.services.blockchain.exceptions import (
    BlockchainAnchorError,
    BlockchainError,
    BlockchainNetworkError,
    BlockchainProviderNotConfiguredError,
    BlockchainTransactionNotFoundError,
    BlockchainVerificationError,
)
from app.services.blockchain.models import AnchorResult, VerificationResult
from app.services.blockchain.provider import (
    BlockchainProvider,
    UnconfiguredBlockchainProvider,
    extract_proof_hash,
)
from app.services.investigation.evidence_proof import (
    CanonicalEvidenceProof,
    EvidenceNotFoundError,
    generate_canonical_evidence_proof,
)
from app.services.investigation.service import CaseNotFoundError

client = TestClient(app)

SAMPLE_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
SAMPLE_TX_ID = "0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
SAMPLE_NETWORK = "ethereum-sepolia"
SAMPLE_PROVIDER = "mock-sepolia"


# ---------------------------------------------------------------------------
# Test Data Helpers
# ---------------------------------------------------------------------------


def _uid() -> uuid.UUID:
    return uuid.uuid4()


def _case_num() -> str:
    return f"CASE-6D-{uuid.uuid4().hex[:8].upper()}"


def _make_case(db) -> Case:
    c = Case(
        id=_uid(),
        case_number=_case_num(),
        title="Phase 6D Evidence Test Case",
        description="Testing Phase 6D Evidence Blockchain integration",
        status="open",
        priority="medium",
    )
    db.add(c)
    db.flush()
    return c


def _make_evidence(db, case_id: uuid.UUID, **kw) -> Evidence:
    defaults = dict(
        id=_uid(),
        case_id=case_id,
        evidence_type="email_rfc822",
        description="Test suspect email evidence",
        sha256=SAMPLE_SHA256,
        collected_at=datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
        collected_by="investigator_bob",
        blockchain_tx_id=None,
        blockchain_verified=False,
    )
    defaults.update(kw)
    ev = Evidence(**defaults)
    db.add(ev)
    db.flush()
    return ev


def _build_mock_provider(
    tx_id: str = SAMPLE_TX_ID,
    network: str = SAMPLE_NETWORK,
    provider_name: str = SAMPLE_PROVIDER,
    verify_status: str = "verified",
    verified: bool = True,
) -> MagicMock:
    """Helper building a mock BlockchainProvider."""
    mock = MagicMock(spec=BlockchainProvider)
    mock.provider_name = provider_name
    mock.network_name = network

    now = datetime.now(timezone.utc)

    def _anchor(proof: CanonicalEvidenceProof) -> AnchorResult:
        return AnchorResult(
            transaction_id=tx_id,
            proof_sha256=proof.proof_sha256,
            network=network,
            provider=provider_name,
            anchored_at=now,
            status="confirmed",
        )

    def _verify(proof: CanonicalEvidenceProof, transaction_id: str | None = None) -> VerificationResult:
        return VerificationResult(
            transaction_id=transaction_id or tx_id,
            proof_sha256=proof.proof_sha256,
            verified=verified,
            network=network,
            provider=provider_name,
            verified_at=now,
            status=verify_status,
        )

    mock.anchor_evidence.side_effect = _anchor
    mock.verify_evidence.side_effect = _verify
    return mock


# ===========================================================================
# 1. Successful Anchor (Service & API)
# ===========================================================================


def test_01_successful_anchor_service():
    """1a. Service: Anchoring successfully computes proof, anchors, persists tx_id, keeps verified=False."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        mock_provider = _build_mock_provider(tx_id=SAMPLE_TX_ID)

        res = anchor_evidence_to_blockchain(
            db=db,
            case_id=case.id,
            evidence_id=ev.id,
            provider=mock_provider,
        )

        assert isinstance(res, EvidenceBlockchainResponse)
        assert res.evidence_id == ev.id
        assert res.case_id == case.id
        assert len(res.proof_sha256) == 64
        assert res.transaction_id == SAMPLE_TX_ID
        assert res.network == SAMPLE_NETWORK
        assert res.provider == SAMPLE_PROVIDER
        assert res.status == "confirmed"
        assert res.blockchain_verified is False

        # In DB
        db.refresh(ev)
        assert ev.blockchain_tx_id == SAMPLE_TX_ID
        assert ev.blockchain_verified is False


def test_01b_successful_anchor_api():
    """1b. API: POST /api/v1/cases/{case_id}/evidence/{evidence_id}/anchor returns 200 with structured response."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        mock_provider = _build_mock_provider(tx_id=SAMPLE_TX_ID)

        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")

        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_id"] == str(ev.id)
        assert data["case_id"] == str(case.id)
        assert data["transaction_id"] == SAMPLE_TX_ID
        assert data["network"] == SAMPLE_NETWORK
        assert data["provider"] == SAMPLE_PROVIDER
        assert data["status"] == "confirmed"
        assert data["blockchain_verified"] is False
        assert len(data["proof_sha256"]) == 64


# ===========================================================================
# 2. Evidence / Case Mismatch (Service & API)
# ===========================================================================


def test_02_evidence_case_mismatch_service():
    """2a. Service: Raises EvidenceNotBelongToCaseError or Case/EvidenceNotFoundError on mismatch."""
    with SessionLocal() as db:
        case_a = _make_case(db)
        case_b = _make_case(db)
        ev_a = _make_evidence(db, case_a.id)
        db.commit()

        mock_provider = _build_mock_provider()

        # Evidence A does not belong to Case B
        with pytest.raises(EvidenceNotBelongToCaseError):
            anchor_evidence_to_blockchain(db, case_b.id, ev_a.id, provider=mock_provider)

        with pytest.raises(EvidenceNotBelongToCaseError):
            verify_evidence_on_blockchain(db, case_b.id, ev_a.id, provider=mock_provider)

        # Non-existent case
        with pytest.raises(CaseNotFoundError):
            anchor_evidence_to_blockchain(db, _uid(), ev_a.id, provider=mock_provider)

        with pytest.raises(CaseNotFoundError):
            verify_evidence_on_blockchain(db, _uid(), ev_a.id, provider=mock_provider)

        # Non-existent evidence
        with pytest.raises(EvidenceNotFoundError):
            anchor_evidence_to_blockchain(db, case_a.id, _uid(), provider=mock_provider)

        with pytest.raises(EvidenceNotFoundError):
            verify_evidence_on_blockchain(db, case_a.id, _uid(), provider=mock_provider)


def test_02b_evidence_case_mismatch_api():
    """2b. API: Returns 404 for case mismatch, unknown case, or unknown evidence."""
    with SessionLocal() as db:
        case_a = _make_case(db)
        case_b = _make_case(db)
        ev_a = _make_evidence(db, case_a.id)
        db.commit()

        # Mismatch
        r1 = client.post(f"/api/v1/cases/{case_b.id}/evidence/{ev_a.id}/anchor")
        assert r1.status_code == 404

        r2 = client.post(f"/api/v1/cases/{case_b.id}/evidence/{ev_a.id}/verify")
        assert r2.status_code == 404

        # Non-existent case
        r3 = client.post(f"/api/v1/cases/{_uid()}/evidence/{ev_a.id}/anchor")
        assert r3.status_code == 404

        # Non-existent evidence
        r4 = client.post(f"/api/v1/cases/{case_a.id}/evidence/{_uid()}/anchor")
        assert r4.status_code == 404


# ===========================================================================
# 3. Duplicate Anchor Protection (Service & API)
# ===========================================================================


def test_03_duplicate_anchor_protection():
    """3. Re-anchoring an already anchored evidence record raises domain error / returns 409."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID)
        db.commit()

        mock_provider = _build_mock_provider()

        # Service level
        with pytest.raises(EvidenceAlreadyAnchoredError) as exc_info:
            anchor_evidence_to_blockchain(db, case.id, ev.id, provider=mock_provider)
        assert SAMPLE_TX_ID in str(exc_info.value)
        assert mock_provider.anchor_evidence.call_count == 0

        # API level: returns 409 Conflict
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")
        assert resp.status_code == 409
        assert "already anchored" in resp.json()["detail"].lower()

        # Verify DB was untouched
        db.refresh(ev)
        assert ev.blockchain_tx_id == SAMPLE_TX_ID


# ===========================================================================
# 4. Provider Failure + DB Rollback (Service & API)
# ===========================================================================


def test_04_provider_failure_and_db_rollback():
    """4. Provider failure triggers DB rollback; evidence remains uncorrupted."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        failing_provider = MagicMock(spec=BlockchainProvider)
        failing_provider.anchor_evidence.side_effect = BlockchainAnchorError("RPC connection timeout during broadcast")

        # Service level
        with pytest.raises(BlockchainAnchorError):
            anchor_evidence_to_blockchain(db, case.id, ev.id, provider=failing_provider)

        # Verify DB rollback
        db.refresh(ev)
        assert ev.blockchain_tx_id is None
        assert ev.blockchain_verified is False

        # API level: maps to 502 Bad Gateway
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=failing_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")
        assert resp.status_code == 502
        assert "RPC connection timeout" in resp.json()["detail"]


def test_04b_network_error_and_db_rollback():
    """4b. Transport-level network failure triggers DB rollback and 502."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        net_fail_provider = MagicMock(spec=BlockchainProvider)
        net_fail_provider.anchor_evidence.side_effect = BlockchainNetworkError("Cannot reach RPC host")

        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=net_fail_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")
        assert resp.status_code == 502
        assert "Cannot reach RPC host" in resp.json()["detail"]

        db.refresh(ev)
        assert ev.blockchain_tx_id is None


# ===========================================================================
# 5. Successful Verification (Service & API)
# ===========================================================================


def test_05_successful_verification():
    """5. Successful verification sets blockchain_verified=True and returns 200."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID, blockchain_verified=False)
        db.commit()

        mock_provider = _build_mock_provider(tx_id=SAMPLE_TX_ID, verified=True, verify_status="verified")

        # Service level
        res = verify_evidence_on_blockchain(db, case.id, ev.id, provider=mock_provider)
        assert res.blockchain_verified is True
        assert res.status == "verified"
        assert res.transaction_id == SAMPLE_TX_ID

        db.refresh(ev)
        assert ev.blockchain_verified is True

        # API level
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["blockchain_verified"] is True
        assert data["status"] == "verified"


# ===========================================================================
# 6. Failed / Mismatched Verification (Service & API)
# ===========================================================================


def test_06_failed_mismatched_verification():
    """6. Mismatched verification updates blockchain_verified=False, status='mismatched' and returns 200."""
    with SessionLocal() as db:
        case = _make_case(db)
        # Previously set to True to verify it resets to False on mismatch
        ev = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID, blockchain_verified=True)
        db.commit()

        mock_provider = _build_mock_provider(tx_id=SAMPLE_TX_ID, verified=False, verify_status="mismatched")

        # Service level
        res = verify_evidence_on_blockchain(db, case.id, ev.id, provider=mock_provider)
        assert res.blockchain_verified is False
        assert res.status == "mismatched"

        db.refresh(ev)
        assert ev.blockchain_verified is False

        # API level
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["blockchain_verified"] is False
        assert data["status"] == "mismatched"


# ===========================================================================
# 7. Missing Transaction ID on Verification (Service & API)
# ===========================================================================


def test_07_missing_transaction_id():
    """7. Verifying unanchored evidence (missing blockchain_tx_id) raises EvidenceNotAnchoredError / returns 400."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, blockchain_tx_id=None)
        db.commit()

        mock_provider = _build_mock_provider()

        # Service level
        with pytest.raises(EvidenceNotAnchoredError):
            verify_evidence_on_blockchain(db, case.id, ev.id, provider=mock_provider)
        assert mock_provider.verify_evidence.call_count == 0

        # API level: returns 400 Bad Request
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/verify")
        assert resp.status_code == 400
        assert "not been anchored" in resp.json()["detail"].lower()


# ===========================================================================
# 8. Proof Regeneration Before Verification
# ===========================================================================


def test_08_proof_regeneration_before_verification():
    """8. Verification must regenerate the canonical proof freshly from the current Evidence record."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID)
        db.commit()

        captured_proofs: list[CanonicalEvidenceProof] = []

        mock_provider = MagicMock(spec=BlockchainProvider)
        mock_provider.provider_name = SAMPLE_PROVIDER
        mock_provider.network_name = SAMPLE_NETWORK

        def _capture_verify(proof: CanonicalEvidenceProof, transaction_id: str | None = None) -> VerificationResult:
            captured_proofs.append(proof)
            return VerificationResult(
                transaction_id=transaction_id or SAMPLE_TX_ID,
                proof_sha256=proof.proof_sha256,
                verified=True,
                network=SAMPLE_NETWORK,
                provider=SAMPLE_PROVIDER,
                verified_at=datetime.now(timezone.utc),
                status="verified",
            )

        mock_provider.verify_evidence.side_effect = _capture_verify

        verify_evidence_on_blockchain(db, case.id, ev.id, provider=mock_provider)

        assert len(captured_proofs) == 1
        proof1 = captured_proofs[0]
        assert isinstance(proof1, CanonicalEvidenceProof)
        assert proof1.evidence_id == str(ev.id)
        assert proof1.case_id == str(case.id)

        # Expected canonical hash directly recomputed
        expected_proof = generate_canonical_evidence_proof(ev)
        assert proof1.proof_sha256 == expected_proof.proof_sha256


# ===========================================================================
# 9. Blockchain Verified Persistence Across Sessions
# ===========================================================================


def test_09_blockchain_verified_persistence():
    """9. Verification outcome persists to PostgreSQL and is readable across fresh sessions."""
    ev_id: uuid.UUID
    case_id: uuid.UUID

    with SessionLocal() as db1:
        case = _make_case(db1)
        ev = _make_evidence(db1, case.id, blockchain_tx_id=SAMPLE_TX_ID, blockchain_verified=False)
        db1.commit()
        ev_id = ev.id
        case_id = case.id

        mock_provider = _build_mock_provider(verified=True, verify_status="verified")
        verify_evidence_on_blockchain(db1, case_id, ev_id, provider=mock_provider)

    # Completely new session
    with SessionLocal() as db2:
        reloaded = db2.get(Evidence, ev_id)
        assert reloaded is not None
        assert reloaded.blockchain_verified is True
        assert reloaded.blockchain_tx_id == SAMPLE_TX_ID


# ===========================================================================
# 10. Evidence.sha256 Unchanged
# ===========================================================================


def test_10_evidence_sha256_unchanged():
    """10. Neither anchoring nor verification modifies Evidence.sha256."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, sha256=SAMPLE_SHA256)
        db.commit()

        original_sha = ev.sha256
        assert original_sha == SAMPLE_SHA256

        mock_provider = _build_mock_provider(verified=True)

        # 1. Anchor
        anchor_evidence_to_blockchain(db, case.id, ev.id, provider=mock_provider)
        db.refresh(ev)
        assert ev.sha256 == original_sha

        # 2. Verify
        verify_evidence_on_blockchain(db, case.id, ev.id, provider=mock_provider)
        db.refresh(ev)
        assert ev.sha256 == original_sha

        # Fresh read
        assert ev.sha256 == SAMPLE_SHA256


# ===========================================================================
# 11. No Raw Evidence Content Sent to Provider
# ===========================================================================


def test_11_no_raw_evidence_content_sent_to_provider():
    """11. Provider only receives CanonicalEvidenceProof, never raw email/MIME/body/attachments."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(
            db,
            case.id,
            description="Confidential forensic description",
        )
        db.commit()

        captured_anchor_args: list[CanonicalEvidenceProof] = []

        mock_provider = MagicMock(spec=BlockchainProvider)
        mock_provider.provider_name = SAMPLE_PROVIDER
        mock_provider.network_name = SAMPLE_NETWORK

        def _anchor_spy(proof: CanonicalEvidenceProof) -> AnchorResult:
            captured_anchor_args.append(proof)
            # extract_proof_hash validates no raw data or forbidden attributes
            extract_proof_hash(proof)
            return AnchorResult(
                transaction_id=SAMPLE_TX_ID,
                proof_sha256=proof.proof_sha256,
                network=SAMPLE_NETWORK,
                provider=SAMPLE_PROVIDER,
                anchored_at=datetime.now(timezone.utc),
                status="confirmed",
            )

        mock_provider.anchor_evidence.side_effect = _anchor_spy

        anchor_evidence_to_blockchain(db, case.id, ev.id, provider=mock_provider)

        assert len(captured_anchor_args) == 1
        sent_proof = captured_anchor_args[0]

        # Verify type
        assert isinstance(sent_proof, CanonicalEvidenceProof)

        # Verify forbidden raw keys not in proof payload
        forbidden_keys = {"body", "body_plain", "body_html", "raw_email", "raw_file", "raw_mime", "attachment_binary"}
        for k in forbidden_keys:
            assert k not in sent_proof.canonical_payload
            assert getattr(sent_proof, k, None) is None

        # Verify Evidence description was not placed in canonical JSON
        assert "Confidential forensic description" not in sent_proof.canonical_json


# ===========================================================================
# 12. Unconfigured Provider Behavior (Service & API)
# ===========================================================================


def test_12_unconfigured_provider():
    """12. Unconfigured provider raises BlockchainProviderNotConfiguredError and returns 503."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        ev_anchored = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID)
        db.commit()

        unconfigured = UnconfiguredBlockchainProvider()

        # Service level: Anchor
        with pytest.raises(BlockchainProviderNotConfiguredError):
            anchor_evidence_to_blockchain(db, case.id, ev.id, provider=unconfigured)

        # Service level: Verify
        with pytest.raises(BlockchainProviderNotConfiguredError):
            verify_evidence_on_blockchain(db, case.id, ev_anchored.id, provider=unconfigured)

        # API level: Anchor -> 503
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=unconfigured):
            resp1 = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")
        assert resp1.status_code == 503
        assert "not configured" in resp1.json()["detail"].lower()

        # API level: Verify -> 503
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=unconfigured):
            resp2 = client.post(f"/api/v1/cases/{case.id}/evidence/{ev_anchored.id}/verify")
        assert resp2.status_code == 503
        assert "not configured" in resp2.json()["detail"].lower()


# ===========================================================================
# 13. No Secrets in Responses
# ===========================================================================


def test_13_no_secrets_in_responses():
    """13. Responses never expose private keys, raw provider payloads, or secrets."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        mock_provider = _build_mock_provider()

        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")

        assert resp.status_code == 200
        body_text = resp.text
        assert "private_key" not in body_text.lower()
        assert "secret" not in body_text.lower()
        assert "raw_response" not in body_text.lower()


# ===========================================================================
# 14. Transaction Not Found on Verification
# ===========================================================================


def test_14_transaction_not_found_on_verification():
    """14. When transaction ID is not found on-chain, returns 404."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID)
        db.commit()

        mock_provider = MagicMock(spec=BlockchainProvider)
        mock_provider.verify_evidence.side_effect = BlockchainTransactionNotFoundError(
            f"Transaction '{SAMPLE_TX_ID}' not found on blockchain."
        )

        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/verify")

        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()


# ===========================================================================
# Phase 6E — Reliability & Idempotency Hardening Tests
# ===========================================================================


def test_15_transaction_confirmation_timeout():
    """15. Transaction confirmation timeout rolls back DB and returns 502."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        timeout_provider = MagicMock(spec=BlockchainProvider)
        timeout_provider.anchor_evidence.side_effect = BlockchainNetworkError(
            f"Failed waiting for transaction confirmation '{SAMPLE_TX_ID}': TimeExhausted: Timed out waiting for transaction receipt"
        )

        # Service level: raises BlockchainNetworkError and rolls back
        with pytest.raises(BlockchainNetworkError) as exc_info:
            anchor_evidence_to_blockchain(db, case.id, ev.id, provider=timeout_provider)
        assert "Timed out waiting for transaction receipt" in str(exc_info.value)

        db.refresh(ev)
        assert ev.blockchain_tx_id is None
        assert ev.blockchain_verified is False

        # API level: returns 502 Bad Gateway
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=timeout_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")
        assert resp.status_code == 502
        assert "Timed out waiting for transaction receipt" in resp.json()["detail"]


def test_16_transaction_receipt_revert():
    """16. Transaction on-chain revert failure rolls back DB and returns 502."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        revert_provider = MagicMock(spec=BlockchainProvider)
        revert_provider.anchor_evidence.side_effect = BlockchainAnchorError(
            f"Transaction {SAMPLE_TX_ID} reverted on-chain."
        )

        with pytest.raises(BlockchainAnchorError):
            anchor_evidence_to_blockchain(db, case.id, ev.id, provider=revert_provider)

        db.refresh(ev)
        assert ev.blockchain_tx_id is None

        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=revert_provider):
            resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")
        assert resp.status_code == 502
        assert "reverted on-chain" in resp.json()["detail"]


def test_17_provider_response_after_broadcast_pending_confirmation():
    """17. Provider response after broadcast with 0 confirmations returns status='pending' and saves tx_id."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        pending_provider = _build_mock_provider(tx_id=SAMPLE_TX_ID)
        # Override to pending status
        def _anchor_pending(proof: CanonicalEvidenceProof) -> AnchorResult:
            return AnchorResult(
                transaction_id=SAMPLE_TX_ID,
                proof_sha256=proof.proof_sha256,
                network=SAMPLE_NETWORK,
                provider=SAMPLE_PROVIDER,
                anchored_at=datetime.now(timezone.utc),
                status="pending",
            )
        pending_provider.anchor_evidence.side_effect = _anchor_pending

        res = anchor_evidence_to_blockchain(db, case.id, ev.id, provider=pending_provider)
        assert res.status == "pending"
        assert res.transaction_id == SAMPLE_TX_ID
        assert res.blockchain_verified is False

        # In DB
        db.refresh(ev)
        assert ev.blockchain_tx_id == SAMPLE_TX_ID
        assert ev.blockchain_verified is False


def test_18_verification_after_confirmation_e2e():
    """18. End-to-end anchor confirmation followed by verification succeeds and persists."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        mock_provider = _build_mock_provider(tx_id=SAMPLE_TX_ID, verified=True, verify_status="verified")

        # 1. Anchor
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            anchor_resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/anchor")
        assert anchor_resp.status_code == 200
        assert anchor_resp.json()["status"] == "confirmed"
        assert anchor_resp.json()["blockchain_verified"] is False

        # 2. Verify
        with patch("app.services.blockchain.evidence_service.get_blockchain_provider", return_value=mock_provider):
            verify_resp = client.post(f"/api/v1/cases/{case.id}/evidence/{ev.id}/verify")
        assert verify_resp.status_code == 200
        assert verify_resp.json()["status"] == "verified"
        assert verify_resp.json()["blockchain_verified"] is True

        db.refresh(ev)
        assert ev.blockchain_verified is True


def test_19_corrupted_malformed_calldata_verification():
    """19. Corrupted/malformed on-chain transaction calldata sets verified=False, status='malformed_calldata'."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID, blockchain_verified=True)
        db.commit()

        malformed_provider = _build_mock_provider(
            tx_id=SAMPLE_TX_ID,
            verified=False,
            verify_status="malformed_calldata",
        )

        res = verify_evidence_on_blockchain(db, case.id, ev.id, provider=malformed_provider)
        assert res.blockchain_verified is False
        assert res.status == "malformed_calldata"

        db.refresh(ev)
        assert ev.blockchain_verified is False


def test_20_tampered_evidence_data_after_anchor_fails_verification():
    """20. Evidence modified after anchoring produces a mismatched proof hash during verification."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, blockchain_tx_id=SAMPLE_TX_ID)
        db.commit()

        # Compute original proof hash
        original_proof = generate_canonical_evidence_proof(ev)

        # Provider simulates on-chain record having original_proof.proof_sha256
        def _verify_against_original(proof: CanonicalEvidenceProof, transaction_id: str | None = None) -> VerificationResult:
            is_matching = (proof.proof_sha256 == original_proof.proof_sha256)
            return VerificationResult(
                transaction_id=transaction_id or SAMPLE_TX_ID,
                proof_sha256=proof.proof_sha256,
                verified=is_matching,
                network=SAMPLE_NETWORK,
                provider=SAMPLE_PROVIDER,
                verified_at=datetime.now(timezone.utc),
                status="verified" if is_matching else "mismatched",
            )

        tamper_provider = MagicMock(spec=BlockchainProvider)
        tamper_provider.provider_name = SAMPLE_PROVIDER
        tamper_provider.network_name = SAMPLE_NETWORK
        tamper_provider.verify_evidence.side_effect = _verify_against_original

        # Untampered: verify succeeds
        res_ok = verify_evidence_on_blockchain(db, case.id, ev.id, provider=tamper_provider)
        assert res_ok.blockchain_verified is True
        assert res_ok.status == "verified"

        # Tamper: change evidence_type
        ev.evidence_type = "tampered_type"
        db.commit()

        # Re-verification must fail because canonical proof was regenerated from tampered row
        res_fail = verify_evidence_on_blockchain(db, case.id, ev.id, provider=tamper_provider)
        assert res_fail.blockchain_verified is False
        assert res_fail.status == "mismatched"

        db.refresh(ev)
        assert ev.blockchain_verified is False
