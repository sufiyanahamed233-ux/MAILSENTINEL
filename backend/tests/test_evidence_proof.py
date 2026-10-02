"""Tests for Phase 6A — Canonical Evidence Proof Generation for MAILSENTINEL.

Verifies:
1.  Exact canonical field set (exactly 7 keys, no extra fields)
2.  Deterministic output across repeated runs
3.  Dictionary/key-order independence during JSON serialization
4.  UTC datetime normalization (naive, offset-aware, ISO-string with Z)
5.  UUID normalization (UUID instances vs uppercase string representation)
6.  Same evidence produces same proof
7.  Changing evidence_sha256 produces different proof
8.  Changing case_id produces different proof
9.  Changing evidence_type produces different proof
10. Changing collected_at produces different proof
11. Changing collected_by produces different proof (including None handling)
12. Unicode handling in collected_by and other text fields
13. Known SHA-256 vector verification
14. Sensitive and mutable data exclusion (no description, created_at, blockchain, bodies)
15. Evidence.sha256 remains completely unchanged
16. Zero database writes (read-only verification)
17. Output schema validation (CanonicalEvidenceProof Pydantic model)
18. EvidenceNotFoundError on non-existent evidence ID
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.evidence import Evidence
from app.services.investigation.evidence_proof import (
    CANONICAL_FIELD_SET,
    CANONICAL_PROOF_VERSION,
    CanonicalEvidenceProof,
    EvidenceNotFoundError,
    generate_canonical_evidence_proof,
    generate_evidence_proof_for_id,
    normalize_timestamp,
    normalize_uuid,
)


def _uid() -> uuid.UUID:
    return uuid.uuid4()


def _case_num() -> str:
    return f"CASE-6A-{uuid.uuid4().hex[:8].upper()}"


def _make_case(db) -> Case:
    c = Case(
        id=_uid(),
        case_number=_case_num(),
        title="Evidence Proof Test Case",
        description="Testing Phase 6A canonical proof generation",
        status="open",
        priority="high",
    )
    db.add(c)
    db.flush()
    return c


def _make_evidence(db, case_id: uuid.UUID, **kw) -> Evidence:
    defaults = dict(
        id=_uid(),
        case_id=case_id,
        evidence_type="email_rfc822",
        description="Original captured suspect email file",
        sha256="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        collected_at=datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
        collected_by="officer_alice",
        blockchain_tx_id="0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        blockchain_verified=True,
    )
    defaults.update(kw)
    ev = Evidence(**defaults)
    db.add(ev)
    db.flush()
    return ev


# ===========================================================================
# 1. Exact canonical field set
# ===========================================================================

def test_01_exact_canonical_field_set():
    """1. Verify canonical payload contains exactly the 7 architecture-defined fields."""
    ev_id = _uid()
    case_id = _uid()
    proof = generate_canonical_evidence_proof(
        evidence_id=ev_id,
        case_id=case_id,
        evidence_type="email_file",
        evidence_sha256="aa" * 32,
        collected_at=datetime.now(timezone.utc),
        collected_by="investigator_bob",
    )

    payload = proof.canonical_payload
    assert set(payload.keys()) == CANONICAL_FIELD_SET
    assert len(payload) == 7
    assert payload["proof_version"] == CANONICAL_PROOF_VERSION
    assert payload["evidence_id"] == str(ev_id)
    assert payload["case_id"] == str(case_id)
    assert payload["evidence_type"] == "email_file"
    assert payload["evidence_sha256"] == "aa" * 32
    assert payload["collected_by"] == "investigator_bob"

    # Verify excluded fields are absent
    for forbidden in [
        "description",
        "created_at",
        "blockchain_tx_id",
        "blockchain_verified",
        "body",
        "html",
        "raw_response",
    ]:
        assert forbidden not in payload


# ===========================================================================
# 2. Deterministic output
# ===========================================================================

def test_02_deterministic_output():
    """2. Repeated calls with identical inputs produce identical canonical JSON and hash."""
    ev_id = _uid()
    case_id = _uid()
    ts = datetime(2026, 10, 2, 14, 30, 0, tzinfo=timezone.utc)

    proofs = [
        generate_canonical_evidence_proof(
            evidence_id=ev_id,
            case_id=case_id,
            evidence_type="network_pcap",
            evidence_sha256="bb" * 32,
            collected_at=ts,
            collected_by="analyst_carol",
        )
        for _ in range(10)
    ]

    first_json = proofs[0].canonical_json
    first_hash = proofs[0].proof_sha256

    for p in proofs[1:]:
        assert p.canonical_json == first_json
        assert p.proof_sha256 == first_hash


# ===========================================================================
# 3. Dictionary key-order independence
# ===========================================================================

def test_03_dictionary_key_order_independence():
    """3. Input dictionary key order does not alter the sorted canonical JSON serialization."""
    ev_id = _uid()
    case_id = _uid()
    ts = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    dict1 = {
        "proof_version": "1.0",
        "evidence_id": ev_id,
        "case_id": case_id,
        "evidence_type": "email_file",
        "evidence_sha256": "cc" * 32,
        "collected_at": ts,
        "collected_by": "alice",
    }

    # Completely different insertion order
    dict2 = {
        "collected_by": "alice",
        "evidence_type": "email_file",
        "collected_at": ts,
        "proof_version": "1.0",
        "evidence_sha256": "cc" * 32,
        "case_id": case_id,
        "evidence_id": ev_id,
    }

    p1 = generate_canonical_evidence_proof(dict1)
    p2 = generate_canonical_evidence_proof(dict2)

    assert p1.canonical_json == p2.canonical_json
    assert p1.proof_sha256 == p2.proof_sha256


# ===========================================================================
# 4. UTC datetime normalization
# ===========================================================================

def test_04_utc_datetime_normalization():
    """4. Naive, timezone-offset, and ISO-Z datetimes normalize to identical canonical representation."""
    ev_id = _uid()
    case_id = _uid()

    # Four representations of 2026-10-02 12:00:00 UTC
    dt_naive = datetime(2026, 10, 2, 12, 0, 0)
    dt_utc = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    dt_ist = datetime(2026, 10, 2, 17, 30, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    str_z = "2026-10-02T12:00:00Z"

    p_naive = generate_canonical_evidence_proof(
        evidence_id=ev_id, case_id=case_id, evidence_type="eml", evidence_sha256="dd" * 32,
        collected_at=dt_naive, collected_by="officer",
    )
    p_utc = generate_canonical_evidence_proof(
        evidence_id=ev_id, case_id=case_id, evidence_type="eml", evidence_sha256="dd" * 32,
        collected_at=dt_utc, collected_by="officer",
    )
    p_ist = generate_canonical_evidence_proof(
        evidence_id=ev_id, case_id=case_id, evidence_type="eml", evidence_sha256="dd" * 32,
        collected_at=dt_ist, collected_by="officer",
    )
    p_str = generate_canonical_evidence_proof(
        evidence_id=ev_id, case_id=case_id, evidence_type="eml", evidence_sha256="dd" * 32,
        collected_at=str_z, collected_by="officer",
    )

    # All 4 must normalize to exact same collected_at value
    expected_ts = "2026-10-02T12:00:00+00:00"
    assert p_naive.canonical_payload["collected_at"] == expected_ts
    assert p_utc.canonical_payload["collected_at"] == expected_ts
    assert p_ist.canonical_payload["collected_at"] == expected_ts
    assert p_str.canonical_payload["collected_at"] == expected_ts

    # And all 4 must produce the identical proof hash
    assert p_naive.proof_sha256 == p_utc.proof_sha256 == p_ist.proof_sha256 == p_str.proof_sha256


# ===========================================================================
# 5. UUID normalization
# ===========================================================================

def test_05_uuid_normalization():
    """5. UUID instances, lowercase strings, and uppercase strings normalize identically."""
    u1 = uuid.UUID("12345678-1234-5678-1234-567812345678")
    u2 = uuid.UUID("abcdef01-abcd-ef01-abcd-ef01abcdef01")

    p_obj = generate_canonical_evidence_proof(
        evidence_id=u1,
        case_id=u2,
        evidence_type="attachment",
        evidence_sha256="ee" * 32,
        collected_at="2026-10-02T12:00:00+00:00",
        collected_by="system",
    )

    p_upper = generate_canonical_evidence_proof(
        evidence_id=str(u1).upper(),
        case_id=str(u2).upper(),
        evidence_type="attachment",
        evidence_sha256="ee" * 32,
        collected_at="2026-10-02T12:00:00+00:00",
        collected_by="system",
    )

    assert p_obj.evidence_id == str(u1).lower()
    assert p_upper.evidence_id == str(u1).lower()
    assert p_obj.case_id == str(u2).lower()
    assert p_upper.case_id == str(u2).lower()
    assert p_obj.canonical_json == p_upper.canonical_json
    assert p_obj.proof_sha256 == p_upper.proof_sha256


# ===========================================================================
# 6. Same evidence produces same proof
# ===========================================================================

def test_06_same_evidence_produces_same_proof():
    """6. The same Evidence database model generates identical proof statements across invocations."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        p1 = generate_canonical_evidence_proof(ev)
        p2 = generate_canonical_evidence_proof(ev)

        assert p1.canonical_json == p2.canonical_json
        assert p1.proof_sha256 == p2.proof_sha256
        assert p1.evidence_id == str(ev.id)
        assert p1.case_id == str(case.id)


# ===========================================================================
# 7. Changing evidence_sha256 produces different proof
# ===========================================================================

def test_07_changing_evidence_sha256():
    """7. Altering evidence_sha256 yields a distinct proof_sha256 hash."""
    base_args = dict(
        evidence_id=_uid(),
        case_id=_uid(),
        evidence_type="email_file",
        collected_at="2026-10-02T12:00:00+00:00",
        collected_by="alice",
    )

    p1 = generate_canonical_evidence_proof(**base_args, evidence_sha256="11" * 32)
    p2 = generate_canonical_evidence_proof(**base_args, evidence_sha256="22" * 32)

    assert p1.proof_sha256 != p2.proof_sha256


# ===========================================================================
# 8. Changing case_id produces different proof
# ===========================================================================

def test_08_changing_case_id():
    """8. Altering case_id yields a distinct proof_sha256 hash."""
    ev_id = _uid()
    base_args = dict(
        evidence_id=ev_id,
        evidence_type="email_file",
        evidence_sha256="aa" * 32,
        collected_at="2026-10-02T12:00:00+00:00",
        collected_by="alice",
    )

    p1 = generate_canonical_evidence_proof(**base_args, case_id=_uid())
    p2 = generate_canonical_evidence_proof(**base_args, case_id=_uid())

    assert p1.proof_sha256 != p2.proof_sha256


# ===========================================================================
# 9. Changing evidence_type produces different proof
# ===========================================================================

def test_09_changing_evidence_type():
    """9. Altering evidence_type yields a distinct proof_sha256 hash."""
    base_args = dict(
        evidence_id=_uid(),
        case_id=_uid(),
        evidence_sha256="aa" * 32,
        collected_at="2026-10-02T12:00:00+00:00",
        collected_by="alice",
    )

    p1 = generate_canonical_evidence_proof(**base_args, evidence_type="email_file")
    p2 = generate_canonical_evidence_proof(**base_args, evidence_type="memory_dump")

    assert p1.proof_sha256 != p2.proof_sha256


# ===========================================================================
# 10. Changing collected_at produces different proof
# ===========================================================================

def test_10_changing_collected_at():
    """10. Altering collected_at timestamp yields a distinct proof_sha256 hash."""
    base_args = dict(
        evidence_id=_uid(),
        case_id=_uid(),
        evidence_type="email_file",
        evidence_sha256="aa" * 32,
        collected_by="alice",
    )

    p1 = generate_canonical_evidence_proof(**base_args, collected_at="2026-10-02T12:00:00+00:00")
    p2 = generate_canonical_evidence_proof(**base_args, collected_at="2026-10-02T12:00:01+00:00")

    assert p1.proof_sha256 != p2.proof_sha256


# ===========================================================================
# 11. Changing collected_by produces different proof
# ===========================================================================

def test_11_changing_collected_by():
    """11. Altering collected_by (including None vs string) yields distinct proof_sha256 hashes."""
    base_args = dict(
        evidence_id=_uid(),
        case_id=_uid(),
        evidence_type="email_file",
        evidence_sha256="aa" * 32,
        collected_at="2026-10-02T12:00:00+00:00",
    )

    p_alice = generate_canonical_evidence_proof(**base_args, collected_by="alice")
    p_bob = generate_canonical_evidence_proof(**base_args, collected_by="bob")
    p_none = generate_canonical_evidence_proof(**base_args, collected_by=None)

    assert p_alice.proof_sha256 != p_bob.proof_sha256
    assert p_alice.proof_sha256 != p_none.proof_sha256
    assert p_bob.proof_sha256 != p_none.proof_sha256

    # Verify None serializes to null in JSON
    assert '"collected_by":null' in p_none.canonical_json
    assert p_none.canonical_payload["collected_by"] is None


# ===========================================================================
# 12. Unicode handling
# ===========================================================================

def test_12_unicode_handling():
    """12. Unicode characters in collected_by are encoded deterministically in UTF-8."""
    unicode_names = [
        "René Müller",
        "検察官 鈴木 (Prosecutor Suzuki)",
        "Élodie Ångström",
        "Дмитрий Иванов",
    ]

    for name in unicode_names:
        proof = generate_canonical_evidence_proof(
            evidence_id=_uid(),
            case_id=_uid(),
            evidence_type="email_rfc822",
            evidence_sha256="ff" * 32,
            collected_at="2026-10-02T12:00:00+00:00",
            collected_by=name,
        )

        assert proof.canonical_payload["collected_by"] == name
        # UTF-8 encoded bytes round-trip cleanly
        raw_bytes = proof.canonical_json.encode("utf-8")
        parsed = json.loads(raw_bytes.decode("utf-8"))
        assert parsed["collected_by"] == name
        assert len(proof.proof_sha256) == 64


# ===========================================================================
# 13. Known SHA-256 vector
# ===========================================================================

def test_13_known_sha256_vector():
    """13. Canonical payload matches pre-computed SHA-256 test vector precisely."""
    proof = generate_canonical_evidence_proof(
        case_id="11111111-1111-1111-1111-111111111111",
        evidence_id="22222222-2222-2222-2222-222222222222",
        evidence_type="email_file",
        evidence_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        collected_at="2026-10-02T12:00:00+00:00",
        collected_by="analyst_alice",
        proof_version="1.0",
    )

    expected_canonical_json = (
        '{"case_id":"11111111-1111-1111-1111-111111111111",'
        '"collected_at":"2026-10-02T12:00:00+00:00",'
        '"collected_by":"analyst_alice",'
        '"evidence_id":"22222222-2222-2222-2222-222222222222",'
        '"evidence_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",'
        '"evidence_type":"email_file",'
        '"proof_version":"1.0"}'
    )
    expected_hash = "40358da518635321cbd3b27c6842361ccc3917d79542d44a513032c3fbdadf33"

    assert proof.canonical_json == expected_canonical_json
    assert proof.proof_sha256 == expected_hash


# ===========================================================================
# 14. Sensitive and mutable data exclusion
# ===========================================================================

def test_14_sensitive_data_exclusion():
    """14. Excludes mutable database fields, email body, and blockchain receipt data."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(
            db,
            case.id,
            description="TOP SECRET FORENSIC ARTIFACT",
            blockchain_tx_id="0xdeadbeef12345678",
            blockchain_verified=True,
        )
        db.commit()

        proof = generate_canonical_evidence_proof(ev)
        json_str = proof.canonical_json

        # Ensure excluded fields and values never leak into the canonical proof
        assert "TOP SECRET FORENSIC ARTIFACT" not in json_str
        assert "0xdeadbeef12345678" not in json_str
        assert "blockchain_tx_id" not in json_str
        assert "blockchain_verified" not in json_str
        assert "description" not in json_str
        assert "created_at" not in json_str


# ===========================================================================
# 15. Evidence.sha256 remains unchanged
# ===========================================================================

def test_15_evidence_sha256_remains_unchanged():
    """15. Computing proof_sha256 never alters or overwrites Evidence.sha256."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, sha256="33" * 32)
        db.commit()

        original_sha = ev.sha256
        proof = generate_canonical_evidence_proof(ev)

        # Evidence.sha256 is preserved
        assert ev.sha256 == original_sha
        # The two hashes represent different concepts and must not be confused
        assert ev.sha256 != proof.proof_sha256
        assert proof.canonical_payload["evidence_sha256"] == original_sha


# ===========================================================================
# 16. No database writes
# ===========================================================================

def test_16_no_database_writes():
    """16. Proof generation performs zero database inserts, updates, or deletes (read-only)."""
    with SessionLocal() as db:
        case = _make_case(db)
        ev = _make_evidence(db, case.id)
        db.commit()

        count_before = db.scalar(select(func.count()).select_from(Evidence))

        # Call service loading directly from DB
        proof = generate_evidence_proof_for_id(db, ev.id)
        assert proof.evidence_id == str(ev.id)

        count_after = db.scalar(select(func.count()).select_from(Evidence))
        assert count_before == count_after
        # No dirty session objects
        assert len(db.dirty) == 0
        assert len(db.new) == 0


# ===========================================================================
# 17. Output schema validation
# ===========================================================================

def test_17_output_schema_validation():
    """17. Result validates under Pydantic v2 CanonicalEvidenceProof schema."""
    proof = generate_canonical_evidence_proof(
        evidence_id=_uid(),
        case_id=_uid(),
        evidence_type="email_file",
        evidence_sha256="44" * 32,
        collected_at="2026-10-02T12:00:00+00:00",
        collected_by="system_agent",
    )

    assert isinstance(proof, CanonicalEvidenceProof)
    # Pydantic v2 model_validate round-trip
    dumped = proof.to_dict()
    validated = CanonicalEvidenceProof.model_validate(dumped)
    assert validated.evidence_id == proof.evidence_id
    assert validated.proof_sha256 == proof.proof_sha256

    # Dictionary subscription support
    assert proof["proof_sha256"] == proof.proof_sha256
    assert proof["canonical_json"] == proof.canonical_json
    assert proof["canonical_payload"] == proof.canonical_payload


# ===========================================================================
# 18. EvidenceNotFoundError on unknown ID
# ===========================================================================

def test_18_unknown_evidence_id_raises_error():
    """18. Querying non-existent evidence raises EvidenceNotFoundError."""
    missing_id = _uid()
    with SessionLocal() as db:
        with pytest.raises(EvidenceNotFoundError) as exc_info:
            generate_evidence_proof_for_id(db, missing_id)
        assert str(missing_id) in str(exc_info.value)
