"""Tests for Phase 5C - Evidence, Events, and Indicators APIs."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from app.db.session import SessionLocal
from app.main import app
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.indicator import ThreatIndicator
from app.models.investigation import InvestigationEvent
from app.schemas.evidence import (
    EvidenceListResponse, EventListResponse, IndicatorListResponse,
    InvestigationEventItem, ThreatIndicatorItem, EvidenceItem,
)
from app.services.investigation.evidence_service import (
    get_case_evidence, get_case_events, get_case_indicators,
)
from app.services.investigation.service import CaseNotFoundError

client = TestClient(app)


def _uid():
    return uuid.uuid4()


def _case_num(tag):
    return f"CASE-{tag}-{uuid.uuid4().hex[:8].upper()}"


def _make_case(db, tag):
    c = Case(id=_uid(), case_number=_case_num(tag), title=f"Case {tag}", status="open", priority="medium")
    db.add(c)
    db.flush()
    return c


def _make_evidence(db, case_id, **kw):
    defaults = dict(
        id=_uid(), case_id=case_id, evidence_type="email_file",
        description="Raw email", sha256="ab" * 32,
        collected_at=datetime.now(tz=timezone.utc),
        collected_by="parser", blockchain_tx_id=None, blockchain_verified=False,
    )
    defaults.update(kw)
    obj = Evidence(**defaults)
    db.add(obj)
    return obj


def _make_event(db, case_id, **kw):
    defaults = dict(
        id=_uid(), case_id=case_id, event_type="email_ingested",
        description="Ingested", actor="system", event_metadata=None,
    )
    defaults.update(kw)
    obj = InvestigationEvent(**defaults)
    db.add(obj)
    return obj


def _make_indicator(db, case_id, **kw):
    defaults = dict(
        id=_uid(), case_id=case_id, indicator_type="domain",
        indicator_value="evil.com", source="parser",
        reputation="malicious", confidence=90,
    )
    defaults.update(kw)
    obj = ThreatIndicator(**defaults)
    db.add(obj)
    return obj


# ============================================================
# Service unit tests
# ============================================================

def test_01_evidence_valid_case():
    with SessionLocal() as db:
        case = _make_case(db, "EV1")
        _make_evidence(db, case.id, sha256="ab" * 32)
        db.commit()
        result = get_case_evidence(db, case.id)
        assert isinstance(result, EvidenceListResponse)
        assert result.case_id == case.id
        assert result.total >= 1
        assert result.items[0].sha256 == result.items[0].sha256.lower()

def test_02_evidence_unknown_case():
    with SessionLocal() as db:
        with pytest.raises(CaseNotFoundError):
            get_case_evidence(db, _uid())

def test_03_evidence_empty():
    with SessionLocal() as db:
        case = _make_case(db, "EV3")
        db.commit()
        result = get_case_evidence(db, case.id)
        assert result.total == 0
        assert result.items == []

def test_04_evidence_sha256_lowercase():
    with SessionLocal() as db:
        case = _make_case(db, "EV4")
        _make_evidence(db, case.id, sha256="ABCDEF12" * 8)
        db.commit()
        result = get_case_evidence(db, case.id)
        for item in result.items:
            assert item.sha256 == item.sha256.lower()

def test_05_events_ordering():
    with SessionLocal() as db:
        case = _make_case(db, "EV5")
        _make_event(db, case.id, event_type="email_ingested", description="First")
        _make_event(db, case.id, event_type="ti_enrichment", description="Second")
        _make_event(db, case.id, event_type="ai_analysis", description="Third")
        db.commit()
        result = get_case_events(db, case.id)
        assert isinstance(result, EventListResponse)
        assert result.total >= 3
        types = [e.event_type for e in result.items]
        assert "email_ingested" in types
        assert "ti_enrichment" in types

def test_06_events_unknown_case():
    with SessionLocal() as db:
        with pytest.raises(CaseNotFoundError):
            get_case_events(db, _uid())

def test_07_events_metadata_sanitization():
    with SessionLocal() as db:
        case = _make_case(db, "EV7")
        _make_event(
            db, case.id, event_type="enriched", description="Done",
            event_metadata={"status": "completed", "actor": "sys", "password": "x", "api_key": "k"},
        )
        db.commit()
        result = get_case_events(db, case.id)
        ev = next(e for e in result.items if e.event_type == "enriched")
        meta = ev.metadata or {}
        assert "password" not in meta
        assert "api_key" not in meta
        assert meta.get("status") == "completed"

def test_08_events_empty():
    with SessionLocal() as db:
        case = _make_case(db, "EV8")
        db.commit()
        result = get_case_events(db, case.id)
        assert result.total == 0
        assert result.items == []

def test_09_indicators_returns_data():
    with SessionLocal() as db:
        case = _make_case(db, "EV9")
        _make_indicator(db, case.id, indicator_type="domain", indicator_value="evil.com")
        _make_indicator(db, case.id, indicator_type="ip", indicator_value="1.2.3.4")
        db.commit()
        result = get_case_indicators(db, case.id)
        assert isinstance(result, IndicatorListResponse)
        assert result.total >= 2

def test_10_indicators_unknown_case():
    with SessionLocal() as db:
        with pytest.raises(CaseNotFoundError):
            get_case_indicators(db, _uid())

def test_11_indicators_empty():
    with SessionLocal() as db:
        case = _make_case(db, "EV11")
        db.commit()
        result = get_case_indicators(db, case.id)
        assert result.total == 0
        assert result.items == []


# ============================================================
# API integration tests
# ============================================================

def test_12_api_evidence_200():
    with SessionLocal() as db:
        case = _make_case(db, "AP12")
        _make_evidence(db, case.id, evidence_type="attachment", sha256="de" * 32)
        db.commit()
        cid = str(case.id)
    r = client.get(f"/api/v1/cases/{cid}/evidence")
    assert r.status_code == 200
    d = r.json()
    assert d["case_id"] == cid
    assert "items" in d and "total" in d and "limit" in d and "offset" in d
    assert d["total"] >= 1
    assert "raw_response" not in str(d)

def test_13_api_evidence_404():
    assert client.get(f"/api/v1/cases/{_uid()}/evidence").status_code == 404

def test_14_api_events_200():
    with SessionLocal() as db:
        case = _make_case(db, "AP14")
        _make_event(
            db, case.id, event_type="ingested", description="Test",
            event_metadata={"status": "ok", "password": "nope"},
        )
        db.commit()
        cid = str(case.id)
    r = client.get(f"/api/v1/cases/{cid}/events")
    assert r.status_code == 200
    d = r.json()
    assert d["case_id"] == cid and d["total"] >= 1
    meta = d["items"][0].get("metadata") or {}
    assert "password" not in meta

def test_15_api_events_404():
    assert client.get(f"/api/v1/cases/{_uid()}/events").status_code == 404

def test_16_api_indicators_200():
    with SessionLocal() as db:
        case = _make_case(db, "AP16")
        _make_indicator(db, case.id, indicator_type="ip", indicator_value="10.0.0.1", confidence=80)
        db.commit()
        cid = str(case.id)
    r = client.get(f"/api/v1/cases/{cid}/indicators")
    assert r.status_code == 200
    d = r.json()
    assert d["case_id"] == cid and d["total"] >= 1

def test_17_api_indicators_404():
    assert client.get(f"/api/v1/cases/{_uid()}/indicators").status_code == 404


# ============================================================
# Pagination tests
# ============================================================

def test_18_evidence_pagination():
    with SessionLocal() as db:
        case = _make_case(db, "PG18")
        for i in range(5):
            _make_evidence(db, case.id, sha256=f"{i:02x}" * 32, description=f"ev{i}")
        db.commit()
        cid = str(case.id)
    r1 = client.get(f"/api/v1/cases/{cid}/evidence?limit=2&offset=0")
    r2 = client.get(f"/api/v1/cases/{cid}/evidence?limit=2&offset=2")
    assert r1.status_code == r2.status_code == 200
    d1, d2 = r1.json(), r2.json()
    assert d1["limit"] == 2 and d1["offset"] == 0
    assert d2["offset"] == 2
    assert d1["total"] >= 5
    ids1 = {i["id"] for i in d1["items"]}
    ids2 = {i["id"] for i in d2["items"]}
    assert ids1.isdisjoint(ids2)

def test_19_events_pagination():
    with SessionLocal() as db:
        case = _make_case(db, "PG19")
        for i in range(4):
            _make_event(db, case.id, event_type=f"ev_{i}", description=f"Event {i}")
        db.commit()
        cid = str(case.id)
    r1 = client.get(f"/api/v1/cases/{cid}/events?limit=2&offset=0")
    r2 = client.get(f"/api/v1/cases/{cid}/events?limit=2&offset=2")
    assert r1.status_code == r2.status_code == 200
    d1, d2 = r1.json(), r2.json()
    assert d1["total"] >= 4
    ids1 = {i["id"] for i in d1["items"]}
    ids2 = {i["id"] for i in d2["items"]}
    assert ids1.isdisjoint(ids2)

def test_20_indicators_pagination():
    with SessionLocal() as db:
        case = _make_case(db, "PG20")
        for i in range(4):
            _make_indicator(db, case.id, indicator_type="domain", indicator_value=f"d{i}.evil.com")
        db.commit()
        cid = str(case.id)
    r1 = client.get(f"/api/v1/cases/{cid}/indicators?limit=2&offset=0")
    r2 = client.get(f"/api/v1/cases/{cid}/indicators?limit=2&offset=2")
    assert r1.status_code == r2.status_code == 200
    d1, d2 = r1.json(), r2.json()
    assert d1["total"] >= 4
    ids1 = {i["id"] for i in d1["items"]}
    ids2 = {i["id"] for i in d2["items"]}
    assert ids1.isdisjoint(ids2)


# ============================================================
# Blockchain fields and data-safety tests
# ============================================================

def test_21_blockchain_fields():
    with SessionLocal() as db:
        case = _make_case(db, "BC21")
        _make_evidence(
            db, case.id, evidence_type="hash", sha256="cafe" * 16,
            blockchain_tx_id="0xdeadbeef", blockchain_verified=True,
        )
        db.commit()
        cid = str(case.id)
    r = client.get(f"/api/v1/cases/{cid}/evidence")
    assert r.status_code == 200
    item = next(i for i in r.json()["items"] if i["evidence_type"] == "hash")
    assert item["blockchain_tx_id"] == "0xdeadbeef"
    assert item["blockchain_verified"] is True

def test_22_raw_response_never_present():
    with SessionLocal() as db:
        case = _make_case(db, "RS22")
        _make_evidence(db, case.id, sha256="feed" * 16)
        _make_event(
            db, case.id, event_type="ti_result", description="Done",
            event_metadata={"raw_response": "bad", "status": "done"},
        )
        _make_indicator(db, case.id, indicator_type="ip", indicator_value="10.0.0.1")
        db.commit()
        cid = str(case.id)
    for ep in ["evidence", "events", "indicators"]:
        r = client.get(f"/api/v1/cases/{cid}/{ep}")
        assert r.status_code == 200
        assert "raw_response" not in r.text, f"raw_response leaked in {ep}"

def test_23_events_null_metadata():
    with SessionLocal() as db:
        case = _make_case(db, "NM23")
        _make_event(db, case.id, event_type="case_opened", description="Opened", event_metadata=None)
        db.commit()
        cid = str(case.id)
    r = client.get(f"/api/v1/cases/{cid}/events")
    assert r.status_code == 200
    item = next(e for e in r.json()["items"] if e["event_type"] == "case_opened")
    assert item["metadata"] is None

def test_24_events_all_unsafe_metadata():
    with SessionLocal() as db:
        case = _make_case(db, "UM24")
        _make_event(
            db, case.id, event_type="all_unsafe", description="Unsafe",
            event_metadata={"password": "x", "api_key": "y", "body_html": "z"},
        )
        db.commit()
        cid = str(case.id)
    r = client.get(f"/api/v1/cases/{cid}/events")
    assert r.status_code == 200
    item = next(e for e in r.json()["items"] if e["event_type"] == "all_unsafe")
    assert item["metadata"] is None


# ============================================================
# Full DB integration test
# ============================================================

def test_25_full_integration():
    with SessionLocal() as db:
        case = _make_case(db, "INT25")
        ev_id = _uid()
        _make_evidence(
            db, case.id, id=ev_id, evidence_type="pcap", sha256="DEAD" * 16,
            collected_by="net_tap", blockchain_tx_id="0xABCD", blockchain_verified=True,
        )
        evt_id = _uid()
        _make_event(
            db, case.id, id=evt_id, event_type="case_created", description="Created",
            actor="analyst", event_metadata={"status": "open", "password": "nope"},
        )
        ind_id = _uid()
        _make_indicator(
            db, case.id, id=ind_id, indicator_type="hash", indicator_value="0" * 64,
            source="malware", confidence=99, reputation="malicious",
        )
        db.commit()
        cid = str(case.id)

    r_ev = client.get(f"/api/v1/cases/{cid}/evidence")
    assert r_ev.status_code == 200
    ev_item = next(i for i in r_ev.json()["items"] if i["id"] == str(ev_id))
    assert ev_item["evidence_type"] == "pcap"
    assert ev_item["sha256"] == "dead" * 16
    assert ev_item["blockchain_tx_id"] == "0xABCD"
    assert ev_item["blockchain_verified"] is True

    r_evt = client.get(f"/api/v1/cases/{cid}/events")
    assert r_evt.status_code == 200
    evt_item = next(e for e in r_evt.json()["items"] if e["id"] == str(evt_id))
    assert evt_item["event_type"] == "case_created"
    assert evt_item["actor"] == "analyst"
    meta = evt_item.get("metadata") or {}
    assert meta.get("status") == "open"
    assert "password" not in meta

    r_ind = client.get(f"/api/v1/cases/{cid}/indicators")
    assert r_ind.status_code == 200
    ind_item = next(i for i in r_ind.json()["items"] if i["id"] == str(ind_id))
    assert ind_item["indicator_type"] == "hash"
    assert ind_item["confidence"] == 99
    assert ind_item["reputation"] == "malicious"
    assert ind_item["source"] == "malware"
