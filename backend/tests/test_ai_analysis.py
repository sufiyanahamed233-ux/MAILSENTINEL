"""Tests for the AIAnalysisResult model (Phase 4A).

Verifies schema registration, column definitions, foreign-key references,
JSONB field configuration, relationship wiring, cascade behaviour,
required-field constraints, UUID primary key, and timestamp defaults.
"""

import uuid
import unittest
from datetime import datetime, timezone

from sqlalchemy import inspect, Integer, Float, Text, String
from sqlalchemy.dialects.postgresql import JSONB

from app.db.base import Base
from app.db.session import SessionLocal
from app.models.ai_analysis import AIAnalysisResult
from app.models.case import Case


class TestAIAnalysisResultModel(unittest.TestCase):
    """Unit / integration tests for the AIAnalysisResult SQLAlchemy model."""

    # ------------------------------------------------------------------
    # Schema registration
    # ------------------------------------------------------------------

    def test_01_model_registered_in_base_metadata(self):
        """AIAnalysisResult table must be present in Base.metadata."""
        self.assertIn(
            "ai_analysis_results",
            Base.metadata.tables,
            "ai_analysis_results table not found in Base.metadata",
        )

    def test_02_tablename_is_correct(self):
        """__tablename__ must be 'ai_analysis_results'."""
        self.assertEqual(AIAnalysisResult.__tablename__, "ai_analysis_results")

    # ------------------------------------------------------------------
    # Column existence and types
    # ------------------------------------------------------------------

    def test_03_expected_columns_exist(self):
        """All specified columns must be present on the table."""
        mapper = inspect(AIAnalysisResult)
        column_names = {col.key for col in mapper.columns}
        expected = {
            "id",
            "case_id",
            "classification",
            "risk_score",
            "confidence",
            "reasoning",
            "threat_indicators",
            "supporting_evidence",
            "attack_techniques",
            "recommended_actions",
            "model",
            "provider",
            "prompt_version",
            "created_at",
        }
        self.assertTrue(
            expected.issubset(column_names),
            f"Missing columns: {expected - column_names}",
        )

    def test_04_risk_score_is_integer(self):
        """risk_score column must use Integer type."""
        table = Base.metadata.tables["ai_analysis_results"]
        col = table.c.risk_score
        self.assertIsInstance(col.type, Integer)

    def test_05_confidence_is_float(self):
        """confidence column must use Float type."""
        table = Base.metadata.tables["ai_analysis_results"]
        col = table.c.confidence
        self.assertIsInstance(col.type, Float)

    def test_06_reasoning_is_text(self):
        """reasoning column must use Text type."""
        table = Base.metadata.tables["ai_analysis_results"]
        col = table.c.reasoning
        self.assertIsInstance(col.type, Text)

    def test_07_classification_is_string(self):
        """classification column must use String type."""
        table = Base.metadata.tables["ai_analysis_results"]
        col = table.c.classification
        self.assertIsInstance(col.type, String)

    # ------------------------------------------------------------------
    # Foreign key
    # ------------------------------------------------------------------

    def test_08_case_id_references_cases_id(self):
        """case_id foreign key must reference cases.id."""
        table = Base.metadata.tables["ai_analysis_results"]
        fk_targets = {
            str(fk.column) for fk in table.c.case_id.foreign_keys
        }
        self.assertIn("cases.id", fk_targets)

    def test_09_case_id_ondelete_cascade(self):
        """case_id FK must specify ON DELETE CASCADE."""
        table = Base.metadata.tables["ai_analysis_results"]
        for fk in table.c.case_id.foreign_keys:
            self.assertEqual(fk.ondelete, "CASCADE")

    # ------------------------------------------------------------------
    # JSONB fields
    # ------------------------------------------------------------------

    def test_10_jsonb_fields_configured(self):
        """JSONB columns must use the PostgreSQL JSONB type."""
        table = Base.metadata.tables["ai_analysis_results"]
        jsonb_cols = [
            "threat_indicators",
            "supporting_evidence",
            "attack_techniques",
            "recommended_actions",
        ]
        for col_name in jsonb_cols:
            col = table.c[col_name]
            # The column type may be JSONB directly or a Variant wrapping JSONB
            col_type = col.type
            # with_variant wraps the dialect type; on PostgreSQL the impl is JSONB
            is_jsonb = isinstance(col_type, JSONB) or (
                hasattr(col_type, "impl") and isinstance(col_type.impl, JSONB)
            )
            self.assertTrue(is_jsonb, f"{col_name} is not using JSONB (got {col_type})")

    # ------------------------------------------------------------------
    # Indexes
    # ------------------------------------------------------------------

    def test_11_case_id_indexed(self):
        """case_id must be indexed."""
        table = Base.metadata.tables["ai_analysis_results"]
        self.assertTrue(table.c.case_id.index, "case_id should be indexed")

    def test_12_classification_indexed(self):
        """classification must be indexed."""
        table = Base.metadata.tables["ai_analysis_results"]
        self.assertTrue(table.c.classification.index, "classification should be indexed")

    def test_13_created_at_indexed(self):
        """created_at must be indexed."""
        table = Base.metadata.tables["ai_analysis_results"]
        self.assertTrue(table.c.created_at.index, "created_at should be indexed")

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def test_14_case_relationship_exists_on_ai_analysis(self):
        """AIAnalysisResult must have a 'case' relationship."""
        mapper = inspect(AIAnalysisResult)
        rel_names = {r.key for r in mapper.relationships}
        self.assertIn("case", rel_names)

    def test_15_case_has_ai_analysis_results_relationship(self):
        """Case must have an 'ai_analysis_results' relationship."""
        mapper = inspect(Case)
        rel_names = {r.key for r in mapper.relationships}
        self.assertIn("ai_analysis_results", rel_names)

    def test_16_cascade_delete_orphan_on_case_relationship(self):
        """Case.ai_analysis_results must have 'all, delete-orphan' cascade."""
        mapper = inspect(Case)
        rel = mapper.relationships["ai_analysis_results"]
        cascade = rel.cascade
        self.assertIn("delete", cascade)
        self.assertIn("delete-orphan", cascade)

    # ------------------------------------------------------------------
    # Nullable / NOT NULL constraints
    # ------------------------------------------------------------------

    def test_17_case_id_not_nullable(self):
        """case_id must be NOT NULL."""
        table = Base.metadata.tables["ai_analysis_results"]
        self.assertFalse(table.c.case_id.nullable)

    def test_18_classification_not_nullable(self):
        """classification must be NOT NULL."""
        table = Base.metadata.tables["ai_analysis_results"]
        self.assertFalse(table.c.classification.nullable)

    def test_19_nullable_fields_are_nullable(self):
        """Optional fields must be nullable."""
        table = Base.metadata.tables["ai_analysis_results"]
        nullable_cols = [
            "risk_score",
            "confidence",
            "reasoning",
            "threat_indicators",
            "supporting_evidence",
            "attack_techniques",
            "recommended_actions",
            "model",
            "provider",
            "prompt_version",
        ]
        for col_name in nullable_cols:
            col = table.c[col_name]
            self.assertTrue(col.nullable, f"{col_name} should be nullable")

    # ------------------------------------------------------------------
    # UUID primary key
    # ------------------------------------------------------------------

    def test_20_id_is_uuid_primary_key(self):
        """id must be a UUID primary key."""
        table = Base.metadata.tables["ai_analysis_results"]
        self.assertTrue(table.c.id.primary_key)

    def test_21_default_uuid_generated(self):
        """id should generate a UUID automatically via default."""
        mapper = inspect(AIAnalysisResult)
        id_col = mapper.columns["id"]
        self.assertIsNotNone(id_col.default)

    # ------------------------------------------------------------------
    # Timestamp default
    # ------------------------------------------------------------------

    def test_22_created_at_has_server_default(self):
        """created_at must have a server_default (func.now())."""
        table = Base.metadata.tables["ai_analysis_results"]
        self.assertIsNotNone(table.c.created_at.server_default)

    def test_23_created_at_timezone_aware(self):
        """created_at DateTime must have timezone=True."""
        table = Base.metadata.tables["ai_analysis_results"]
        col_type = table.c.created_at.type
        self.assertTrue(getattr(col_type, "timezone", False), "created_at should be timezone-aware")

    # ------------------------------------------------------------------
    # PostgreSQL persistence round-trip
    # ------------------------------------------------------------------

    def test_24_persistence_round_trip(self):
        """AIAnalysisResult can be persisted and loaded from PostgreSQL."""
        with SessionLocal() as db:
            test_case = Case(
                id=uuid.uuid4(),
                case_number=f"CASE-AI-{uuid.uuid4().hex[:6].upper()}",
                title="AI Analysis Persistence Test",
                status="open",
                priority="medium",
            )
            db.add(test_case)
            db.commit()

            analysis = AIAnalysisResult(
                case_id=test_case.id,
                classification="suspicious",
                risk_score=72,
                confidence=0.85,
                reasoning="Multiple phishing indicators detected.",
                threat_indicators=[
                    {"type": "url", "value": "https://phish.example.com/login"},
                ],
                supporting_evidence={
                    "header_anomalies": ["SPF fail", "mismatched reply-to"],
                },
                attack_techniques=[
                    {"id": "T1566.001", "name": "Spearphishing Attachment"},
                ],
                recommended_actions=[
                    {"action": "quarantine", "priority": "high"},
                ],
                model="gpt-4o",
                provider="openai",
                prompt_version="v1.0.0",
            )
            db.add(analysis)
            db.commit()

            loaded = (
                db.query(AIAnalysisResult)
                .filter(AIAnalysisResult.case_id == test_case.id)
                .first()
            )
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.classification, "suspicious")
            self.assertEqual(loaded.risk_score, 72)
            self.assertAlmostEqual(loaded.confidence, 0.85, places=2)
            self.assertEqual(loaded.reasoning, "Multiple phishing indicators detected.")
            self.assertIsInstance(loaded.threat_indicators, list)
            self.assertIsInstance(loaded.supporting_evidence, dict)
            self.assertIsInstance(loaded.attack_techniques, list)
            self.assertIsInstance(loaded.recommended_actions, list)
            self.assertEqual(loaded.model, "gpt-4o")
            self.assertEqual(loaded.provider, "openai")
            self.assertEqual(loaded.prompt_version, "v1.0.0")
            self.assertIsNotNone(loaded.created_at)
            self.assertIsInstance(loaded.id, uuid.UUID)

    def test_25_relationship_navigation(self):
        """Case.ai_analysis_results returns related AIAnalysisResult rows."""
        with SessionLocal() as db:
            test_case = Case(
                id=uuid.uuid4(),
                case_number=f"CASE-AIREL-{uuid.uuid4().hex[:6].upper()}",
                title="AI Relationship Test",
                status="open",
                priority="medium",
            )
            db.add(test_case)
            db.commit()

            for cls_label in ("clean", "malicious"):
                db.add(AIAnalysisResult(
                    case_id=test_case.id,
                    classification=cls_label,
                ))
            db.commit()

            db.refresh(test_case)
            self.assertEqual(len(test_case.ai_analysis_results), 2)
            labels = {r.classification for r in test_case.ai_analysis_results}
            self.assertEqual(labels, {"clean", "malicious"})

    def test_26_cascade_delete(self):
        """Deleting a Case cascades to its AIAnalysisResult rows."""
        with SessionLocal() as db:
            case_id = uuid.uuid4()
            test_case = Case(
                id=case_id,
                case_number=f"CASE-AIDEL-{uuid.uuid4().hex[:6].upper()}",
                title="AI Cascade Delete Test",
                status="open",
                priority="medium",
            )
            db.add(test_case)
            db.commit()

            db.add(AIAnalysisResult(
                case_id=case_id,
                classification="unknown",
            ))
            db.commit()

            # Verify row exists
            count_before = (
                db.query(AIAnalysisResult)
                .filter(AIAnalysisResult.case_id == case_id)
                .count()
            )
            self.assertEqual(count_before, 1)

            db.delete(test_case)
            db.commit()

            count_after = (
                db.query(AIAnalysisResult)
                .filter(AIAnalysisResult.case_id == case_id)
                .count()
            )
            self.assertEqual(count_after, 0)

    def test_27_minimal_required_fields_only(self):
        """AIAnalysisResult must be creatable with only required fields."""
        with SessionLocal() as db:
            test_case = Case(
                id=uuid.uuid4(),
                case_number=f"CASE-AIMIN-{uuid.uuid4().hex[:6].upper()}",
                title="AI Minimal Fields Test",
                status="open",
                priority="medium",
            )
            db.add(test_case)
            db.commit()

            analysis = AIAnalysisResult(
                case_id=test_case.id,
                classification="clean",
            )
            db.add(analysis)
            db.commit()

            loaded = db.get(AIAnalysisResult, analysis.id)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.classification, "clean")
            self.assertIsNone(loaded.risk_score)
            self.assertIsNone(loaded.confidence)
            self.assertIsNone(loaded.reasoning)
            self.assertIsNone(loaded.threat_indicators)
            self.assertIsNone(loaded.supporting_evidence)
            self.assertIsNone(loaded.attack_techniques)
            self.assertIsNone(loaded.recommended_actions)
            self.assertIsNone(loaded.model)
            self.assertIsNone(loaded.provider)
            self.assertIsNone(loaded.prompt_version)
            self.assertIsNotNone(loaded.created_at)


if __name__ == "__main__":
    unittest.main()
