import unittest
from unittest.mock import MagicMock

from fastapi import HTTPException
from sqlalchemy.orm import DeclarativeBase, Session

from app.core.config import settings
from app.db.base import Base
from app.db.session import check_db_connection, get_db
from app.main import db_health_check, health_check


class TestHealthEndpoints(unittest.TestCase):
    """Test suite for health endpoints and database foundation using standard library unittest."""

    def test_health_check_response(self):
        """Verify the /health endpoint returns the expected status, app name, and environment."""
        response = health_check()
        self.assertIsInstance(response, dict)
        self.assertEqual(response.get("status"), "ok")
        self.assertEqual(response.get("app"), settings.APP_NAME)
        self.assertEqual(response.get("environment"), settings.ENVIRONMENT)

    def test_declarative_base(self):
        """Verify that Base is an instance of SQLAlchemy DeclarativeBase."""
        self.assertTrue(issubclass(Base, DeclarativeBase))

    def test_get_db_generator(self):
        """Verify get_db dependency yields a Session and properly closes it."""
        db_gen = get_db()
        db_session = next(db_gen)
        self.assertIsInstance(db_session, Session)
        # Advance generator to verify closure
        try:
            next(db_gen)
        except StopIteration:
            pass  # Expected generator completion

    def test_db_health_check_success(self):
        """Verify db_health_check returns ok when DB query succeeds."""
        mock_db = MagicMock(spec=Session)
        mock_db.execute.return_value = None
        result = db_health_check(db=mock_db)
        self.assertEqual(result, {"status": "ok", "database": "connected"})
        mock_db.execute.assert_called_once()

    def test_db_health_check_failure(self):
        """Verify db_health_check raises HTTPException 503 when DB query fails."""
        mock_db = MagicMock(spec=Session)
        mock_db.execute.side_effect = Exception("Connection refused")
        with self.assertRaises(HTTPException) as ctx:
            db_health_check(db=mock_db)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertIn("Connection refused", ctx.exception.detail)

    def test_check_db_connection_function(self):
        """Verify check_db_connection returns a (bool, message) tuple."""
        is_connected, error_msg = check_db_connection()
        self.assertIsInstance(is_connected, bool)
        self.assertTrue(error_msg is None or isinstance(error_msg, str))


if __name__ == "__main__":
    unittest.main()

