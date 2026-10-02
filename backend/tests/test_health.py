import unittest

from app.core.config import settings
from app.main import health_check


class TestHealthEndpoint(unittest.TestCase):
    """Minimal test suite for the /health endpoint using standard library unittest."""

    def test_health_check_response(self):
        """Verify the health check endpoint returns the expected status and metadata."""
        response = health_check()
        self.assertIsInstance(response, dict)
        self.assertEqual(response.get("status"), "ok")
        self.assertEqual(response.get("app"), settings.APP_NAME)
        self.assertEqual(response.get("environment"), settings.ENVIRONMENT)


if __name__ == "__main__":
    unittest.main()
