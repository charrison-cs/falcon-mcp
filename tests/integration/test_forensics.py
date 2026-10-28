import pytest

from tests.integration.utils.base_integration_test import BaseIntegrationTest
from falcon_mcp.modules.forensics import ForensicsModule

@pytest.mark.integration
class TestForensicsIntegration(BaseIntegrationTest):
    """Integration tests for Forensics."""

    @pytest.fixture(autouse=True)
    def setup_module(self, falcon_client):
        """Set up module with real client."""
        self.module = ForensicsModule(falcon_client)

    def test_search_returns_details(self):
        """Test that search returns full collection details."""
        result = self.call_method(self.module.search_collections, limit=5)

        self.assert_no_error(result)
        self.assert_valid_list_response(result)

        if len(result) > 0:
            self.assert_search_returns_details(
                result,
                expected_fields=["id", "priority", "state"],
            )