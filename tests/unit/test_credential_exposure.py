"""
Unit tests for CredentialExposureDetector (adapted from josh-test)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone

from src.modules.detectors.credential_exposure import CredentialExposureDetector
from src.core.models import (
    DetectionStatus,
    SignalType,
    ServerProfile,
)


@pytest.fixture
def detector():
    """Create detector instance"""
    return CredentialExposureDetector()


@pytest.fixture
def mock_adapter():
    """Create mock adapter"""
    adapter = AsyncMock()
    return adapter


@pytest.fixture
def server_profile():
    """Create server profile with resources capability"""
    from src.core.models import ServerCapabilities
    return ServerProfile(
        server_name="Test Server",
        server_version="1.0.0",
        protocol_version="2024-11-05",
        capabilities=ServerCapabilities(resources=True),
        transport="sse"
    )


class TestCredentialExposureDetectorMetadata:
    """Test detector metadata"""

    def test_metadata_fields(self, detector):
        """Test all metadata fields are properly set"""
        meta = detector.metadata
        assert meta.id == "MCP-2024-CE-001"
        assert meta.name == "Credential Exposure Detector"
        assert meta.version == "1.0.0"
        assert meta.prerequisites == {"resources": True}
        assert meta.timeout_s == 30
        assert meta.severity_default == "HIGH"

    def test_standards_mapping(self, detector):
        """Test standards are properly mapped"""
        standards = detector.metadata.standards
        assert standards.cwe == "CWE-522"
        assert standards.owasp_llm == "LLM01"
        assert standards.owasp_api == "API2"
        assert standards.asvs == ["V2.1"]
        assert standards.cvss.base_score == 8.2
        assert standards.cvss.severity == "HIGH"


class TestSecretExtraction:
    """Test secret extraction patterns"""

    def test_extract_passwords(self, detector):
        """Test password pattern detection"""
        text = "password: super_secret_123"
        secrets = detector._extract_secrets(text)
        assert len(secrets['passwords']) > 0
        assert 'super_secret_123' in secrets['passwords']

    def test_extract_api_keys(self, detector):
        """Test API key pattern detection"""
        text = "api_key: sk-1234567890abcdefghijklmnopqrst"
        secrets = detector._extract_secrets(text)
        assert len(secrets['api_keys']) > 0

    def test_extract_jwt_tokens(self, detector):
        """Test JWT token detection"""
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        secrets = detector._extract_secrets(text)
        assert len(secrets['tokens']) > 0

    def test_extract_private_keys(self, detector):
        """Test private key detection"""
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAKj34..."
        secrets = detector._extract_secrets(text)
        assert len(secrets['private_keys']) > 0

    def test_extract_connection_strings(self, detector):
        """Test database connection string detection"""
        text = "postgresql://user:pass@localhost:5432/db"
        secrets = detector._extract_secrets(text)
        assert len(secrets['connection_strings']) > 0

    def test_extract_multiple_secret_types(self, detector):
        """Test extraction of multiple secret types"""
        text = """
        password: admin123
        api_key: sk-test_key_12345
        db_url: mongodb://localhost:27017
        """
        secrets = detector._extract_secrets(text)
        assert len(secrets['passwords']) > 0
        assert len(secrets['api_keys']) > 0
        assert len(secrets['connection_strings']) > 0

    def test_no_secrets_in_clean_text(self, detector):
        """Test that clean text produces no false positives"""
        text = "This is just a normal sentence with no secrets."
        secrets = detector._extract_secrets(text)
        # All lists should be empty
        total_secrets = sum(len(v) for v in secrets.values())
        assert total_secrets == 0

    def test_filter_short_matches(self, detector):
        """Test that very short matches are filtered out"""
        text = "pwd: abc"  # Too short to be real password
        secrets = detector._extract_secrets(text)
        # Should filter out 3-character or less matches
        # Our filter is > 3, so 'abc' should be filtered
        assert len(secrets['passwords']) == 0


class TestSensitiveResourceDetection:
    """Test sensitive resource URI detection"""

    def test_is_sensitive_resource_credential(self, detector):
        """Test credential-related URIs are flagged"""
        assert detector._is_sensitive_resource("internal://credentials")
        assert detector._is_sensitive_resource("resource://password_file")

    def test_is_sensitive_resource_password(self, detector):
        """Test password-related URIs are flagged"""
        assert detector._is_sensitive_resource("resource://user_passwords")

    def test_is_sensitive_resource_token(self, detector):
        """Test token-related URIs are flagged"""
        assert detector._is_sensitive_resource("api://tokens/active")

    def test_is_sensitive_resource_private(self, detector):
        """Test private resource URIs are flagged"""
        assert detector._is_sensitive_resource("internal://private/data")

    def test_is_not_sensitive_resource(self, detector):
        """Test non-sensitive URIs are not flagged"""
        assert not detector._is_sensitive_resource("resource://public/info")
        assert not detector._is_sensitive_resource("file://readme.txt")


class TestSeverityDetermination:
    """Test severity level determination"""

    def test_critical_severity_private_keys(self, detector):
        """Test private keys trigger CRITICAL severity"""
        secrets = {
            'passwords': [],
            'api_keys': [],
            'tokens': [],
            'connection_strings': [],
            'private_keys': ['-----BEGIN RSA PRIVATE KEY-----'],
            'database_urls': []
        }
        assert detector._determine_severity(secrets) == "CRITICAL"

    def test_critical_severity_connection_strings(self, detector):
        """Test connection strings trigger CRITICAL severity"""
        secrets = {
            'passwords': [],
            'api_keys': [],
            'tokens': [],
            'connection_strings': ['postgresql://user:pass@localhost'],
            'private_keys': [],
            'database_urls': []
        }
        assert detector._determine_severity(secrets) == "CRITICAL"

    def test_high_severity_passwords(self, detector):
        """Test passwords trigger HIGH severity"""
        secrets = {
            'passwords': ['admin123'],
            'api_keys': [],
            'tokens': [],
            'connection_strings': [],
            'private_keys': [],
            'database_urls': []
        }
        assert detector._determine_severity(secrets) == "HIGH"

    def test_medium_severity_tokens(self, detector):
        """Test tokens trigger MEDIUM severity"""
        secrets = {
            'passwords': [],
            'api_keys': [],
            'tokens': ['some_token_value'],
            'connection_strings': [],
            'private_keys': [],
            'database_urls': []
        }
        assert detector._determine_severity(secrets) == "MEDIUM"


class TestCredentialExposureDetection:
    """Test main detection logic"""

    @pytest.mark.asyncio
    async def test_detect_exposed_credentials(self, detector, mock_adapter, server_profile):
        """Test detection of exposed credentials in resources"""
        # Mock list_resources
        mock_adapter.list_resources.return_value = [
            {"uri": "internal://credentials", "name": "Credentials", "description": "User credentials"}
        ]

        # Mock read_resource with credentials
        mock_adapter.read_resource.return_value = {
            "contents": [
                {"text": "Admin Password: super_secret_password123"}
            ]
        }

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.detector_id == "MCP-2024-CE-001"
        assert result.status == DetectionStatus.PRESENT
        assert result.confidence == 0.95
        assert len(result.signals) > 0
        assert result.signals[0].type == SignalType.SENSITIVE_EXPOSURE
        assert result.evidence['resources_scanned'] == 1
        assert result.evidence['sensitive_resources_found'] == 1

    @pytest.mark.asyncio
    async def test_no_credentials_found(self, detector, mock_adapter, server_profile):
        """Test when no credentials are found"""
        # Mock list_resources
        mock_adapter.list_resources.return_value = [
            {"uri": "resource://public/info", "name": "Info", "description": "Public info"}
        ]

        # Mock read_resource with clean content
        mock_adapter.read_resource.return_value = {
            "contents": [
                {"text": "This is just public information."}
            ]
        }

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.ABSENT
        assert len(result.signals) == 0

    @pytest.mark.asyncio
    async def test_multiple_secret_types_detected(self, detector, mock_adapter, server_profile):
        """Test detection of multiple secret types"""
        mock_adapter.list_resources.return_value = [
            {"uri": "internal://secrets", "name": "Secrets", "description": ""}
        ]

        mock_adapter.read_resource.return_value = {
            "contents": [
                {"text": """
                password: admin123
                api_key: sk-1234567890abcdefghijklmnopqrst
                database_url: postgresql://user:pass@localhost:5432/db
                """}
            ]
        }

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.PRESENT
        assert len(result.signals) > 0
        signal = result.signals[0]
        assert 'total_secrets' in signal.context
        assert signal.context['total_secrets'] >= 3  # At least 3 secrets
        assert 'passwords' in signal.context['secret_types']
        assert 'api_keys' in signal.context['secret_types']

    @pytest.mark.asyncio
    async def test_no_resources_available(self, detector, mock_adapter, server_profile):
        """Test when no resources are available"""
        mock_adapter.list_resources.return_value = []

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.ABSENT
        assert result.confidence == 0.0
        assert result.evidence['resources_scanned'] == 0

    @pytest.mark.asyncio
    async def test_error_handling(self, detector, mock_adapter, server_profile):
        """Test error handling in detector"""
        mock_adapter.list_resources.side_effect = Exception("Connection failed")

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.UNKNOWN
        assert result.confidence == 0.0
        assert 'error' in result.evidence
        assert 'Connection failed' in result.evidence['error']

    @pytest.mark.asyncio
    async def test_critical_severity_signal(self, detector, mock_adapter, server_profile):
        """Test that critical secrets generate appropriate signal"""
        mock_adapter.list_resources.return_value = [
            {"uri": "internal://keys", "name": "Keys", "description": ""}
        ]

        mock_adapter.read_resource.return_value = {
            "contents": [
                {"text": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAKj34..."}
            ]
        }

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.PRESENT
        signal = result.signals[0]
        assert signal.context['is_critical'] is True
        assert signal.context['severity'] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_protected_resource_skip(self, detector, mock_adapter, server_profile):
        """Test that protected resources are skipped gracefully"""
        mock_adapter.list_resources.return_value = [
            {"uri": "protected://resource", "name": "Protected", "description": ""}
        ]

        # Simulate access denied
        mock_adapter.read_resource.side_effect = Exception("Access denied")

        result = await detector.run(mock_adapter, None, server_profile)

        # Should complete without error (protected resources are expected)
        assert result.status == DetectionStatus.ABSENT
        assert len(result.signals) == 0
