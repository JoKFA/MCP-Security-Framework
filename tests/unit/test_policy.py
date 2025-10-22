"""
Unit tests for policy engine.

Tests scope configuration, rate limiting, redaction, and audit logging.
"""

import asyncio
import json
import tempfile
import time
from pathlib import Path

import pytest

from src.core.policy import (
    ScopeConfig,
    RateLimitConfig,
    PolicyConfig,
    AuthConfig,
    ReportingConfig,
    RateLimiter,
    Redactor,
    AuditLogger,
    load_scope_config,
)


class TestScopeConfig:
    """Test ScopeConfig model and validation."""

    def test_minimal_config(self):
        config = ScopeConfig(target="http://localhost:9001/sse")
        assert config.target == "http://localhost:9001/sse"
        assert config.policy.dry_run is False
        assert config.rate_limit.qps == 2.0

    def test_target_validation(self):
        # Valid targets
        ScopeConfig(target="http://localhost:9001/sse")
        ScopeConfig(target="https://example.com/mcp")
        ScopeConfig(target="stdio://npx/-s/@modelcontextprotocol/server-time")

        # Invalid targets
        with pytest.raises(Exception):  # Pydantic ValidationError
            ScopeConfig(target="invalid-target")

        with pytest.raises(Exception):
            ScopeConfig(target="ftp://example.com")

    def test_is_path_allowed(self):
        config = ScopeConfig(
            target="http://localhost:9001",
            allowed_prefixes=["/resources", "/tools"],
            blocked_paths=["/admin", "/internal"]
        )

        # Allowed paths
        assert config.is_path_allowed("/resources/data") is True
        assert config.is_path_allowed("/tools/read") is True

        # Blocked paths (takes precedence)
        assert config.is_path_allowed("/admin/users") is False
        assert config.is_path_allowed("/internal/secrets") is False

        # Not in allowed list (default deny)
        assert config.is_path_allowed("/other/path") is False

    def test_load_from_yaml(self, tmp_path):
        # Create test scope.yaml
        yaml_content = """
target: "http://localhost:9001/sse"
allowed_prefixes:
  - "/resources"
blocked_paths:
  - "/admin"
rate_limit:
  qps: 5.0
  burst: 10
policy:
  dry_run: true
  redact_evidence: false
"""
        yaml_file = tmp_path / "test_scope.yaml"
        yaml_file.write_text(yaml_content)

        config = ScopeConfig.from_yaml(yaml_file)
        assert config.target == "http://localhost:9001/sse"
        assert config.rate_limit.qps == 5.0
        assert config.policy.dry_run is True
        assert config.policy.redact_evidence is False

    def test_load_from_yaml_not_found(self):
        with pytest.raises(FileNotFoundError):
            ScopeConfig.from_yaml("nonexistent.yaml")

    def test_env_var_expansion(self, tmp_path, monkeypatch):
        # Set environment variable
        monkeypatch.setenv("TEST_API_KEY", "secret123")

        yaml_content = """
target: "http://localhost:9001"
auth:
  type: "api_key"
  api_key: "${TEST_API_KEY}"
"""
        yaml_file = tmp_path / "test_scope.yaml"
        yaml_file.write_text(yaml_content)

        config = ScopeConfig.from_yaml(yaml_file)
        assert config.auth.api_key == "secret123"


class TestRateLimiter:
    """Test RateLimiter (token bucket)."""

    async def test_rate_limiter_basic(self):
        config = RateLimitConfig(qps=10.0, burst=5)  # 10 req/s, burst 5
        limiter = RateLimiter(config)

        # Should be able to consume burst immediately
        for _ in range(5):
            await limiter.acquire()

        # Next request should wait (tokens depleted)
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should wait ~0.1s (1/10 qps)
        assert elapsed >= 0.05  # Allow some jitter

    async def test_rate_limiter_refill(self):
        config = RateLimitConfig(qps=10.0, burst=2)
        limiter = RateLimiter(config)

        # Consume burst
        await limiter.acquire()
        await limiter.acquire()

        # Wait for refill (0.2s = 2 tokens at 10 qps)
        await asyncio.sleep(0.2)

        # Should be able to acquire immediately
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05  # Should be instant

    async def test_rate_limiter_stats(self):
        config = RateLimitConfig(qps=5.0, burst=10)
        limiter = RateLimiter(config)

        stats = limiter.get_stats()
        assert stats["qps"] == 5.0
        assert stats["burst"] == 10
        assert stats["current_tokens"] == 10.0

        # Consume some tokens
        await limiter.acquire(3)
        stats = limiter.get_stats()
        assert stats["current_tokens"] == 7.0


class TestRedactor:
    """Test Redactor (secret masking and payload hashing)."""

    def test_redact_small_payload(self):
        redactor = Redactor(max_payload_kb=1)  # 1KB limit
        data = {"message": "Hello world", "user": "alice"}

        result = redactor.redact_payload(data)
        assert result["redacted"] is True
        assert result["size_bytes"] < 1024
        assert "data" in result
        assert result["data"]["message"] == "Hello world"

    def test_redact_large_payload(self):
        redactor = Redactor(max_payload_kb=1)  # 1KB limit
        large_data = {"data": "x" * 5000}  # ~5KB

        result = redactor.redact_payload(large_data)
        assert result["truncated"] is True
        assert "hash" in result
        assert "snippet" in result
        assert result["size_bytes"] > 1024

    def test_redact_secrets(self):
        redactor = Redactor()

        # Test API key masking (using fake test key pattern)
        text = "API_KEY=test_key_abcdefghijklmnopqrstuvwxyz1234567890"
        redacted = redactor._redact_secrets(text)
        # Should preserve first 4 chars and mask rest
        assert "test" in redacted
        assert "abcdefghijklmnopqrstuvwxyz1234567890" not in redacted
        assert "*" in redacted

        # Test password masking
        text = 'password: "MySecretPass123"'
        redacted = redactor._redact_secrets(text)
        # Should contain first 4 chars and asterisks
        assert "MySe" in redacted
        assert "*" in redacted
        assert redacted != text  # Something was redacted

        # Test bearer token
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        redacted = redactor._redact_secrets(text)
        assert "eyJh" in redacted  # First 4 chars preserved
        assert "*" in redacted

    def test_hash_string(self):
        redactor = Redactor()
        hash1 = redactor.hash_string("test")
        hash2 = redactor.hash_string("test")
        hash3 = redactor.hash_string("different")

        assert hash1 == hash2  # Same input = same hash
        assert hash1 != hash3  # Different input = different hash
        assert len(hash1) == 64  # SHA256 = 64 hex chars


class TestAuditLogger:
    """Test AuditLogger (JSONL with rolling hash)."""

    async def test_audit_logger_basic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path)

            # Log some events
            await logger.log("test_event", {"foo": "bar"})
            await logger.log("another_event", {"baz": 123})

            # Verify file exists
            assert log_path.exists()

            # Read and verify entries
            with open(log_path, "r") as f:
                lines = f.readlines()
                assert len(lines) == 2

                entry1 = json.loads(lines[0])
                assert entry1["type"] == "test_event"
                assert entry1["data"]["foo"] == "bar"
                assert "ts" in entry1

    async def test_audit_logger_rolling_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path)

            await logger.log("event1", {"data": "first"})
            hash1 = logger.get_integrity_hash()

            await logger.log("event2", {"data": "second"})
            hash2 = logger.get_integrity_hash()

            # Hash should change after new entry
            assert hash1 != hash2

    async def test_audit_logger_integrity_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path)

            await logger.log("event", {"data": "test"})

            # Integrity should verify
            assert logger.verify_integrity() is True

            # Tamper with file
            with open(log_path, "a") as f:
                f.write('{"type": "tampered", "data": {}}\n')

            # Integrity should fail
            assert logger.verify_integrity() is False

    async def test_audit_logger_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path)

            await logger.log("event1", {"data": "test"})
            await logger.log("event2", {"data": "test"})

            stats = logger.get_stats()
            assert stats["entry_count"] == 2
            assert stats["log_path"] == str(log_path)
            assert stats["size_bytes"] > 0
            assert "integrity_hash" in stats

    async def test_audit_logger_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"

            # Create logger and add entry
            logger1 = AuditLogger(log_path)
            await logger1.log("event1", {"data": "first"})
            hash1 = logger1.get_integrity_hash()

            # Create new logger instance (should load existing entries)
            logger2 = AuditLogger(log_path)
            assert logger2.entry_count == 1
            assert logger2.get_integrity_hash() == hash1

            # Add another entry
            await logger2.log("event2", {"data": "second"})
            assert logger2.entry_count == 2


class TestHelperFunctions:
    """Test helper functions."""

    def test_load_scope_config(self, tmp_path):
        yaml_content = """
target: "http://localhost:9001"
rate_limit:
  qps: 3.0
"""
        yaml_file = tmp_path / "scope.yaml"
        yaml_file.write_text(yaml_content)

        config = load_scope_config(yaml_file)
        assert isinstance(config, ScopeConfig)
        assert config.rate_limit.qps == 3.0
