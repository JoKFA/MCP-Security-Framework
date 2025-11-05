"""
Policy engine - scope configuration, rate limiting, redaction, and audit logging.

Enforces safety guardrails for non-destructive assessments.
"""

import asyncio
import hashlib
import json
import os
import re
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator


# ============================================================================
# Scope Configuration Models
# ============================================================================

class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""
    qps: float = Field(default=2.0, ge=0.1, le=100.0, description="Queries per second")
    burst: int = Field(default=5, ge=1, le=100, description="Burst capacity")
    backoff_ms: List[int] = Field(
        default_factory=lambda: [200, 400, 800, 1600],
        description="Exponential backoff delays in milliseconds"
    )


class PolicyConfig(BaseModel):
    """Policy settings for assessment behavior."""
    dry_run: bool = Field(default=False, description="Preview mode without execution")
    redact_evidence: bool = Field(default=True, description="Redact sensitive evidence")
    max_payload_kb: int = Field(default=128, ge=1, le=10240, description="Max payload size in KB")
    fail_on_high: bool = Field(default=False, description="Fail on HIGH severity findings")
    max_total_requests: int = Field(default=1000, ge=1, description="Max total requests")
    request_timeout_s: int = Field(default=30, ge=1, le=300, description="Request timeout")


class AuthConfig(BaseModel):
    """Authentication configuration."""
    type: str = Field(default="none", description="Auth type: none, api_key, oauth, mtls")
    api_key: Optional[str] = Field(None, description="API key (or env var reference)")
    header_name: Optional[str] = Field(default="X-API-Key", description="API key header")
    token_url: Optional[str] = Field(None, description="OAuth token URL")
    client_id: Optional[str] = Field(None, description="OAuth client ID")
    client_secret: Optional[str] = Field(None, description="OAuth client secret")

    @field_validator("type")
    @classmethod
    def validate_auth_type(cls, v: str) -> str:
        allowed = {"none", "api_key", "oauth", "mtls"}
        if v not in allowed:
            raise ValueError(f"auth.type must be one of {allowed}")
        return v


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    output_dir: str = Field(default="./reports", description="Output directory")
    formats: List[str] = Field(
        default_factory=lambda: ["json", "sarif", "html"],
        description="Report formats"
    )
    store_evidence: bool = Field(default=True, description="Store evidence files")
    evidence_retention_days: int = Field(default=30, ge=1, description="Evidence retention")

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, v: List[str]) -> List[str]:
        allowed = {"json", "sarif", "html", "pdf"}
        invalid = set(v) - allowed
        if invalid:
            raise ValueError(f"Invalid formats: {invalid}. Allowed: {allowed}")
        return v


class ScopeConfig(BaseModel):
    """
    Complete scope configuration.

    Loaded from scope.yaml and validated.
    """
    target: str = Field(..., description="Target URL or stdio command")
    transport: Optional[str] = Field(None, description="Transport type (auto-detected if None)")
    mode: Literal["safe", "balanced", "aggressive"] = Field(
        default="balanced",
        description="Assessment intensity. Controls detector behavior and active probing."
    )

    allowed_prefixes: List[str] = Field(
        default_factory=lambda: ["internal://", "file://", "/resources", "/tools/"],
        description="Allowed resource/tool prefixes"
    )
    blocked_paths: List[str] = Field(
        default_factory=lambda: ["/admin", "/system"],
        description="Blocked paths (takes precedence)"
    )

    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    detectors: Optional[Dict[str, List[str]]] = Field(
        None,
        description="Detector selection (include/exclude lists)"
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata (project, environment, tags)"
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        if not v:
            raise ValueError("target is required")
        # Basic validation - must be URL or stdio://
        if not (v.startswith("http://") or v.startswith("https://") or v.startswith("stdio://")):
            raise ValueError("target must start with http://, https://, or stdio://")
        return v

    def is_path_allowed(self, path: str) -> bool:
        """
        Check if a path is allowed by scope rules.

        Args:
            path: Resource URI or tool name

        Returns:
            True if path is allowed, False otherwise

        Logic:
            1. If path matches any blocked_paths → False
            2. If path matches any allowed_prefixes → True
            3. Otherwise → False (default deny)
        """
        # Check blocked list first (takes precedence)
        for blocked in self.blocked_paths:
            if path.startswith(blocked):
                return False

        # Check allowed list
        for allowed in self.allowed_prefixes:
            if path.startswith(allowed):
                return True

        # Default deny
        return False

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "ScopeConfig":
        """
        Load scope configuration from YAML file.

        Args:
            path: Path to scope.yaml

        Returns:
            ScopeConfig instance

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If YAML is invalid or validation fails
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Expand environment variables in auth config
        if "auth" in data:
            auth = data["auth"]
            if "api_key" in auth and auth["api_key"]:
                auth["api_key"] = cls._expand_env_var(auth["api_key"])
            if "client_id" in auth and auth["client_id"]:
                auth["client_id"] = cls._expand_env_var(auth["client_id"])
            if "client_secret" in auth and auth["client_secret"]:
                auth["client_secret"] = cls._expand_env_var(auth["client_secret"])

        return cls(**data)

    @classmethod
    def load_from_yaml(cls, path: Union[str, Path]) -> "ScopeConfig":
        """Backwards-compatible alias for from_yaml()."""
        return cls.from_yaml(path)

    @staticmethod
    def _expand_env_var(value: str) -> str:
        """Expand ${VAR} or $VAR environment variable references."""
        if not value:
            return value

        # Match ${VAR} or $VAR
        pattern = r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)"

        def replacer(match):
            var_name = match.group(1) or match.group(2)
            return os.environ.get(var_name, "")

        return re.sub(pattern, replacer, value)


# ============================================================================
# Rate Limiter (Token Bucket Algorithm)
# ============================================================================

class RateLimiter:
    """
    Token bucket rate limiter.

    Enforces QPS limits with burst capacity and exponential backoff.
    """

    def __init__(self, config: RateLimitConfig):
        self.qps = config.qps
        self.burst = config.burst
        self.backoff_delays = config.backoff_ms

        # Token bucket state
        self.tokens = float(self.burst)
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()

        # Backoff state
        self.backoff_index = 0

    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens (wait if needed).

        Args:
            tokens: Number of tokens to acquire (default: 1)

        Blocks until tokens are available.
        """
        async with self.lock:
            while True:
                # Refill tokens based on elapsed time
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens = min(self.burst, self.tokens + elapsed * self.qps)
                self.last_update = now

                # If enough tokens available, consume and return
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    self.backoff_index = 0  # Reset backoff on success
                    return

                # Not enough tokens - wait with backoff
                if self.backoff_index < len(self.backoff_delays):
                    delay_ms = self.backoff_delays[self.backoff_index]
                    self.backoff_index += 1
                else:
                    # Max backoff reached, use last delay
                    delay_ms = self.backoff_delays[-1]

                await asyncio.sleep(delay_ms / 1000.0)

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            "qps": self.qps,
            "burst": self.burst,
            "current_tokens": round(self.tokens, 2),
            "backoff_level": self.backoff_index,
        }


# ============================================================================
# Evidence Redactor
# ============================================================================

class Redactor:
    """
    Redacts sensitive data from evidence.

    Strategies:
    - Hash large payloads (> max_payload_kb)
    - Mask secret-like patterns (API keys, tokens, passwords)
    - Truncate long strings with snippet + hash
    """

    # Secret patterns (compiled with IGNORECASE flag)
    SECRET_PATTERNS = [
        r"(api[_-]?key|apikey)[\s:=\"']+([a-zA-Z0-9_\-]{20,})",
        r"(token|access[_-]?token)[\s:=\"']+([a-zA-Z0-9_\-\.]{20,})",
        r"(password|passwd|pwd)[\s:=\"']+([^\s\"']{8,})",
        r"(secret|secret[_-]?key)[\s:=\"']+([a-zA-Z0-9_\-]{20,})",
        r"(bearer)\s+([a-zA-Z0-9_\-\.]{20,})",
    ]

    def __init__(self, max_payload_kb: int = 128):
        self.max_payload_bytes = max_payload_kb * 1024
        # Compile with IGNORECASE flag
        self.secret_regex = re.compile("|".join(self.SECRET_PATTERNS), re.IGNORECASE)

    def redact_payload(self, data: Any, context: str = "") -> Dict[str, Any]:
        """
        Redact a payload (request/response body).

        Args:
            data: Payload data (dict, list, str, etc.)
            context: Context string (e.g., "request", "response")

        Returns:
            Dict with redacted data or hash
        """
        # Serialize to JSON to measure size
        try:
            json_str = json.dumps(data, default=str)
        except (TypeError, ValueError):
            json_str = str(data)

        size_bytes = len(json_str.encode("utf-8"))

        # If small enough, redact secrets and return
        if size_bytes <= self.max_payload_bytes:
            redacted = self._redact_secrets(json_str)
            return {
                "data": json.loads(redacted) if isinstance(data, (dict, list)) else redacted,
                "size_bytes": size_bytes,
                "redacted": True,
            }

        # Too large - return hash + snippet
        hash_value = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
        snippet = json_str[:500] + "..." if len(json_str) > 500 else json_str

        return {
            "hash": hash_value,
            "size_bytes": size_bytes,
            "snippet": self._redact_secrets(snippet),
            "truncated": True,
        }

    def _redact_secrets(self, text: str) -> str:
        """Mask secret-like patterns in text."""
        def mask_match(match):
            # Find which group matched
            for i, group in enumerate(match.groups()):
                if group and i % 2 == 1:  # Secret value groups are odd indices
                    # Mask all but first 4 chars
                    if len(group) > 4:
                        return match.group(0).replace(group, group[:4] + "*" * (len(group) - 4))
            return match.group(0)

        return self.secret_regex.sub(mask_match, text)

    def hash_string(self, text: str) -> str:
        """Generate SHA256 hash of text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ============================================================================
# Audit Logger (JSONL with Rolling Hash)
# ============================================================================

class AuditLogger:
    """
    Append-only audit log in JSONL format.

    Features:
    - One JSON object per line
    - Rolling hash for integrity verification
    - Thread-safe writes
    - Timestamped entries
    """

    def __init__(self, log_path: Union[str, Path]):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.lock = asyncio.Lock()
        self.entry_count = 0
        self.rolling_hash = hashlib.sha256()

        # If file exists, compute initial rolling hash
        if self.log_path.exists():
            self._compute_initial_hash()

    def _compute_initial_hash(self) -> None:
        """Compute rolling hash of existing log entries."""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                self.rolling_hash.update(line.strip().encode("utf-8"))
                self.entry_count += 1

    async def log(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Append an entry to the audit log.

        Args:
            event_type: Event type (e.g., "request", "response", "error")
            data: Event data (must be JSON-serializable)
        """
        entry = {
            "type": event_type,
            "ts": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }

        json_line = json.dumps(entry, default=str)

        async with self.lock:
            # Append to file
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json_line + "\n")

            # Update rolling hash
            self.rolling_hash.update(json_line.encode("utf-8"))
            self.entry_count += 1

    def get_integrity_hash(self) -> str:
        """Get current rolling hash for integrity verification."""
        return self.rolling_hash.hexdigest()

    def get_stats(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        return {
            "log_path": str(self.log_path),
            "entry_count": self.entry_count,
            "integrity_hash": self.get_integrity_hash(),
            "size_bytes": self.log_path.stat().st_size if self.log_path.exists() else 0,
        }

    def verify_integrity(self) -> bool:
        """
        Verify log integrity by recomputing hash.

        Returns:
            True if hash matches, False otherwise
        """
        if not self.log_path.exists():
            return True

        computed_hash = hashlib.sha256()
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    computed_hash.update(line.strip().encode("utf-8"))
        except Exception:
            return False

        return computed_hash.hexdigest() == self.get_integrity_hash()


# ============================================================================
# Helper Functions
# ============================================================================

def load_scope_config(path: Union[str, Path]) -> ScopeConfig:
    """
    Load and validate scope configuration.

    Args:
        path: Path to scope.yaml

    Returns:
        Validated ScopeConfig instance
    """
    return ScopeConfig.from_yaml(path)
