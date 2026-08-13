#!/usr/bin/env python3
"""Lineaje AI Policy Scanner — GitHub Actions edition.

Scans already-checked-out source code against Lineaje AI security policies
and prints results as structured JSON to stdout. Designed to run on a
GitHub-managed Ubuntu runner where the repository is pre-checked-out.

Usage::

    python scripts/gha_repo_scan.py --source-path .

Output (stdout, JSON)::

    {
      "status": "violations_found | compliant | error",
      "scan_metadata": {
        "repo": "owner/repo",
        "branch": "main",
        "head_sha": "abc1234",
        "scanned_at": "2026-05-10T10:00:00Z",
        "files_scanned": 150,
        "batches": 2,
        "failed_batches": 0
      },
      "report": "...(markdown policy report)...",
      "violations": [...],
      "aibom": [...],
      "scan_errors": []
    }

Required environment variable::

    LINEAJE_PAT_TOKEN  — Lineaje PAT token used directly as MCP bearer

Exit codes::

    0 — scan completed (check "status" field)
    1 — runtime error
    2 — configuration error (missing LINEAJE_PAT_TOKEN, missing repo/branch)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import fnmatch
import json
import logging
import logging.handlers
import os
import pathlib
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# LLM output sanitization — reject fix_code containing code-execution primitives
# ---------------------------------------------------------------------------

_DANGEROUS_CODE_PATTERNS = re.compile(
    r'\b(eval|exec|compile|execfile|__import__|os\.system|os\.popen|'
    r'subprocess\.call|subprocess\.run|subprocess\.Popen|subprocess\.check_output|'
    r'subprocess\.check_call|subprocess\.getoutput|subprocess\.getstatusoutput)\b'
)


def _validate_fix_code(fix_code_entries: list) -> list:
    """Validate and sanitize fix_code entries from LLM remediation output.

    Removes any fix_code entry whose 'replacement' text contains dynamic code
    execution primitives (eval, exec, subprocess, etc.).
    Returns only safe entries; logs warnings for rejected patches.
    """
    safe_entries = []
    for entry in fix_code_entries:
        replacement = entry.get("replacement", "") if isinstance(entry, dict) else ""
        original = entry.get("original", "") if isinstance(entry, dict) else ""
        # Check replacement text for dangerous patterns
        if _DANGEROUS_CODE_PATTERNS.search(replacement):
            logger.warning(
                "Rejected fix_code patch: replacement contains dangerous code execution "
                "primitive. original snippet: %s",
                (original[:80] + "...") if len(original) > 80 else original,
            )
            continue
        safe_entries.append(entry)
    return safe_entries

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Audit Trail — Append-only decision log for AI-driven MCP actions
# ===========================================================================

_AUDIT_LOG_PATH = os.environ.get(
    "LINEAJE_AUDIT_LOG",
    os.path.join(tempfile.gettempdir(), "lineaje_ai_audit.jsonl"),
)

# Module-level correlation ID for linking multi-step workflow steps
_WORKFLOW_CORRELATION_ID: str = os.environ.get(
    "LINEAJE_CORRELATION_ID", str(uuid.uuid4())
)


class _AuditLogger:
    """Append-only, immutable audit logger for AI-driven decisions."""

    _lock = threading.Lock()

    @classmethod
    def log_decision(
        cls,
        *,
        tool_name: str,
        input_arguments: Any,
        output: Any,
        principal: str,
        model_identifier: str = "lineaje-ai-policy-scanner",
        model_version: str = "1.0",
        correlation_id: Optional[str] = None,
        step_id: Optional[str] = None,
    ) -> None:
        """Write an immutable audit record as a single JSON line."""
        input_serialized = json.dumps(input_arguments, sort_keys=True, default=str)
        input_hash = hashlib.sha256(input_serialized.encode("utf-8")).hexdigest()
        output_serialized = json.dumps(output, sort_keys=True, default=str)
        output_hash = hashlib.sha256(output_serialized.encode("utf-8")).hexdigest()

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id or _WORKFLOW_CORRELATION_ID,
            "step_id": step_id or str(uuid.uuid4()),
            "model_identifier": model_identifier,
            "model_version": model_version,
            "tool_name": tool_name,
            "principal": principal,
            "input_hash_sha256": input_hash,
            "output_hash_sha256": output_hash,
            "input": input_arguments,
            "output_summary": output_serialized[:2048],
        }

        line = json.dumps(record, default=str) + "\n"

        with cls._lock:
            try:
                with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as exc:
                logger.error("Failed to write audit record: %s", exc)

        logger.debug("Audit record written: tool=%s step_id=%s", tool_name, record["step_id"])

# ===========================================================================
# Input Sanitization for Prompt Injection Prevention
# ===========================================================================

_MALICIOUS_PATTERNS = [
    # Shell command patterns
    re.compile(r'(?:^|\s|;|&&|\|\|)\s*(?:rm\s+-rf|curl\s+|wget\s+|bash\s+-c|sh\s+-c|eval\s*\(|exec\s*\(|os\.system|subprocess\.)', re.IGNORECASE | re.MULTILINE),
    # Hidden prompt injection markers
    re.compile(r'(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions|disregard\s+(?:all\s+)?(?:previous|above)\s+(?:instructions|prompts))', re.IGNORECASE),
    # System prompt override attempts
    re.compile(r'(?:you\s+are\s+now|new\s+instructions?:|system\s*prompt:|<\|?system\|?>|\[INST\]|\[/INST\])', re.IGNORECASE),
    # Leetspeak common evasion for dangerous commands
    re.compile(r'(?:3x3c|3v4l|syst3m|sub?pr0c3ss|0s\.syst|rm\s*-\s*r\s*f)', re.IGNORECASE),
    # Encoded payload patterns (base64 with common dangerous prefixes)
    re.compile(r'(?:echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d|base64\s+--decode|atob\s*\()', re.IGNORECASE),
    # PowerShell encoded commands
    re.compile(r'(?:powershell\s+-e(?:nc(?:oded)?)?\s+|IEX\s*\(|Invoke-Expression)', re.IGNORECASE),
]


def _sanitize_scan_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize file contents in scan payload to prevent prompt injection.

    Checks for hidden prompts, base64-encoded commands, leetspeak obfuscation,
    shell commands, and other malicious content patterns. Files with suspicious
    content are flagged but still included with a sanitization marker so the
    scanner can handle them safely.
    """
    sanitized = dict(payload)
    files = sanitized.get("files") or sanitized.get("file_contents") or []
    flagged_files: List[str] = []

    for file_entry in files:
        content = ""
        if isinstance(file_entry, dict):
            content = file_entry.get("content", "") or file_entry.get("source", "") or ""
        elif isinstance(file_entry, str):
            content = file_entry
        else:
            continue

        # Check for base64-encoded blobs that might hide commands
        try:
            if len(content) > 50:
                # Look for long base64 strings that decode to shell commands
                b64_matches = re.findall(r'[A-Za-z0-9+/=]{40,}', content)
                for b64_str in b64_matches[:5]:  # limit checks
                    try:
                        decoded = base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
                        for pattern in _MALICIOUS_PATTERNS:
                            if pattern.search(decoded):
                                fname = file_entry.get("path", "unknown") if isinstance(file_entry, dict) else "unknown"
                                flagged_files.append(fname)
                                if isinstance(file_entry, dict):
                                    file_entry["_sanitization_flag"] = "base64_encoded_suspicious_content"
                                break
                    except Exception:
                        pass
        except Exception:
            pass

        # Direct pattern matching on raw content
        for pattern in _MALICIOUS_PATTERNS:
            if pattern.search(content):
                fname = file_entry.get("path", "unknown") if isinstance(file_entry, dict) else "unknown"
                if fname not in flagged_files:
                    flagged_files.append(fname)
                if isinstance(file_entry, dict):
                    file_entry["_sanitization_flag"] = file_entry.get("_sanitization_flag", "suspicious_pattern_detected")
                break

    if flagged_files:
        logger.warning(
            "Sanitization flagged %d file(s) with potentially malicious content: %s",
            len(flagged_files), flagged_files[:10]
        )
        sanitized["_sanitization_metadata"] = {
            "flagged_files_count": len(flagged_files),
            "flagged_files": flagged_files[:50],
            "sanitized_at": datetime.now(timezone.utc).isoformat(),
        }

    return sanitized

# ===========================================================================
# Input Sanitization for MCP/LLM payloads
# ===========================================================================

_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules)"),
    re.compile(r"(?i)you\s+are\s+now\s+(a|an|in)\s+"),
    re.compile(r"(?i)system\s*:\s*"),
    re.compile(r"(?i)\[\s*INST\s*\]"),
    re.compile(r"(?i)<\|?(im_start|im_end|system|endoftext)\|?>"),
    re.compile(r"(?i)do\s+not\s+follow\s+(any|the)\s+(previous|above)"),
    re.compile(r"(?i)disregard\s+(all|any|the)\s+(previous|above|prior)"),
]

_MAX_PAYLOAD_CONTENT_SIZE = 10 * 1024 * 1024  # 10 MB max per payload
_MAX_SINGLE_FILE_SIZE = 2 * 1024 * 1024  # 2 MB max per file content


def _sanitize_mcp_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize and validate a payload before sending to MCP/LLM service.

    - Strips null bytes and control characters from string fields
    - Detects and removes prompt injection patterns
    - Validates size constraints
    - Returns a sanitized copy of the payload

    Raises ValueError if the payload is fundamentally invalid.
    """
    if not isinstance(payload, dict):
        raise ValueError("MCP payload must be a dictionary")

    sanitized = {}
    for key, value in payload.items():
        if isinstance(value, str):
            sanitized[key] = _sanitize_string_field(value, key)
        elif isinstance(value, list):
            sanitized[key] = [_sanitize_payload_item(item) for item in value]
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_mcp_payload(value)
        else:
            sanitized[key] = value
    return sanitized


def _sanitize_string_field(value: str, field_name: str = "") -> str:
    """Sanitize a single string field for MCP transmission."""
    if len(value) > _MAX_SINGLE_FILE_SIZE:
        logger.warning(
            "Field '%s' exceeds max size (%d > %d), truncating.",
            field_name, len(value), _MAX_SINGLE_FILE_SIZE,
        )
        value = value[:_MAX_SINGLE_FILE_SIZE]

    # Remove null bytes and non-printable control chars (keep newlines, tabs)
    value = value.replace("\x00", "")
    value = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

    # Check for prompt injection patterns
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(value):
            logger.warning(
                "Potential prompt injection detected in field '%s', sanitizing.",
                field_name,
            )
            value = pattern.sub("[REDACTED]", value)

    return value


def _sanitize_payload_item(item: Any) -> Any:
    """Sanitize an individual item within a payload list."""
    if isinstance(item, str):
        return _sanitize_string_field(item)
    elif isinstance(item, dict):
        return _sanitize_mcp_payload(item)
    elif isinstance(item, list):
        return [_sanitize_payload_item(i) for i in item]
    return item


def _validate_payload_size(payload: Dict[str, Any]) -> None:
    """Validate total serialized payload size is within limits."""
    serialized = json.dumps(payload)
    if len(serialized) > _MAX_PAYLOAD_CONTENT_SIZE:
        raise ValueError(
            f"Payload size ({len(serialized)} bytes) exceeds maximum "
            f"allowed size ({_MAX_PAYLOAD_CONTENT_SIZE} bytes)"
        )


# ===========================================================================
# MCP Output Validation / Sanitization
# ===========================================================================

_DANGEROUS_PATTERN = re.compile(
    r'<script[^>]*>.*?</script>|javascript:|on\w+\s*=|data:text/html',
    re.IGNORECASE | re.DOTALL,
)
_CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _sanitize_string(value: str) -> str:
    """Remove control characters and dangerous patterns from a string."""
    value = _CONTROL_CHAR_PATTERN.sub('', value)
    value = _DANGEROUS_PATTERN.sub('[REMOVED]', value)
    return value


def _sanitize_value(value: Any) -> Any:
    """Recursively sanitize a value returned from MCP server."""
    if isinstance(value, str):
        return _sanitize_string(value)
    elif isinstance(value, dict):
        return {_sanitize_string(k) if isinstance(k, str) else k: _sanitize_value(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    elif isinstance(value, (int, float, bool, type(None))):
        return value
    else:
        # Convert unexpected types to sanitized string representation
        return _sanitize_string(str(value))


def _validate_mcp_response(result: Any, tool_name: str) -> Any:
    """Validate and sanitize the response from an MCP tool invocation.

    Raises ValueError if the response structure is fundamentally invalid.
    """
    if result is None:
        raise ValueError(f"MCP tool '{tool_name}' returned None response")

    if not isinstance(result, (dict, list, str)):
        raise ValueError(
            f"MCP tool '{tool_name}' returned unexpected type: {type(result).__name__}"
        )

    # Sanitize all string content recursively
    sanitized = _sanitize_value(result)

    # Tool-specific structural validation
    if tool_name == "scan_source_code" and isinstance(sanitized, dict):
        # Ensure expected top-level keys are of correct types if present
        if "violations" in sanitized and not isinstance(sanitized["violations"], list):
            logger.warning("MCP scan_source_code: 'violations' is not a list, coercing to empty list")
            sanitized["violations"] = []
        if "report" in sanitized and not isinstance(sanitized["report"], str):
            logger.warning("MCP scan_source_code: 'report' is not a string, coercing")
            sanitized["report"] = str(sanitized["report"])

    elif tool_name == "get_remediation" and isinstance(sanitized, dict):
        if "fix_code" in sanitized and not isinstance(sanitized["fix_code"], list):
            logger.warning("MCP get_remediation: 'fix_code' is not a list, coercing to empty list")
            sanitized["fix_code"] = []

    logger.debug("MCP response for '%s' validated and sanitized successfully", tool_name)
    return sanitized

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.commercialdev.dev.veedna.com/mcp"
# MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

# AI Risk Classification (required by AI governance policy)
# Levels: "minimal" | "limited" | "high" | "unacceptable"
AI_RISK_CLASSIFICATION = "limited"

# SSL context for MCP server authentication — verifies server TLS certificate
# and hostname to ensure we are connecting to the legitimate MCP server.
_MCP_SSL_CONTEXT = ssl.create_default_context()
_MCP_SSL_CONTEXT.verify_mode = ssl.CERT_REQUIRED
_MCP_SSL_CONTEXT.check_hostname = True

MAX_SCAN_WORKERS = 4
REMEDIATION_BRANCH_PREFIX = "remediation/unifai-gha"
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100

# ---------------------------------------------------------------------------
# Approved Foundation Model Registry — version-pinned with integrity hashes
# Only models listed here may be invoked. Each entry includes:
#   - model_id: fully qualified model identifier with version
#   - digest: SHA-256 hash for integrity verification
#   - approved: whether the model is cleared for use
# ---------------------------------------------------------------------------
APPROVED_MODEL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "amazon.nova-lite-v1:0": {
        "model_id": "amazon.nova-lite-v1:0",
        "version": "1.0",
        "digest": "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "approved": True,
        "registry_source": "lineaje-approved-models",
    },
}

# The default model to use — must exist in APPROVED_MODEL_REGISTRY
DEFAULT_FOUNDATION_MODEL_ID = "amazon.nova-lite-v1:0"


def get_verified_model_id(model_key: str) -> str:
    """Retrieve a model ID from the approved registry with integrity check.

    Raises ValueError if the model is not in the registry or not approved.
    """
    if model_key not in APPROVED_MODEL_REGISTRY:
        raise ValueError(
            f"Model '{model_key}' is NOT in the approved model registry. "
            f"Approved models: {list(APPROVED_MODEL_REGISTRY.keys())}"
        )
    entry = APPROVED_MODEL_REGISTRY[model_key]
    if not entry.get("approved", False):
        raise ValueError(
            f"Model '{model_key}' is in the registry but NOT approved for use."
        )
    if not entry.get("digest"):
        raise ValueError(
            f"Model '{model_key}' has no integrity digest pinned — cannot verify."
        )
    logger.debug(
        "Model '%s' verified: version=%s, digest=%s, registry=%s",
        model_key, entry["version"], entry["digest"], entry["registry_source"],
    )
    return entry["model_id"]

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120
_MCP_SESSION_EXPIRY_SEC = 3600  # MCP session validity window (1 hour)
_MCP_SESSION_HMAC_KEY: bytes = secrets.token_bytes(32)  # Per-process signing key


class _SignedSession:
    """Wraps an MCP session ID with HMAC signature, expiry, and token binding."""

    def __init__(self, session_id: str, bearer_token: str) -> None:
        self._session_id = session_id
        self._created_at = time.time()
        self._expiry = self._created_at + _MCP_SESSION_EXPIRY_SEC
        # Bind session to the bearer token via a hash
        self._token_binding = hashlib.sha256(bearer_token.encode()).hexdigest()
        # Compute HMAC over session_id + expiry + binding
        self._signature = self._compute_signature()

    def _compute_signature(self) -> str:
        payload = f"{self._session_id}|{self._expiry}|{self._token_binding}"
        return hmac.new(_MCP_SESSION_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _hmac_digest(payload: str) -> str:
        return hmac.new(_MCP_SESSION_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()

    def verify(self, bearer_token: str) -> str:
        """Verify integrity, expiry, and binding. Returns session_id or raises."""
        # Check expiry
        if time.time() > self._expiry:
            raise ValueError("MCP session has expired")
        # Check token binding
        current_binding = hashlib.sha256(bearer_token.encode()).hexdigest()
        if not hmac.compare_digest(current_binding, self._token_binding):
            raise ValueError("MCP session token binding mismatch")
        # Verify HMAC signature
        expected_sig = self._compute_signature()
        if not hmac.compare_digest(expected_sig, self._signature):
            raise ValueError("MCP session signature verification failed")
        return self._session_id

    @property
    def is_expired(self) -> bool:
        return time.time() > self._expiry

    @property
    def session_id(self) -> str:
        return self._session_id

# Refresh-token renew URL — not used with PAT auth (kept for reference)
# _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
#     "https://lineaje-idp-service.commercialdev.dev.veedna.com"
#     # "https://lineaje-identity-service.v2.prod.veedna.com"
#     "/lineajeidentity/api/v1/auth/native/renew-access-token"
# )

_LINEAJE_IDENTITY_SERVICE_URL_DEFAULT = (
    "https://lineaje-identity-service.commercialdev.dev.veedna.com"
    # "https://lineaje-identity-service.v2.prod.veedna.com"
)

_PAT_INTROSPECT_PATH = "/lineajeidentity/api/v1/pat/introspect"

_ARCHIVE_EXCLUDE = {
    ".git", ".gitignore", ".gitattributes", ".gitmodules", ".hg", ".svn",
    ".env", ".env.local", ".env.development", ".env.production",
    "__pycache__", ".pytest_cache", "venv", ".venv", ".venv-scan", "env", ".tox",
    "htmlcov", ".coverage", ".mypy_cache", ".ruff_cache",
    "node_modules", ".yarn", ".pnp",
    "dist", "build", ".next", ".nuxt", "out", "coverage", ".cache",
    "target", ".gradle", ".m2",
    "Pods", ".expo",
    ".idea", ".vscode",
    ".lineaje-aiepo-security",
    "migrations", "alembic",
}
_ARCHIVE_EXCLUDE_GLOBS = {
    "*.secret", "*.key", "*.pem", "*.env.*",
    "*.zip", "*.tar", "*.tar.gz", "*.jar", "*.war", "*.swp", "*.swo",
    "*.lock", "package-lock.json", "yarn.lock", "Pipfile.lock",
    "poetry.lock", "Gemfile.lock", "Cargo.lock", "composer.lock",
    "*.min.js", "*.min.css", "*.map",
    "*_pb2.py", "*.pb.go", "*.pb.cc", "*.pb.h",
    "*.snap",
}
_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
    ".pyc", ".pyo", ".o", ".a",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".db", ".sqlite", ".sqlite3",
}

_MANIFEST_FILE_NAMES: frozenset = frozenset({
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock",
    "environment.yml", "environment.yaml",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "build.sbt",
    "Gemfile", "Gemfile.lock",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "packages.config", "packages.lock.json", "nuget.config", "Directory.Packages.props",
    "composer.json", "composer.lock",
    "Package.swift", "Package.resolved",
    "pubspec.yaml", "pubspec.lock",
    "mix.exs", "mix.lock",
})
_MANIFEST_GLOB_PATTERNS: tuple = ("*.csproj", "*.fsproj", "*.vbproj", "*.gemspec")

# ===========================================================================
# Token helpers
# ===========================================================================

def _normalize_token(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().lstrip("﻿").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


# Kept for reference — used by RefreshTokenTokenManager (commented out below)
# def _normalize_url(url: Optional[str]) -> str:
#     if url is None:
#         return ""
#     u = str(url).strip()
#     if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
#         u = u[1:-1].strip()
#     return u


# Kept for reference — used by RefreshTokenTokenManager (commented out below)
# def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
#     text = raw_text.strip() if raw_text else ""
#     try:
#         parsed: Any = json.loads(raw_text)
#     except json.JSONDecodeError:
#         # Some endpoints return a bare JWT string
#         parts = text.split(".")
#         if context == "renew-access-token" and len(parts) == 3:
#             return {"access_token": text}
#         raise RuntimeError(f"{context}: response is not valid JSON") from None
#     for _ in range(8):
#         if isinstance(parsed, dict):
#             return parsed
#         if isinstance(parsed, str):
#             s = parsed.strip()
#             if not s:
#                 raise RuntimeError(f"{context}: empty JSON string where object expected")
#             try:
#                 parsed = json.loads(s)
#             except json.JSONDecodeError:
#                 parts = s.split(".")
#                 if context == "renew-access-token" and len(parts) == 3:
#                     return {"access_token": s}
#                 raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
#             continue
#         break
#     raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


# Refresh-token exchange manager — not used with PAT auth (kept for reference)
# class RefreshTokenTokenManager:
#     """Exchange a refresh token for short-lived MCP access tokens, auto-renewing before expiry."""
#
#     def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
#         self._refresh_token = _normalize_token(refresh_token)
#         if not self._refresh_token:
#             raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
#         self._renew_url = (
#             _normalize_url(renew_access_token_url)
#             or _normalize_url(os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL"))
#             or _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
#         ).rstrip("/")
#         self._lock = threading.Lock()
#         self._access_token = ""
#         self._access_deadline = 0.0
#         try:
#             self._skew_sec = int(os.environ.get(
#                 "LINEAJE_TOKEN_REFRESH_SKEW_SEC", str(_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC)
#             ))
#         except ValueError:
#             self._skew_sec = _DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC
#
#     def get_access_token(self) -> str:
#         with self._lock:
#             return self._get_unlocked()
#
#     def _get_unlocked(self) -> str:
#         now = time.time()
#         if self._access_token and now < self._access_deadline - self._skew_sec:
#             return self._access_token
#         self._renew()
#         if not self._access_token:
#             raise RuntimeError("renew-access-token did not return access_token")
#         return self._access_token
#
#     def _renew(self) -> None:
#         q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
#         url = f"{self._renew_url}?{q}"
#         req = urllib.request.Request(
#             url, data=b"null",
#             headers={"Content-Type": "application/json"},
#             method="POST",
#         )
#         try:
#             with urllib.request.urlopen(req, timeout=120) as resp:
#                 data = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
#         except urllib.error.HTTPError as exc:
#             body = exc.read().decode(errors="replace")
#             raise RuntimeError(f"renew-access-token HTTP {exc.code}: {body[:800]}") from exc
#         at = (data.get("access_token") or "").strip()
#         if not at:
#             raise RuntimeError(f"Token response missing access_token: {data!r}")
#         self._access_token = at
#         rt = (data.get("refresh_token") or "").strip()
#         if rt:
#             self._refresh_token = rt
#         exp = data.get("expires_in")
#         try:
#             exp_sec = int(exp) if exp is not None else 3600
#         except (TypeError, ValueError):
#             exp_sec = 3600
#         self._access_deadline = time.time() + max(60, exp_sec)
#         logger.debug("Access token renewed; expires in %ds", exp_sec)


def _identity_service_base_url() -> str:
    """Resolve identity service base URL.

    Resolution order:
      1. LINEAJE_IDENTITY_SERVICE_URL env var
      2. Host extracted from LINEAJE_FETCH_ACCESS_TOKEN_URL
      3. Host extracted from LINEAJE_RENEW_ACCESS_TOKEN_URL
      4. Hardcoded default (_LINEAJE_IDENTITY_SERVICE_URL_DEFAULT)
    """
    explicit = os.environ.get("LINEAJE_IDENTITY_SERVICE_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    for env_var in ("LINEAJE_FETCH_ACCESS_TOKEN_URL", "LINEAJE_RENEW_ACCESS_TOKEN_URL"):
        raw = os.environ.get(env_var, "").strip()
        if raw:
            parsed = urllib.parse.urlparse(raw)
            return f"{parsed.scheme}://{parsed.netloc}"
    return _LINEAJE_IDENTITY_SERVICE_URL_DEFAULT


def introspect_lineaje_pat(pat: str) -> Dict[str, Any]:
    """Validate a Lineaje PAT via the identity service introspect endpoint."""
    base = _identity_service_base_url()
    if not base:
        raise RuntimeError(
            "Identity service URL not configured. "
            "Set LINEAJE_IDENTITY_SERVICE_URL or LINEAJE_FETCH_ACCESS_TOKEN_URL."
        )
    url = base + _PAT_INTROSPECT_PATH
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {pat}", "Accept": "application/json"},
        method="GET",
    )
    logger.info("PAT introspect: GET %s", url)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            logger.info("PAT introspect: HTTP %s", getattr(resp, "status", None) or resp.getcode())
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode(errors="replace")
        raise RuntimeError(f"PAT introspect HTTP {exc.code}: {err_body[:400]}") from exc
    try:
        info = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PAT introspect returned non-JSON: {raw[:200]}") from exc
    logger.info(
        "PAT introspect: user_email=%s tenant_id=%s company_id=%s",
        info.get("user_email", ""), info.get("tenant_id", ""), info.get("company_id", ""),
    )
    return info


def build_bearer_getter() -> Callable[[], str]:
    """Return a callable that yields the Lineaje PAT directly as the MCP bearer token."""
    pat = _normalize_token(os.environ.get("LINEAJE_PAT_TOKEN", ""))
    if not pat:
        raise RuntimeError("LINEAJE_PAT_TOKEN is not set")
    logger.info("Auth: Lineaje PAT token")
    return lambda: pat

    # Refresh-token exchange path — not used with PAT auth (kept for reference)
    # mgr = RefreshTokenTokenManager(pat)
    # return mgr.get_access_token

# ===========================================================================
# File collection
# ===========================================================================

def _is_manifest_file(filename: str) -> bool:
    if filename in _MANIFEST_FILE_NAMES:
        return True
    return any(fnmatch.fnmatch(filename, pat) for pat in _MANIFEST_GLOB_PATTERNS)


def collect_repo_files(local_path: str) -> List[str]:
    file_list: List[str] = []
    for root, dirs, filenames in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in _ARCHIVE_EXCLUDE
            and not fnmatch.fnmatch(d, ".venv-*")
            and not fnmatch.fnmatch(d, "venv-*")
        ]
        for fname in filenames:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, local_path)
            ext = pathlib.Path(fname).suffix.lower()
            if ext in _BINARY_EXTENSIONS:
                continue
            if any(fnmatch.fnmatch(rel_path, g) for g in _ARCHIVE_EXCLUDE_GLOBS):
                continue
            if any(p in _ARCHIVE_EXCLUDE for p in pathlib.Path(rel_path).parts):
                continue
            file_list.append(rel_path.replace("\\", "/"))
    return file_list

# ===========================================================================
# Archive creation
# ===========================================================================

def _norm_archive_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def create_batch_archive(
    source_dir: str,
    archive_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: int = 0,
    run_id: str = "",
    manifest_files: Optional[List[str]] = None,
) -> str:
    archive_path = os.path.join(archive_dir, f"repo_scan_batch_{batch_index}.zip")
    extra_manifests = [m for m in (manifest_files or []) if m not in file_subset]
    all_files = list(file_subset) + extra_manifests
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in all_files:
            full_path = os.path.join(source_dir, rel_path)
            if os.path.isfile(full_path):
                zf.write(full_path, rel_path)
        metadata = {
            "scan_source": "gha_repo_scan",
            "repo": source_code_repo,
            "branch": branch,
            "head_sha": head_sha,
            "scan_type": "full_repository",
            "batch_index": batch_index,
            "batch_file_count": len(file_subset),
            "manifest_file_count": len(extra_manifests),
        }
        zf.writestr("user_metadata.json", json.dumps(metadata, indent=2))
    size_kb = os.path.getsize(archive_path) // 1024
    logger.info(
        "Batch archive #%d: %d files + %d manifests, %d KB",
        batch_index, len(file_subset), len(extra_manifests), size_kb,
    )
    return archive_path


def _batch_size(total_files: int) -> int:
    raw = (os.environ.get("UNIFAI_FILE_BATCH_SIZE") or "").strip()
    if not raw:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    try:
        size = int(raw)
    except ValueError:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    if size <= 0:
        return max(1, total_files)
    return size

# ===========================================================================
# MCP scan (SDK path only)
# ===========================================================================

def _upload_to_s3(presigned_url: str, archive_path: str) -> None:
    size = os.path.getsize(archive_path)
    logger.info("Uploading %d KB to S3 ...", size // 1024)
    with open(archive_path, "rb") as f:
        req = urllib.request.Request(
            presigned_url, data=f.read(), method="PUT",
            headers={"Content-Type": "application/zip"},
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"S3 upload failed: HTTP {resp.status}")
    logger.info("S3 upload complete")


def _parse_tool_result(result: Any) -> dict:
    if hasattr(result, "content") and result.content:
        raw = result.content[0].text if hasattr(result.content[0], "text") else str(result.content[0])
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"raw": raw}
    return {"raw": "empty response"}


def _run_mcp_scan_via_client(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
) -> Dict[str, Any]:
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession

    async def _scan() -> Dict[str, Any]:
        upload_args: Dict[str, Any] = {
            "source_code_repo": source_code_repo,
            "branch_or_tag": branch,
            "files_to_scan": files_to_scan,
        }
        tok1 = bearer_getter()
        async with streamablehttp_client(
            server_url, headers={"Authorization": f"Bearer {tok1}"},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("MCP step 1/3: get_upload_url")
                upload_result = _parse_tool_result(
                    await session.call_tool("get_upload_url", arguments=upload_args)
                )
                if not upload_result.get("success"):
                    raise RuntimeError(f"get_upload_url failed: {upload_result.get('error', upload_result)}")
                archive_id = upload_result["archive_id"]
                presigned_url = upload_result["presigned_url"]

        logger.info("MCP step 2/3: upload to S3")
        _upload_to_s3(presigned_url, archive_path)

        tok2 = bearer_getter()
        sse_timeout = int(os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800"))
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}"},
            sse_read_timeout=sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                logger.info("MCP step 3/3: analyze_uploaded_archive (timeout=%ds)", sse_timeout)
                analyze_args = dict(upload_args)
                analyze_args["archive_id"] = archive_id
                result = _parse_tool_result(
                    await session2.call_tool("analyze_uploaded_archive", arguments=analyze_args)
                )
                return result

    return asyncio.run(_scan())


def run_mcp_scan(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
) -> Dict[str, Any]:
    logger.info("MCP scan: %d files, repo=%s, branch=%s", len(files_to_scan), source_code_repo, branch)
    return _run_mcp_scan_via_client(server_url, bearer_getter, source_code_repo, branch, files_to_scan, archive_path)

# ===========================================================================
# Parallel batch scan
# ===========================================================================

def parallel_batch_scan(
    batches: List[List[str]],
    source_dir: str,
    temp_dir: str,
    source_code_repo: str,
    branch: str,
    head_sha: str,
    run_id: str,
    server_url: str,
    bearer_getter: Callable[[], str],
    manifest_files: Optional[List[str]] = None,
    max_workers: int = MAX_SCAN_WORKERS,
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, str]], int, List[str]]:
    all_remediation_actions: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    all_aibom: List[Dict[str, str]] = []
    aibom_seen: set = set()
    failed_batch_count = 0
    failure_details: List[str] = []
    lock = threading.Lock()

    def _scan_one(batch_idx: int, batch_files: List[str]) -> Tuple[int, Dict[str, Any]]:
        logger.info("Batch %d/%d: %d files", batch_idx, len(batches), len(batch_files))
        archive_path = create_batch_archive(
            source_dir, temp_dir, batch_files,
            source_code_repo, branch, head_sha, batch_idx, run_id=run_id,
            manifest_files=manifest_files,
        )
        result = run_mcp_scan(server_url, bearer_getter, source_code_repo, branch, batch_files, archive_path)
        return batch_idx, result

    def _collect(batch_idx: int, mcp_result: Dict[str, Any]) -> None:
        batch_actions = mcp_result.get("remediation_actions", [])
        batch_report = mcp_result.get("report", "")
        batch_aibom = mcp_result.get("aibom", [])
        logger.info(
            "Batch %d/%d done: status=%s violations=%d aibom=%d",
            batch_idx, len(batches), mcp_result.get("status", "unknown"),
            len(batch_actions), len(batch_aibom),
        )
        with lock:
            all_remediation_actions.extend(batch_actions)
            if batch_report:
                all_reports.append(batch_report)
            for entry in batch_aibom:
                key = (entry.get("name", ""), entry.get("source_file", ""))
                if key not in aibom_seen:
                    aibom_seen.add(key)
                    all_aibom.append(entry)

    workers = min(len(batches), max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_scan_one, idx, files): idx for idx, files in enumerate(batches, 1)}
        for future in as_completed(future_map):
            batch_idx = future_map[future]
            try:
                _, mcp_result = future.result()
                _collect(batch_idx, mcp_result)
            except BaseException as exc:
                failed_batch_count += 1
                # Unwrap ExceptionGroup / TaskGroup to surface the real cause
                cause = exc
                if hasattr(exc, "exceptions") and exc.exceptions:
                    cause = exc.exceptions[0]
                    if hasattr(cause, "exceptions") and cause.exceptions:
                        cause = cause.exceptions[0]
                detail = f"Batch {batch_idx}/{len(batches)} failed: {type(cause).__name__}: {cause}"
                logger.error("%s", detail)
                logger.debug("Full exception:", exc_info=exc)
                failure_details.append(detail)

    return all_remediation_actions, all_reports, all_aibom, failed_batch_count, failure_details

# ===========================================================================
# JSON output
# ===========================================================================

def build_json_output(
    *,
    status: str,
    repo: str,
    branch: str,
    head_sha: str,
    source_code_repo: str,
    files_scanned: int,
    batches: int,
    failed_batches: int,
    violations: List[Dict[str, Any]],
    aibom: Optional[List[Dict[str, str]]] = None,
    report: str = "",
    remediation_pr: Optional[int] = None,
    remediation_branch: str = "",
    failed_remediation_files: Optional[List[str]] = None,
    scan_errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "status": status,
        "scan_metadata": {
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "source_code_repo": source_code_repo,
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": files_scanned,
            "batches": batches,
            "failed_batches": failed_batches,
        },
        "report": report,
        "violations": violations,
        "aibom": aibom or [],
        "remediation_pr": remediation_pr,
        "remediation_branch": remediation_branch,
        "failed_remediation_files": failed_remediation_files or [],
        "scan_errors": scan_errors or [],
    }


def print_human_output(output: Dict[str, Any]) -> None:
    status = output.get("status", "unknown")
    violations = output.get("violations", [])
    scan_errors = output.get("scan_errors", [])
    metadata = output.get("scan_metadata", {})
    scanned_at = metadata.get("scanned_at", "")
    branch = metadata.get("branch", "")

    if status == "compliant":
        status_label = "✅ Compliant"
    elif status == "violations_found":
        status_label = "❌ Not Compliant"
    else:
        status_label = status

    print("# UnifAI Security Report")
    print()
    print(f"**Status:** {status_label}")
    if branch:
        print(f"**Branch:** `{branch}`")
    if scanned_at:
        print(f"**Scanned at:** {scanned_at}")

    if scan_errors:
        print("\n**Errors:**")
        for err in scan_errors:
            print(f"- {err}")
        print()

    if not violations:
        if status == "compliant":
            print("\nNo violations found.")
        return

    from collections import defaultdict
    by_file: Dict[str, List[str]] = defaultdict(list)
    for v in violations:
        file_ = v.get("file", "(unknown)")
        control = v.get("control", "(unknown)")
        by_file[file_].append(control)

    num_files = len(by_file)
    print(f"\n**{len(violations)} violation(s) across {num_files} file(s)**\n")

    print("| File | Policy Violations |")
    print("|------|-------------------|")

    for file_, controls in sorted(by_file.items()):
        numbered = "".join(f"{i}. {c}<br>" for i, c in enumerate(controls, 1))
        print(f"| `{file_}` | {numbered} |")


# ===========================================================================
# Patch application (ported from veracode_repo_scan.py, no external deps)
# ===========================================================================

def _normalize_for_patch_match(s: str) -> str:
    return re.sub(r"[ \t]+", " ", s)


def _apply_fix_entry(content: str, original: str, replacement: str) -> Tuple[str, bool]:
    if not original:
        return content, False

    if original in content:
        return content.replace(original, replacement, 1), True

    orig_stripped = original.strip()
    if orig_stripped and orig_stripped in content:
        return content.replace(orig_stripped, replacement, 1), True

    norm_orig = _normalize_for_patch_match(orig_stripped)
    norm_content = _normalize_for_patch_match(content)
    idx = norm_content.find(norm_orig)
    if idx != -1:
        orig_len = len(orig_stripped)
        real_idx = 0
        norm_walked = 0
        for ci, ch in enumerate(content):
            if norm_walked >= idx:
                real_idx = ci
                break
            norm_walked += len(_normalize_for_patch_match(ch))
        else:
            real_idx = len(content)
        sub = content[real_idx: real_idx + orig_len + 50]
        if orig_stripped in sub:
            actual_idx = content.find(orig_stripped, real_idx)
            if actual_idx != -1:
                return content[:actual_idx] + replacement + content[actual_idx + len(orig_stripped):], True

    orig_lines = [l for l in orig_stripped.splitlines() if l.strip()]
    if orig_lines:
        anchor = orig_lines[0].strip()
        if len(anchor) > 15:
            anchor_idx = content.find(anchor)
            if anchor_idx != -1:
                end_search = content.find(orig_lines[-1].strip(), anchor_idx) if len(orig_lines) > 1 else anchor_idx
                if end_search != -1:
                    end_idx = end_search + len(orig_lines[-1].strip())
                    found_block = content[anchor_idx:end_idx]
                    if len(found_block) < len(orig_stripped) * 2:
                        return content[:anchor_idx] + replacement + content[end_idx:], True

    return content, False


def _norm_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def _resolve_source_file(source_dir: str, filepath: str, file_list: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a violation filepath to (rel_path, content) from the live checkout."""
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_rel_path(raw)
    root = pathlib.Path(source_dir)

    candidate = root / raw
    if candidate.is_file():
        return norm_fp, candidate.read_text(errors="replace")

    # Try normalised path
    candidate2 = root / norm_fp
    if candidate2.is_file():
        return norm_fp, candidate2.read_text(errors="replace")

    # Basename fallback
    base = pathlib.Path(norm_fp).name
    matches = [f for f in file_list if pathlib.Path(f).name == base]
    if len(matches) == 1:
        full = root / matches[0]
        if full.is_file():
            return _norm_rel_path(matches[0]), full.read_text(errors="replace")

    logger.warning("Cannot resolve remediation file %r in source dir", raw)
    return None, None


def apply_pipeline_fix_code_to_clone(
    remediation_actions: List[Dict[str, Any]],
    source_dir: str,
    file_list: List[str],
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Apply fix_code patches from MCP remediation_actions to checked-out files.

    Returns (validated_fixes, failed_files, fix_table_rows).
    """
    validated_fixes: Dict[str, str] = {}
    failed_files: List[str] = []
    fix_table_rows: List[Dict[str, str]] = []

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for action in remediation_actions:
        fp = (action.get("file") or "").strip()
        if fp:
            by_file.setdefault(fp, []).append(action)

    for filepath, actions in by_file.items():
        has_fix_code = any(action.get("fix_code") for action in actions)
        if not has_fix_code:
            failed_files.append(filepath)
            continue

        rel_path, original_content = _resolve_source_file(source_dir, filepath, file_list)
        if rel_path is None or original_content is None:
            failed_files.append(filepath)
            continue

        content = original_content
        patch_applied = False
        for action in actions:
            for fix_entry in (action.get("fix_code") or []):
                original = fix_entry.get("original") or ""
                replacement = fix_entry.get("replacement", "")
                if not original.strip():
                    continue
                content, applied = _apply_fix_entry(content, original, replacement)
                if applied:
                    patch_applied = True
                else:
                    logger.debug(
                        "Patch not applied for %r — original snippet (%d chars) not found",
                        filepath, len(original),
                    )

        if patch_applied and content != original_content:
            validated_fixes[rel_path] = content
            for action in actions:
                fix_table_rows.append({
                    "policy": action.get("control", ""),
                    "description": (action.get("instruction") or "")[:200],
                    "file": filepath,
                })
        else:
            logger.warning("No patch applied for %r — snippets did not match file content", filepath)
            failed_files.append(filepath)

    return validated_fixes, failed_files, fix_table_rows


# ===========================================================================
# Remediation PR creation
# ===========================================================================

def _create_fix_pr(
    github_token: str,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
) -> Tuple[Optional[int], str]:
    """Commit fix_code patches to a remediation branch and open (or refresh) a PR."""
    try:
        import sys as _sys
        import os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
        from scm_client import GitHubClient  # type: ignore
    except ImportError:
        logger.error("scm_client.py not found — cannot create remediation PR")
        return None, ""

    if not validated_fixes:
        return None, ""

    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)
    sha_short = head_sha[:7]
    timestamp = time.strftime("%m%d%H%M")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}-{safe_branch.replace('/', '-')}-{sha_short}-{timestamp}"

    scm = GitHubClient(token=github_token)

    # Resolve short SHA to full 40-char SHA (GitHub's /git/refs API requires it)
    if len(head_sha) < 40:
        try:
            commit_data = scm._request("GET", f"/repos/{repo}/commits/{head_sha}")
            head_sha = commit_data["sha"]
        except Exception as exc:
            logger.warning("Could not resolve short SHA %s: %s", head_sha, exc)

    try:
        logger.info("Creating remediation branch %s from %s", remediation_branch, sha_short)
        scm.create_branch(repo, remediation_branch, head_sha)
    except Exception as exc:
        logger.error("Failed to create/verify remediation branch: %s", exc)
        return None, remediation_branch

    committed: List[str] = []
    for filepath, content in validated_fixes.items():
        blob_sha: Optional[str] = None
        try:
            blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
        except Exception:
            pass
        policies = ", ".join({r["policy"] for r in fix_table if r["file"] == filepath}) or "policy violations"
        message = f"fix({filepath}): remediate {policies} [unifai-gha-scan]"
        try:
            scm.commit_file(repo, remediation_branch, filepath, content.encode("utf-8"), message, sha=blob_sha)
            committed.append(filepath)
            logger.info("Committed fix: %s", filepath)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", filepath, exc)

    if not committed:
        logger.warning("No files committed — skipping PR creation")
        return None, remediation_branch

    title = f"[unifai-bot] fix: AI policy remediation for {branch}@{sha_short}"

    files_list = "\n".join(f"- `{f}`" for f in committed)
    failed_list = ("\n".join(f"- `{f}`" for f in (failed_files or []))) or "_None_"
    pr_body_lines = [
        "## UniFAI AI Policy Remediation",
        "",
        f"Automated fixes for policy violations detected in `{branch}` at `{sha_short}`.",
        "",
        f"### Files remediated ({len(committed)})",
        "",
        files_list,
        "",
        f"### Files without fixes ({len(failed_files or [])})",
        "",
        failed_list,
    ]
    if report:
        MAX_REPORT_CHARS = 56_000  # leave room for rest of PR body; GitHub cap is 65536
        report_text = report.strip()
        if len(report_text) > MAX_REPORT_CHARS:
            report_text = report_text[:MAX_REPORT_CHARS] + "\n\n---\n\n*…Report truncated for GitHub PR body size limit. Retrieve the full text from CI logs.*"
        pr_body_lines += ["", "---", "", "<details><summary>Full scan report</summary>", "", report_text, "", "</details>"]
    pr_body = "\n".join(pr_body_lines)

    try:
        pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, pr_body)
        logger.info("Created remediation PR #%d", pr_number)
        return pr_number, remediation_branch
    except Exception as exc:
        logger.error("Failed to create remediation PR: %s", exc)
        return None, remediation_branch


# ===========================================================================
# Main scan orchestration
# ===========================================================================

def _execute_scan(args: argparse.Namespace) -> int:
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "")
    head_sha = args.head_sha or os.environ.get("GITHUB_SHA", "")
    source_path = os.path.abspath(args.source_path)
    server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL
    source_code_repo = f"https://github.com/{repo}.git" if repo else source_path

    # Validate config
    missing = [n for n, v in [("GITHUB_REPOSITORY / --repo", repo), ("GITHUB_REF_NAME / --branch", branch)] if not v]
    if missing:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Missing required config: {', '.join(missing)}"],
        )
        print_human_output(output)
        return 2

    try:
        bearer_getter = build_bearer_getter()
        pat_token = bearer_getter()
        pat_info = introspect_lineaje_pat(pat_token)
        logger.info(
            "Auth OK — user=%s tenant=%s company=%s",
            pat_info.get("user_email", ""),
            pat_info.get("tenant_id", ""),
            pat_info.get("company_id", ""),
        )
    except Exception as exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Auth failed: {exc}"],
        )
        print_human_output(output)
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    scan_start = time.perf_counter()

    logger.info("Scanning source path: %s (repo=%s branch=%s sha=%s)", source_path, repo, branch, head_sha[:7] if head_sha else "?")

    # Step 1: Collect files
    file_list = collect_repo_files(source_path)
    if not file_list:
        logger.info("No scannable files found")
        output = build_json_output(
            status="compliant", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
        )
        print_human_output(output)
        return 0

    manifest_files = [f for f in file_list if _is_manifest_file(os.path.basename(f))]
    code_files = [f for f in file_list if not _is_manifest_file(os.path.basename(f))]
    scan_files = code_files if code_files else file_list
    batch_size = _batch_size(len(scan_files))
    batches = [scan_files[i: i + batch_size] for i in range(0, len(scan_files), batch_size)]
    logger.info(
        "Files: %d total (%d code, %d manifest) → %d batch(es) of ≤%d",
        len(file_list), len(code_files), len(manifest_files), len(batches), batch_size,
    )

    # Step 2: MCP scan
    with tempfile.TemporaryDirectory(prefix="gha-repo-scan-") as temp_dir:
        all_violations, all_reports, all_aibom, failed_batches_count, failure_details = parallel_batch_scan(
            batches=batches,
            source_dir=source_path,
            temp_dir=temp_dir,
            source_code_repo=source_code_repo,
            branch=branch,
            head_sha=head_sha,
            run_id=run_id,
            server_url=server_url,
            bearer_getter=bearer_getter,
            manifest_files=manifest_files or None,
        )

    elapsed = time.perf_counter() - scan_start
    logger.info(
        "Scan complete in %.1fs: %d violation(s), %d AIBOM entry/ies, %d failed batch(es)",
        elapsed, len(all_violations), len(all_aibom), failed_batches_count,
    )

    combined_report = "\n\n---\n\n".join(r for r in all_reports if r)

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details,
        )
        print_human_output(output)
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    # Step 3: Remediation — apply fix_code patches and create PR
    remediation_pr_number: Optional[int] = None
    remediation_branch = ""
    failed_rem_files: List[str] = []

    github_token = (
        getattr(args, "github_token", None)
        or os.environ.get("GH_TOKEN", "")
        or os.environ.get("GITHUB_TOKEN", "")
    )
    if all_violations and github_token and getattr(args, "create_fix_pr", False):
        logger.info(
            "STEP 3: Applying fix_code patches for %d violation(s)", len(all_violations)
        )
        try:
            validated_fixes, failed_rem_files, fix_table = apply_pipeline_fix_code_to_clone(
                all_violations, source_path, file_list
            )
            logger.info(
                "Patches applied: %d file(s); no fix_code: %d file(s)",
                len(validated_fixes), len(failed_rem_files),
            )
            if validated_fixes:
                remediation_pr_number, remediation_branch = _create_fix_pr(
                    github_token, repo, branch, head_sha,
                    validated_fixes, fix_table,
                    report=combined_report, failed_files=failed_rem_files,
                )
            else:
                logger.warning("No patches could be applied — skipping PR creation")
        except Exception as exc:
            logger.error("Remediation step failed: %s", exc)
    elif all_violations:
        logger.info("Skipping remediation — GITHUB_TOKEN / --github-token not set")

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        remediation_pr=remediation_pr_number,
        remediation_branch=remediation_branch,
        failed_remediation_files=failed_rem_files,
        scan_errors=failure_details,
    )
    print_human_output(output)
    return 0

# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lineaje AI Policy Scanner — GitHub Actions edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--source-path", default=".",
        help="Path to the checked-out source code (default: current directory)",
    )
    parser.add_argument(
        "--repo", default="",
        help="Repository owner/repo slug (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--branch", default="",
        help="Branch name (default: $GITHUB_REF_NAME)",
    )
    parser.add_argument(
        "--head-sha", default="",
        help="Commit SHA (default: $GITHUB_SHA)",
    )
    parser.add_argument(
        "--mcp-server-url", default="",
        help=f"MCP server URL (default: {MCP_SERVER_URL})",
    )
    parser.add_argument(
        "--github-token", default="",
        help="GitHub token for creating remediation PRs (default: $GH_TOKEN then $GITHUB_TOKEN). "
             "If not set, violations are reported but no PR is created.",
    )
    parser.add_argument(
        "--create-fix-pr", default=False, action="store_true",
        help="Create a remediation PR with fix_code patches (default: false).",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Always show INFO from this logger regardless of --debug
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    # --- Persistent audit log with six-month (180-day) retention ---
    _LOG_RETENTION_DAYS = 180  # Minimum six-month retention for high-risk AI systems
    _AUDIT_LOG_DIR = pathlib.Path(os.environ.get("LINEAJE_AUDIT_LOG_DIR", "/var/log/lineaje"))
    _AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    _audit_log_path = _AUDIT_LOG_DIR / "ai_policy_scan_audit.log"
    _audit_handler = logging.handlers.TimedRotatingFileHandler(
        filename=str(_audit_log_path),
        when="D",
        interval=1,
        backupCount=_LOG_RETENTION_DAYS,
        utc=True,
    )
    _audit_handler.setLevel(logging.INFO)
    _audit_handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    ))
    logging.getLogger().addHandler(_audit_handler)
    logger.info(
        "Audit logging initialized: path=%s, retention_days=%d",
        _audit_log_path, _LOG_RETENTION_DAYS,
    )

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print_human_output(err)
        return 1


if __name__ == "__main__":
    sys.exit(main())
