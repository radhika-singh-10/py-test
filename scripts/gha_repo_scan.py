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

    LINEAJE_PAT_TOKEN  — Lineaje refresh token (exchanged for short-lived access tokens)

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
import hashlib
import json
import logging
import os
import pathlib
import re
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

MAX_SCAN_WORKERS = 4
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://lineaje-identity-service.v2.prod.veedna.com"
    "/lineajeidentity/api/v1/auth/native/renew-access-token"
)

# Expected SHA-256 fingerprint of the MCP server's TLS certificate.
# Set via environment variable LINEAJE_MCP_CERT_FINGERPRINT or override here.
_MCP_EXPECTED_CERT_FINGERPRINT: Optional[str] = os.environ.get("LINEAJE_MCP_CERT_FINGERPRINT", "")

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

# Maximum file size (bytes) allowed for upload to MCP server
_MAX_FILE_SIZE_BYTES = 512 * 1024  # 512 KB

# ===========================================================================
# PII redaction helpers (generic)
# ===========================================================================

_PII_PATTERNS: List[Tuple[str, str]] = [
    # Email addresses
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]"),
    # US phone numbers
    (r"\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b", "[REDACTED_PHONE]"),
    # US SSN
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    # Credit card numbers (basic pattern)
    (r"\b(?:\d[ \-]?){13,16}\b", "[REDACTED_CC]"),
    # IPv4 addresses
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]"),
    # API keys / tokens (generic high-entropy strings)
    (r"(?i)(?:api[_\-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*\S+", "[REDACTED_SECRET]"),
]

_COMPILED_PII_PATTERNS = [(re.compile(p), r) for p, r in _PII_PATTERNS]


def redact_pii(content: str) -> str:
    """Redact common PII patterns from a string."""
    for pattern, replacement in _COMPILED_PII_PATTERNS:
        content = pattern.sub(replacement, content)
    return content


# ===========================================================================
# Singapore PII redaction helpers
# ===========================================================================

_SG_PII_PATTERNS: List[Tuple[str, str]] = [
    # NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    (r"\b[STFG]\d{7}[A-Z]\b", "[REDACTED_NRIC]"),
    # SingPass identifier (common format)
    (r"(?i)singpass[\s:_\-]*[a-zA-Z0-9@._\-]+", "[REDACTED_SINGPASS]"),
    # CPF account numbers (9 digits)
    (r"\b\d{9}\b", "[REDACTED_CPF]"),
    # Singapore phone numbers (+65 XXXX XXXX)
    (r"\b(?:\+65[\s\-]?)?\d{4}[\s\-]?\d{4}\b", "[REDACTED_SG_PHONE]"),
    # Singapore postal codes (6 digits, common pattern)
    (r"\bSingapore\s+\d{6}\b", "[REDACTED_SG_POSTAL]"),
]

_COMPILED_SG_PII_PATTERNS = [(re.compile(p), r) for p, r in _SG_PII_PATTERNS]


def redact_singapore_pii(content: str) -> str:
    """Redact Singapore-specific PII patterns from a string."""
    for pattern, replacement in _COMPILED_SG_PII_PATTERNS:
        content = pattern.sub(replacement, content)
    return content


def redact_all_pii(content: str) -> str:
    """Apply both generic and Singapore PII redaction."""
    content = redact_pii(content)
    content = redact_singapore_pii(content)
    return content


# ===========================================================================
# File content sanitization and validation
# ===========================================================================

_MAX_CONTENT_SIZE = _MAX_FILE_SIZE_BYTES

# Prompt injection patterns to detect/strip
_PROMPT_INJECTION_LINE_PATTERNS = [
    re.compile(r"^\s*(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"^\s*(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be))", re.IGNORECASE),
    re.compile(r"^\s*(?:system|assistant|user)\s*:\s*", re.IGNORECASE),
    re.compile(r"^\s*<\s*(?:system|instruction|prompt)\s*>", re.IGNORECASE),
    re.compile(r"^\s*\[(?:INST|SYS|SYSTEM|PROMPT)\]", re.IGNORECASE),
    re.compile(r"^\s*###\s*(?:instruction|system|prompt)", re.IGNORECASE),
]

# Hidden/invisible Unicode prompt-injection characters
_INVISIBLE_UNICODE_PATTERN = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]"
)

# Leetspeak AI-instruction patterns
_LEETSPEAK_PATTERN = re.compile(
    r"(?i)(?:1gn0r3|d1sr3g4rd|f0rg3t|4ct\s+4s|pr3t3nd)", re.IGNORECASE
)

# Suspicious imperative AI directives
_AI_DIRECTIVE_PATTERN = re.compile(
    r"(?i)(?:do\s+not\s+(?:follow|obey|apply)|override\s+(?:your\s+)?(?:instructions|rules|guidelines)|"
    r"new\s+(?:instructions?|directives?|rules?)\s*:)", re.IGNORECASE
)

# Binary executable signatures
_BINARY_SIGNATURES = [
    b"\x7fELF",       # ELF executable
    b"MZ",            # PE/DOS executable
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"#!/bin/sh",     # shell script
    b"#!/bin/bash",   # bash script
]


def sanitize_file_content_for_upload(content_bytes: bytes, filename: str = "") -> Tuple[bool, bytes, str]:
    """
    Validate and sanitize file content bytes before uploading to MCP server.

    Returns (ok, sanitized_bytes, reason).
    If ok is False, the file should be skipped.
    """
    # Enforce maximum file size
    if len(content_bytes) > _MAX_CONTENT_SIZE:
        return False, b"", f"File exceeds maximum size limit ({len(content_bytes)} > {_MAX_CONTENT_SIZE} bytes)"

    # Reject files with null bytes (binary content indicator)
    if b"\x00" in content_bytes:
        return False, b"", "File contains null bytes (likely binary content)"

    # Check for binary executable signatures
    for sig in _BINARY_SIGNATURES:
        if content_bytes.startswith(sig):
            return False, b"", f"File has binary executable signature"

    # Decode to string for text-based checks
    try:
        content_str = content_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            content_str = content_bytes.decode("latin-1", errors="replace")
        except Exception:
            return False, b"", "File cannot be decoded as text"

    # Reject files with excessive non-printable control characters
    control_chars = sum(1 for c in content_str if ord(c) < 32 and c not in "\t\n\r")
    if control_chars > 10:
        return False, b"", f"File contains {control_chars} non-printable control characters"

    # Strip invisible Unicode prompt-injection characters
    content_str = _INVISIBLE_UNICODE_PATTERN.sub("", content_str)

    # Strip/escape lines with prompt injection patterns
    lines = content_str.splitlines(keepends=True)
    sanitized_lines = []
    for line in lines:
        stripped = line.rstrip("\n\r")
        injected = False
        for pat in _PROMPT_INJECTION_LINE_PATTERNS:
            if pat.match(stripped):
                injected = True
                break
        if injected:
            sanitized_lines.append("# [SANITIZED: potential prompt injection removed]\n")
        else:
            sanitized_lines.append(line)
    content_str = "".join(sanitized_lines)

    return True, content_str.encode("utf-8", errors="replace"), ""


def screen_file_content_for_prompt_injection(content_bytes: bytes, filename: str = "") -> Tuple[bool, bytes, str]:
    """
    Screen raw file bytes for prompt injection and malicious content before upload.

    Returns (ok, sanitized_bytes, reason).
    If ok is False, the file should be skipped/flagged.
    """
    # Check for binary executable signatures
    for sig in _BINARY_SIGNATURES:
        if content_bytes.startswith(sig):
            return False, b"", f"File has binary/shell executable signature"

    # Reject null bytes
    if b"\x00" in content_bytes:
        return False, b"", "File contains null bytes"

    try:
        content_str = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        return False, b"", "File cannot be decoded"

    # Check for hidden/invisible Unicode prompt-injection characters
    if _INVISIBLE_UNICODE_PATTERN.search(content_str):
        logger.warning("File '%s' contains invisible Unicode characters; stripping.", filename)
        content_str = _INVISIBLE_UNICODE_PATTERN.sub("", content_str)

    # Check for base64-encoded embedded prompts
    b64_chunks = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", content_str)
    for chunk in b64_chunks:
        try:
            decoded = base64.b64decode(chunk).decode("utf-8", errors="replace")
            for pat in _PROMPT_INJECTION_LINE_PATTERNS:
                if pat.search(decoded):
                    return False, b"", f"File contains base64-encoded prompt injection in '{filename}'"
            if _AI_DIRECTIVE_PATTERN.search(decoded):
                return False, b"", f"File contains base64-encoded AI directive in '{filename}'"
        except Exception:
            pass

    # Check for leetspeak AI-instruction patterns
    if _LEETSPEAK_PATTERN.search(content_str):
        logger.warning("File '%s' contains leetspeak AI-instruction patterns; flagging.", filename)
        content_str = _LEETSPEAK_PATTERN.sub("[SANITIZED]", content_str)

    # Check for suspicious imperative AI directives
    if _AI_DIRECTIVE_PATTERN.search(content_str):
        logger.warning("File '%s' contains suspicious AI directive patterns; sanitizing.", filename)
        content_str = _AI_DIRECTIVE_PATTERN.sub("[SANITIZED_DIRECTIVE]", content_str)

    # Strip prompt injection lines
    lines = content_str.splitlines(keepends=True)
    sanitized_lines = []
    for line in lines:
        stripped = line.rstrip("\n\r")
        injected = False
        for pat in _PROMPT_INJECTION_LINE_PATTERNS:
            if pat.match(stripped):
                injected = True
                break
        if injected:
            sanitized_lines.append("# [SANITIZED: prompt injection removed]\n")
        else:
            sanitized_lines.append(line)
    content_str = "".join(sanitized_lines)

    return True, content_str.encode("utf-8", errors="replace"), ""


# ===========================================================================
# MCP output sanitization helpers
# ===========================================================================

_MAX_STRING_FIELD_LENGTH = 1_000_000  # 1 MB max for string fields
_MAX_LIST_LENGTH = 10_000


def _sanitize_string(value: Any, max_length: int = _MAX_STRING_FIELD_LENGTH) -> str:
    """Sanitize a value to a safe string."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return ""
    # Truncate if too long
    if len(value) > max_length:
        logger.warning("Truncating oversized string field from MCP output (%d chars)", len(value))
        value = value[:max_length] + "...[TRUNCATED]"
    return value


def _sanitize_dict(value: Any) -> Dict[str, Any]:
    """Sanitize a value to a safe dict."""
    if not isinstance(value, dict):
        return {}
    sanitized: Dict[str, Any] = {}
    for k, v in value.items():
        safe_key = _sanitize_string(k, max_length=256)
        if isinstance(v, dict):
            sanitized[safe_key] = _sanitize_dict(v)
        elif isinstance(v, list):
            sanitized[safe_key] = _sanitize_list(v)
        elif isinstance(v, str):
            sanitized[safe_key] = _sanitize_string(v)
        elif isinstance(v, (int, float, bool)) or v is None:
            sanitized[safe_key] = v
        else:
            sanitized[safe_key] = _sanitize_string(v)
    return sanitized


def _sanitize_list(value: Any, max_items: int = _MAX_LIST_LENGTH) -> List[Any]:
    """Sanitize a value to a safe list."""
    if not isinstance(value, list):
        return []
    if len(value) > max_items:
        logger.warning("Truncating oversized list from MCP output (%d items)", len(value))
        value = value[:max_items]
    result = []
    for item in value:
        if isinstance(item, dict):
            result.append(_sanitize_dict(item))
        elif isinstance(item, list):
            result.append(_sanitize_list(item))
        elif isinstance(item, str):
            result.append(_sanitize_string(item))
        elif isinstance(item, (int, float, bool)) or item is None:
            result.append(item)
        else:
            result.append(_sanitize_string(item))
    return result


def sanitize_violations(violations: Any) -> List[Dict[str, Any]]:
    """Validate and sanitize violations list from MCP server output."""
    if not isinstance(violations, list):
        logger.warning("MCP output 'violations' is not a list; got %s", type(violations).__name__)
        return []
    return _sanitize_list(violations)


def sanitize_aibom(aibom: Any) -> List[Dict[str, Any]]:
    """Validate and sanitize AIBOM list from MCP server output."""
    if not isinstance(aibom, list):
        logger.warning("MCP output 'aibom' is not a list; got %s", type(aibom).__name__)
        return []
    return _sanitize_list(aibom)


def sanitize_report(report: Any) -> str:
    """Validate and sanitize report string from MCP server output."""
    if not isinstance(report, str):
        logger.warning("MCP output 'report' is not a string; got %s", type(report).__name__)
        return ""
    return _sanitize_string(report)


def sanitize_scan_errors(scan_errors: Any) -> List[str]:
    """Validate and sanitize scan_errors list from MCP server output."""
    if not isinstance(scan_errors, list):
        logger.warning("MCP output 'scan_errors' is not a list; got %s", type(scan_errors).__name__)
        if isinstance(scan_errors, str):
            return [_sanitize_string(scan_errors)]
        return []
    result = []
    for item in scan_errors:
        result.append(_sanitize_string(item))
    return result


# ===========================================================================
# MCP server certificate pinning
# ===========================================================================

def _get_mcp_server_cert_fingerprint(server_url: str) -> str:
    """
    Retrieve the SHA-256 fingerprint of the MCP server's TLS certificate.
    Returns hex string of the fingerprint.
    """
    parsed = urllib.parse.urlparse(server_url)
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        cert_pem = ssl.get_server_certificate((hostname, port))
        cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        logger.debug("MCP server cert fingerprint (SHA-256): %s", fingerprint)
        return fingerprint
    except Exception as exc:
        raise RuntimeError(f"Failed to retrieve MCP server certificate: {exc}") from exc


def validate_mcp_server_certificate(server_url: str) -> None:
    """
    Validate the MCP server's TLS certificate fingerprint against the expected value.
    If no expected fingerprint is configured, logs a warning and skips pinning.
    """
    expected = (_MCP_EXPECTED_CERT_FINGERPRINT or "").strip().lower().replace(":", "")
    if not expected:
        logger.warning(
            "MCP server certificate pinning is not configured. "
            "Set LINEAJE_MCP_CERT_FINGERPRINT to enable certificate pinning."
        )
        return
    actual = _get_mcp_server_cert_fingerprint(server_url).lower().replace(":", "")
    if actual != expected:
        raise RuntimeError(
            f"MCP server certificate fingerprint mismatch! "
            f"Expected: {expected}, Got: {actual}. "
            "Aborting to prevent potential MITM attack."
        )
    logger.info("MCP server certificate fingerprint validated successfully.")


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


def _normalize_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    u = str(url).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
        u = u[1:-1].strip()
    return u


def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
    text = raw_text.strip() if raw_text else ""
    try:
        parsed: Any = json.loads(raw_text)
    except json.JSONDecodeError:
        # Some endpoints return a bare JWT string
        parts = text.split(".")
        if context == "renew-access-token" and len(parts) == 3:
            return {"access_token": text}
        raise RuntimeError(f"{context}: response is not valid JSON") from None
    for _ in range(8):
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            s = parsed.strip()
            if not s:
                raise RuntimeError(f"{context}: empty JSON string where object expected")
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parts = s.split(".")
                if context == "renew-access-token" and len(parts) == 3:
                    return {"access_token": s}
                raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
            continue
        break
    raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


class RefreshTokenTokenManager:
    """Exchange LINEAJE_PAT_TOKEN for short-lived MCP access tokens, auto-renewing before expiry."""

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
        self._renew_url = (
            _normalize_url(renew_access_token_url)
            or _normalize_url(os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL"))
            or _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
        ).rstrip("/")
        self._lock = threading.Lock()
        self._access_token = ""
        self._access_deadline = 0.0
        try:
            self._skew_sec = int(os.environ.get(
                "LINEAJE_TOKEN_REFRESH_SKEW_SEC", str(_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC)
            ))
        except ValueError:
            self._skew_sec = _DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC

    def get_access_token(self) -> str:
        with self._lock:
            return self._get_unlocked()

    def _get_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _renew(self) -> None:
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
        req = urllib.request.Request(
            url, data=b"null",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"renew-access-token HTTP {exc.code}: {body[:800]}") from exc
        at = (data.get("access_token") or "").strip()
        if not at:
            raise RuntimeError(f"Token response missing access_token: {data!r}")
        self._access_token = at
        rt = (data.get("refresh_token") or "").strip()
        if rt:
            self._refresh_token = rt
        exp = data.get("expires_in")
        try:
            exp_sec = int(exp) if exp is not None else 3600
        except (TypeError, ValueError):
            exp_sec = 3600
        self._access_deadline = time.time() + max(60, exp_sec)
        logger.debug("Access token renewed; expires in %ds", exp_sec)


def build_bearer_getter() -> Callable[[], str]:
    pat = _normalize_token(os.environ.get("LINEAJE_PAT_TOKEN", ""))
    if not pat:
        raise RuntimeError("LINEAJE_PAT_TOKEN is not set")
    mgr = RefreshTokenTokenManager(pat)
    return mgr.get_access_token

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
                try:
                    with open(full_path, "rb") as fh:
                        content_bytes = fh.read()
                except Exception as read_exc:
                    logger.warning("Skipping file '%s': cannot read: %s", rel_path, read_exc)
                    continue

                # Sanitize and validate file content before including in archive
                ok1, content_bytes, reason1 = sanitize_file_content_for_upload(content_bytes, filename=rel_path)
                if not ok1:
                    logger.warning("Skipping file '%s' (sanitize_file_content_for_upload): %s", rel_path, reason1)
                    continue

                ok2, content_bytes, reason2 = screen_file_content_for_prompt_injection(content_bytes, filename=rel_path)
                if not ok2:
                    logger.warning("Skipping file '%s' (screen_file_content_for_prompt_injection): %s", rel_path, reason2)
                    continue

                # Apply PII redaction before including in archive
                try:
                    content_str = content_bytes.decode("utf-8", errors="replace")
                    content_str = redact_all_pii(content_str)
                    content_bytes = content_str.encode("utf-8", errors="replace")
                except Exception as pii_exc:
                    logger.warning("PII redaction failed for '%s': %s", rel_path, pii_exc)

                zf.writestr(rel_path, content_bytes)

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
        logger.info(
            "MCP request: tool=get_upload_url server=%s repo=%s branch=%s files=%d",
            server_url, source_code_repo, branch, len(files_to_scan),
        )
        logger.debug("MCP request payload (get_upload_url): %s", json.dumps(upload_args))
        async with streamablehttp_client(
            server_url, headers={"Authorization": f"Bearer {tok1}"},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("MCP step 1/3: get_upload_url")
                try:
                    raw_upload_result = await session.call_tool("get_upload_url", arguments=upload_args)
                    upload_result = _parse_tool_result(raw_upload_result)
                    logger.info("MCP response: tool=get_upload_url success=%s", upload_result.get("success"))
                    logger.debug("MCP response payload (get_upload_url): %s", json.dumps(upload_result, default=str))
                except Exception as exc:
                    logger.error("MCP error: tool=get_upload_url error=%s", exc)
                    raise
                if not upload_result.get("success"):
                    raise RuntimeError(f"get_upload_url failed: {upload_result.get('error', upload_result)}")
                archive_id = upload_result["archive_id"]
                presigned_url = upload_result["presigned_url"]

        logger.info("MCP step 2/3: upload to S3")
        _upload_to_s3(presigned_url, archive_path)

        tok2 = bearer_getter()
        sse_timeout = int(os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800"))
        analyze_args = dict(upload_args)
        analyze_args["archive_id"] = archive_id
        logger.info(
            "MCP request: tool=analyze_uploaded_archive server=%s archive_id=%s timeout=%ds",
            server_url, archive_id, sse_timeout,
        )
        logger.debug("MCP request payload (analyze_uploaded_archive): %s", json.dumps(analyze_args, default=str))
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}"},
            sse_read_timeout=sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                logger.info("MCP step 3/3: analyze_uploaded_archive (timeout=%ds)", sse_timeout)
                try:
                    raw_result = await session2.call_tool("analyze_uploaded_archive", arguments=analyze_args)
                    result = _parse_tool_result(raw_result)
                    logger.info(
                        "MCP response: tool=analyze_uploaded_archive status=%s violations=%d aibom=%d",
                        result.get("status", "unknown"),
                        len(result.get("remediation_actions", [])),
                        len(result.get("aibom", [])),
                    )
                    logger.debug(
                        "MCP response payload (analyze_uploaded_archive): %s",
                        json.dumps(result, default=str),
                    )
                except Exception as exc:
                    logger.error("MCP error: tool=analyze_uploaded_archive error=%s", exc)
                    raise
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
        # Sanitize MCP server output before using it
        batch_actions = sanitize_violations(mcp_result.get("remediation_actions", []))
        batch_report = sanitize_report(mcp_result.get("report", ""))
        batch_aibom = sanitize_aibom(mcp_result.get("aibom", []))
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
                detail = f"Batch {batch_idx}/{len(batches)} failed: {exc}"
                logger.error("%s", detail)
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
        "scan_errors": scan_errors or [],
    }

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
        print(json.dumps(output, indent=2))
        return 2

    try:
        bearer_getter = build_bearer_getter()
        # Eagerly fetch a token at startup to catch auth errors early
        bearer_getter()
        logger.info("Auth OK — LINEAJE_PAT_TOKEN accepted")
    except Exception as exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Auth failed: {exc}"],
        )
        print(json.dumps(output, indent=2))
        return 2

    # Validate MCP server certificate before any communication
    try:
        validate_mcp_server_certificate(server_url)
    except RuntimeError as cert_exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"MCP server certificate validation failed: {cert_exc}"],
        )
        print(json.dumps(output, indent=2))
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
        print(json.dumps(output, indent=2))
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
        "Scan complete in %.1fs: %d violation(s), %d AIBOM entr(ies), %d failed batch(es)",
        elapsed, len(all_violations), len(all_aibom), failed_batches_count,
    )

    combined_report = sanitize_report("\n\n---\n\n".join(r for r in all_reports if r))
    sanitized_violations = sanitize_violations(all_violations)
    sanitized_aibom = sanitize_aibom(all_aibom)
    sanitized_errors = sanitize_scan_errors(failure_details)

    if failed_batches_count and not sanitized_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=sanitized_aibom, report=combined_report,
            scan_errors=sanitized_errors,
        )
        print(json.dumps(output, indent=2))
        return 1

    status = "compliant" if not sanitized_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=sanitized_violations, aibom=sanitized_aibom, report=combined_report,
        scan_errors=sanitized_errors,
    )
    print(json.dumps(output, indent=2))
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

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print(json.dumps(err, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())