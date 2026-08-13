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
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# Patterns commonly used in prompt injection attacks against LLMs
_PROMPT_INJECTION_PATTERNS = [
    re.compile(r'(?i)(?:^|\n)\s*(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|prompts|rules|context)'),
    re.compile(r'(?i)(?:^|\n)\s*(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|new\s+instruction|system\s*:)'),
    re.compile(r'(?i)(?:^|\n)\s*<\s*(?:system|prompt|instruction)\s*>'),
    re.compile(r'(?i)(?:^|\n)\s*\[\s*(?:SYSTEM|INST|INSTRUCTION)\s*\]'),
]

_MAX_FILE_CONTENT_LENGTH = 500_000  # 500KB per file content limit


def _sanitize_file_content(content: str) -> str:
    """Sanitize file content to mitigate prompt injection attacks.

    Strips or neutralizes patterns that could be interpreted as prompt
    injection when the content is sent to an LLM-backed service.
    """
    if not content:
        return content
    # Truncate excessively large content
    if len(content) > _MAX_FILE_CONTENT_LENGTH:
        content = content[:_MAX_FILE_CONTENT_LENGTH] + "\n[TRUNCATED]"
    # Neutralize prompt injection patterns by prefixing matched lines
    for pattern in _PROMPT_INJECTION_PATTERNS:
        content = pattern.sub(lambda m: "/* [SANITIZED] */ " + m.group(0).lstrip(), content)
    # Remove null bytes and other control characters that could confuse parsing
    content = content.replace('\x00', '')
    return content


def _sanitize_batch_files(batch_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate and sanitize a batch of files before sending to the MCP server.

    Each file dict is expected to have 'path' and 'content' keys.
    Returns a new list with sanitized content.
    """
    sanitized = []
    for file_entry in batch_files:
        if not isinstance(file_entry, dict):
            continue
        sanitized_entry = dict(file_entry)
        # Validate path - must be a relative path, no path traversal
        path = sanitized_entry.get("path", "")
        if not path or ".." in path.split("/") or path.startswith("/"):
            logger.warning("Skipping file with invalid path: %s", path)
            continue
        # Sanitize content
        if "content" in sanitized_entry and isinstance(sanitized_entry["content"], str):
            sanitized_entry["content"] = _sanitize_file_content(sanitized_entry["content"])
        sanitized.append(sanitized_entry)
    return sanitized

logger = logging.getLogger("gha_repo_scan")


def _validate_mcp_response(response: Any) -> dict:
    """Validate and sanitize a parsed MCP server response.

    Ensures the response conforms to expected JSON-RPC structure and
    sanitizes string values to prevent injection attacks.
    """
    if not isinstance(response, dict):
        raise ValueError(f"MCP response must be a JSON object, got {type(response).__name__}")
    # Validate JSON-RPC structure
    if "jsonrpc" in response and response.get("jsonrpc") != "2.0":
        raise ValueError(f"Unexpected jsonrpc version: {response.get('jsonrpc')}")
    # Must have either 'result' or 'error'
    if "result" not in response and "error" not in response and "id" in response:
        raise ValueError("MCP response missing both 'result' and 'error' fields")
    return response


def _sanitize_mcp_text(text: Any) -> str:
    """Sanitize a text value from MCP server response.

    Strips control characters (except newlines/tabs) and validates type.
    """
    if not isinstance(text, str):
        return ""
    # Remove control characters except \n, \r, \t
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return sanitized

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

# Risk classification metadata for this AI system deployment.
# Valid levels: "minimal", "limited", "high", "unacceptable"
AI_RISK_CLASSIFICATION = {
    "risk_level": "limited",
    "system_name": "Lineaje AI Policy Scanner",
    "deployment_context": "CI/CD automated code scanning",
    "classification_standard": "EU AI Act",
}


def _validate_risk_classification(config: dict) -> None:
    """Validate that the AI system risk classification metadata is properly declared."""
    valid_levels = {"minimal", "limited", "high", "unacceptable"}
    risk_level = config.get("risk_level")
    if not risk_level:
        raise ValueError(
            "AI system configuration error: 'risk_level' must be declared in "
            "AI_RISK_CLASSIFICATION metadata."
        )
    if risk_level not in valid_levels:
        raise ValueError(
            f"AI system configuration error: 'risk_level' must be one of "
            f"{valid_levels}, got '{risk_level}'."
        )


_validate_risk_classification(AI_RISK_CLASSIFICATION)

# Patterns for dangerous dynamic code execution primitives in LLM output
_DANGEROUS_CODE_EXEC_PATTERNS = re.compile(
    r'\b(eval|exec|compile|execfile|__import__|subprocess'
    r'|os\.system|os\.popen|os\.exec[a-z]*|os\.spawn[a-z]*'
    r'|commands\.getoutput|commands\.getstatusoutput'
    r'|pty\.spawn|builtins\.__import__)\s*\(',
    re.IGNORECASE,
)


def _sanitize_llm_output(text: str) -> None:
    """Validate LLM output for dynamic code execution primitives.

    Raises ValueError if dangerous patterns are detected in the LLM response.
    """
    matches = _DANGEROUS_CODE_EXEC_PATTERNS.findall(text)
    if matches:
        unique_matches = sorted(set(m.lower().strip() for m in matches))
        logger.warning(
            "LLM output contains dynamic code execution primitives: %s. "
            "Output will be sanitized.",
            unique_matches,
        )
        raise ValueError(
            f"LLM output failed sanitization: detected code execution "
            f"primitives {unique_matches}. Refusing to process untrusted output."
        )

MAX_SCAN_WORKERS = 4
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://lineaje-identity-service.v2.prod.veedna.com"
    "/lineajeidentity/api/v1/auth/native/renew-access-token"
)

# ===========================================================================
# Secure Session Token Handling
# ===========================================================================

_SESSION_TOKEN_SECRET = os.environ.get(
    "_LINEAJE_SESSION_HMAC_SECRET", secrets.token_hex(32)
)
_SESSION_TOKEN_MAX_AGE_SEC = 3600  # 1 hour max session lifetime


class SecureSessionToken:
    """Wraps an MCP session-id with HMAC signing, expiry, and subject binding."""

    def __init__(self, raw_token: str, subject: str) -> None:
        self.raw_token = raw_token
        self.subject = subject
        self.issued_at = time.time()
        self.signature = self._compute_signature()

    def _compute_signature(self) -> str:
        payload = f"{self.raw_token}|{self.subject}|{self.issued_at}"
        return hmac.new(
            _SESSION_TOKEN_SECRET.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, expected_subject: str) -> bool:
        """Verify HMAC signature, expiry, and subject binding."""
        # Check expiry
        if (time.time() - self.issued_at) > _SESSION_TOKEN_MAX_AGE_SEC:
            logger.warning("Session token expired (age=%.0fs)", time.time() - self.issued_at)
            return False
        # Check subject binding
        if not hmac.compare_digest(self.subject, expected_subject):
            logger.warning("Session token subject mismatch")
            return False
        # Verify HMAC integrity
        expected_sig = self._compute_signature()
        if not hmac.compare_digest(self.signature, expected_sig):
            logger.warning("Session token HMAC verification failed")
            return False
        return True

    @staticmethod
    def _compute_hmac(raw_token: str, subject: str, issued_at: float) -> str:
        payload = f"{raw_token}|{subject}|{issued_at}"
        return hmac.new(
            _SESSION_TOKEN_SECRET.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()


def _validate_and_bind_session_id(
    new_session_id: Optional[str],
    current_token: Optional["SecureSessionToken"],
    subject: str,
) -> Optional["SecureSessionToken"]:
    """Validate a new session ID from the server and bind it to the subject.

    Returns a SecureSessionToken if the new ID is acceptable, otherwise
    returns the current token (if still valid) or None.
    """
    if not new_session_id:
        # No new token from server; keep current if still valid
        if current_token and current_token.verify(subject):
            return current_token
        return None

    # Basic sanity: session IDs should be reasonable length, printable ASCII
    if len(new_session_id) > 512 or not new_session_id.isprintable():
        logger.warning("Rejected malformed session-id from server")
        if current_token and current_token.verify(subject):
            return current_token
        return None

    # Create a new signed, bound token
    return SecureSessionToken(raw_token=new_session_id, subject=subject)


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
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {
        "status": status,
        "scan_metadata": {
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "source_code_repo": source_code_repo,
            "scanned_at": generated_at,
            "files_scanned": files_scanned,
            "batches": batches,
            "failed_batches": failed_batches,
        },
        "report": report,
        "violations": violations,
        "aibom": aibom or [],
        "scan_errors": scan_errors or [],
        "provenance": {
            "content_label": "AI-GENERATED: This output was produced by an automated AI-assisted scanning system.",
            "synthetic_origin": True,
            "model_identifier": "lineaje-mcp-scan/1.0",
            "content_origin": "MCP server automated policy scan",
            "generated_at": generated_at,
            "watermark": "SYNTHETIC-CONTENT-LINEAJE-SCAN",
        },
    }
    # Compute HMAC-SHA256 signature over the content for integrity verification
    signing_key = os.environ.get("PROVENANCE_SIGNING_KEY", "lineaje-default-provenance-key")
    content_bytes = json.dumps(result, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(signing_key.encode('utf-8'), content_bytes, hashlib.sha256).hexdigest()
    result["provenance"]["signature_algorithm"] = "HMAC-SHA256"
    result["provenance"]["signature"] = signature
    return result

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

    combined_report = "\n\n---\n\n".join(r for r in all_reports if r)

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details,
        )
        print(json.dumps(output, indent=2))
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        scan_errors=failure_details,
    )
    # Minimise output: only include essential summary fields
    _ALLOWED_OUTPUT_KEYS = {
        "status", "repo", "branch", "head_sha", "scan_id",
        "policy_pass", "violation_count", "error_count", "scan_errors",
    }
    minimised = {k: v for k, v in output.items() if k in _ALLOWED_OUTPUT_KEYS}
    # For violations, include only id, policy, severity, and file path
    if "violations" in output and isinstance(output["violations"], list):
        minimised["violations"] = [
            {k: v for k, v in item.items() if k in ("id", "policy", "severity", "file", "line")}
            for item in output["violations"]
        ]
    # Exclude full markdown report and complete aibom arrays
    print(json.dumps(minimised, indent=2))
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
        help=f"MCP server URL (default: {MCP_SERVER_URL}). Must match an allowed hostname.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    # --- Log retention policy: minimum 6 months (180 days) for high-risk AI systems ---
    LOG_RETENTION_DAYS = 180  # Minimum retention period per AI governance policy
    log_dir = pathlib.Path(os.environ.get("LINEAJE_LOG_DIR", "/var/log/lineaje"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "gha_repo_scan.log"

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    log_datefmt = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format=log_format,
        datefmt=log_datefmt,
        stream=sys.stderr,
    )

    # File handler with timed rotation — retains logs for at least 180 days (6 months)
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=str(log_file),
        when="D",
        interval=1,
        backupCount=LOG_RETENTION_DAYS,
        utc=True,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(fmt=log_format, datefmt=log_datefmt))
    logging.getLogger().addHandler(file_handler)

    logger.info(
        "Log retention configured: retention_days=%d, log_file=%s",
        LOG_RETENTION_DAYS, log_file,
    )

    # Always show INFO from this logger regardless of --debug
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "error_count": 1}
        print(json.dumps(err, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
