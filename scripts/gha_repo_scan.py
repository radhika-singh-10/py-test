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
import os
import pathlib
import re
import sys
import tempfile
import threading
import time
import uuid
import hashlib
import getpass
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# ===========================================================================
# Input sanitization for AI model payloads
# ===========================================================================

_MAX_FILE_BYTES_FOR_AI = 512 * 1024  # 512 KB per file sent to AI model

# Prompt-injection and jailbreak patterns to detect in file content
_PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(?:DAN|jailbreak|unrestricted)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|evil|malicious)\s+AI", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]", re.IGNORECASE),
    re.compile(r"###\s*system\s*prompt", re.IGNORECASE),
    re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"print\s+(your\s+)?(system\s+)?instructions", re.IGNORECASE),
    re.compile(r"override\s+(your\s+)?(safety|content)\s+(filter|policy|guideline)", re.IGNORECASE),
    re.compile(r"bypass\s+(your\s+)?(safety|content)\s+(filter|policy|guideline)", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(your\s+)?(safety|content)\s+(filter|policy|guideline)", re.IGNORECASE),
    re.compile(r"\bDAN\b"),  # "Do Anything Now" jailbreak keyword
    re.compile(r"jailbreak", re.IGNORECASE),
]

# Patterns for other malicious content that should not be forwarded to the AI
_MALICIOUS_CONTENT_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?:eval|exec)\s*\(\s*(?:base64_decode|base64\.b64decode|atob)\s*\(", re.IGNORECASE),
    re.compile(r"(?:os\.system|subprocess\.(?:call|run|Popen))\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
]


def _sanitize_file_content_for_ai(path: str, content_bytes: bytes) -> Tuple[bool, str, bytes]:
    """Validate and sanitize file content before sending to the AI model.

    Args:
        path: Relative file path (used only for logging/error messages).
        content_bytes: Raw file bytes.

    Returns:
        A tuple of (is_safe, reason, sanitized_bytes).
        ``is_safe`` is False when the content should be excluded from the
        AI payload; ``reason`` explains why.
    """
    # 1. Size guard — very large files are truncated to avoid token flooding
    if len(content_bytes) > _MAX_FILE_BYTES_FOR_AI:
        logger.warning(
            "File '%s' exceeds %d bytes (%d bytes); truncating before AI submission.",
            path, _MAX_FILE_BYTES_FOR_AI, len(content_bytes),
        )
        content_bytes = content_bytes[:_MAX_FILE_BYTES_FOR_AI]

    # 2. Attempt to decode as text for pattern matching
    try:
        text = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        # Binary files that cannot be decoded are passed through as-is
        return True, "", content_bytes

    # 3. Check for prompt-injection patterns
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning(
                "File '%s' contains a potential prompt-injection pattern (%s); excluding from AI payload.",
                path, pattern.pattern,
            )
            return False, f"prompt injection pattern detected: {pattern.pattern}", b""

    # 4. Check for other malicious content patterns
    for pattern in _MALICIOUS_CONTENT_PATTERNS:
        if pattern.search(text):
            logger.warning(
                "File '%s' contains a potentially malicious content pattern (%s); excluding from AI payload.",
                path, pattern.pattern,
            )
            return False, f"malicious content pattern detected: {pattern.pattern}", b""

    return True, "", content_bytes

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Prompt-injection / malicious-content sanitization
# ===========================================================================

# Invisible / zero-width Unicode characters often used to hide injected text
_INVISIBLE_CHARS_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u2028\u2029]"
)

# Patterns that look like AI prompt directives embedded in source files
_PROMPT_INJECTION_PHRASES: List[str] = [
    r"ignore (all |previous |above |prior )?instructions?",
    r"disregard (all |previous |above |prior )?instructions?",
    r"forget (all |previous |above |prior )?instructions?",
    r"you are now",
    r"act as (a |an )?(different|new|unrestricted|evil|malicious|jailbreak)",
    r"do not follow",
    r"override (your |all )?(previous |prior )?(instructions?|rules?|constraints?)",
    r"system prompt",
    r"new persona",
    r"jailbreak",
    r"dan mode",
    r"developer mode",
    r"prompt injection",
    r"<\s*system\s*>",
    r"\[system\]",
    r"\[assistant\]",
    r"\[user\]",
    r"### instruction",
    r"### system",
]
_PROMPT_INJECTION_RE = re.compile(
    "|".join(_PROMPT_INJECTION_PHRASES), re.IGNORECASE
)

# Shell / binary command patterns
_SHELL_CMD_RE = re.compile(
    r"(?:^|[\s;|&`$(){}])(?:rm\s+-[rRf]|curl\s+|wget\s+|chmod\s+|chown\s+"
    r"|nc\s+|ncat\s+|bash\s+-[ci]|sh\s+-[ci]|python[23]?\s+-c"
    r"|perl\s+-e|ruby\s+-e|exec\s*\(|system\s*\(|os\.system"
    r"|subprocess\.|eval\s*\(|__import__\s*\()",
    re.MULTILINE,
)

# Leetspeak substitution map for normalisation before phrase matching
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s",
})

# Maximum content length we will forward to the AI agent (bytes)
_MAX_SAFE_CONTENT_BYTES = 512 * 1024  # 512 KB


def _is_likely_base64_payload(text: str) -> bool:
    """Return True if *text* looks like a substantial base64-encoded blob."""
    # Strip whitespace and check character set
    stripped = re.sub(r"[\s]", "", text)
    if len(stripped) < 64:
        return False
    b64_chars = re.sub(r"[A-Za-z0-9+/=]", "", stripped)
    ratio_non_b64 = len(b64_chars) / max(len(stripped), 1)
    if ratio_non_b64 > 0.05:
        return False
    # Try to decode and see if the result contains suspicious strings
    try:
        padding = 4 - len(stripped) % 4
        padded = stripped + "=" * (padding % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        if _PROMPT_INJECTION_RE.search(decoded) or _SHELL_CMD_RE.search(decoded):
            return True
    except Exception:
        pass
    return False


def _sanitize_file_content(path: str, content: str) -> Tuple[str, List[str]]:
    """Sanitize *content* from *path* before forwarding to the AI agent.

    Returns a tuple of (sanitized_content, list_of_warnings).  If dangerous
    content is detected the offending sections are replaced with a safe
    placeholder so the scan can still proceed on the remaining content.
    """
    warnings: List[str] = []

    # 1. Enforce maximum size
    if len(content.encode("utf-8", errors="replace")) > _MAX_SAFE_CONTENT_BYTES:
        content = content.encode("utf-8", errors="replace")[:_MAX_SAFE_CONTENT_BYTES].decode(
            "utf-8", errors="replace"
        )
        warnings.append(f"{path}: content truncated to {_MAX_SAFE_CONTENT_BYTES} bytes")

    # 2. Strip invisible / zero-width characters
    cleaned = _INVISIBLE_CHARS_RE.sub("", content)
    if cleaned != content:
        warnings.append(f"{path}: invisible/zero-width characters removed")
        content = cleaned

    # 3. Check for prompt-injection phrases (plain text)
    if _PROMPT_INJECTION_RE.search(content):
        warnings.append(
            f"{path}: potential prompt-injection directive detected and redacted"
        )
        content = _PROMPT_INJECTION_RE.sub("[REDACTED-INJECTION]", content)

    # 4. Check leetspeak-normalised version for prompt-injection phrases
    leet_normalised = content.translate(_LEET_MAP)
    if _PROMPT_INJECTION_RE.search(leet_normalised):
        warnings.append(
            f"{path}: leetspeak-encoded prompt-injection directive detected and redacted"
        )
        # Redact line-by-line to preserve as much legitimate content as possible
        safe_lines = []
        for line in content.splitlines(keepends=True):
            if _PROMPT_INJECTION_RE.search(line.translate(_LEET_MAP)):
                safe_lines.append("[REDACTED-INJECTION]\n")
            else:
                safe_lines.append(line)
        content = "".join(safe_lines)

    # 5. Check for base64-encoded payloads containing injections
    for token in re.findall(r"[A-Za-z0-9+/=]{64,}", content):
        if _is_likely_base64_payload(token):
            warnings.append(
                f"{path}: base64-encoded prompt-injection payload detected and redacted"
            )
            content = content.replace(token, "[REDACTED-BASE64-INJECTION]")

    # 6. Check for embedded shell / binary commands
    if _SHELL_CMD_RE.search(content):
        # Only warn — shell commands are legitimate in many source files;
        # we log the warning but do NOT redact to avoid breaking real code.
        warnings.append(
            f"{path}: shell/binary command pattern detected — review recommended"
        )

    return content, warnings


def _sanitize_file_payloads(
    file_payloads: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Run :func:`_sanitize_file_content` over every payload in *file_payloads*.

    Returns ``(sanitized_payloads, all_warnings)``.
    """
    sanitized: List[Dict[str, Any]] = []
    all_warnings: List[str] = []
    for payload in file_payloads:
        path = payload.get("path", "<unknown>")
        content = payload.get("content", "")
        if isinstance(content, str):
            safe_content, warnings = _sanitize_file_content(path, content)
            for w in warnings:
                logger.warning("[sanitize] %s", w)
            all_warnings.extend(warnings)
            payload = {**payload, "content": safe_content}
        sanitized.append(payload)
    return sanitized, all_warnings

# ===========================================================================
# Content Sanitization — prompt injection defence
# ===========================================================================

# Invisible / confusable Unicode ranges commonly used for hidden prompts
_INVISIBLE_UNICODE_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u2028\u2029]"
)

# Patterns that look like AI directive injection attempts
_PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)"
    r"|disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)"
    r"|you\s+are\s+now\s+(a|an)\s+"
    r"|act\s+as\s+(a|an)\s+"
    r"|new\s+instructions?\s*:"
    r"|system\s*:\s*(you|ignore|forget)"
    r"|<\s*system\s*>.*?<\s*/\s*system\s*>"
    r"|\[\s*system\s*\].*?\[\s*/\s*system\s*\])"
)

# Leetspeak substitution map for normalisation before pattern matching
_LEET_MAP = str.maketrans("013456789", "oieaasbtg")

# Base64 alphabet — used to detect large embedded base64 blobs
_B64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{60,}={0,2})")

# Shell / binary executable magic bytes
_BINARY_MAGIC: list[bytes] = [
    b"\x7fELF",          # ELF executable
    b"MZ",               # PE/DOS executable
    b"\xca\xfe\xba\xbe", # Mach-O fat binary
    b"\xfe\xed\xfa\xce", # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf", # Mach-O 64-bit
    b"\xcf\xfa\xed\xfe", # Mach-O 64-bit LE
    b"\xce\xfa\xed\xfe", # Mach-O 32-bit LE
    b"#!",               # shebang (only flag if followed by /bin or /usr)
]

_SHEBANG_SHELL_RE = re.compile(rb"^#!\s*/(?:bin|usr)/")

# Suspicious shell command patterns inside text files
_SHELL_CMD_RE = re.compile(
    r"(?i)(\bcurl\b.*\bsh\b|\bwget\b.*\bsh\b|\beval\b\s*\(|\bexec\b\s*\("
    r"|\bos\.system\b|\bsubprocess\.(?:call|run|Popen)\b.*shell\s*=\s*True"
    r"|\bpowershell\b.*-[Ee]nc\b)"
)


class ContentSanitizationError(ValueError):
    """Raised when file content fails sanitization checks."""


def _sanitize_file_content(path: str, content_bytes: bytes) -> bytes:
    """Inspect *content_bytes* for prompt-injection and malicious payloads.

    Returns the (possibly lightly redacted) bytes that are safe to forward
    to the AI agent, or raises :class:`ContentSanitizationError` when the
    content cannot be made safe.

    Checks performed
    ----------------
    1. Binary executable / shell-script magic bytes.
    2. Invisible / hidden Unicode characters used for prompt smuggling.
    3. Embedded base64 blobs that may encode secondary prompts.
    4. Leetspeak-normalised prompt-injection keyword patterns.
    5. Suspicious shell commands embedded in text files.
    """
    # ------------------------------------------------------------------
    # 1. Binary executable detection
    # ------------------------------------------------------------------
    for magic in _BINARY_MAGIC:
        if content_bytes.startswith(magic):
            # Allow shebangs only for well-known interpreters (python, node …)
            # but reject raw shell invocations.
            if magic == b"#!" and _SHEBANG_SHELL_RE.match(content_bytes):
                raise ContentSanitizationError(
                    f"{path}: rejected — shell-script shebang detected"
                )
            if magic != b"#!":
                raise ContentSanitizationError(
                    f"{path}: rejected — binary executable magic bytes detected"
                )

    # Heuristic: high ratio of non-printable bytes → binary
    if len(content_bytes) > 0:
        non_printable = sum(
            1 for b in content_bytes[:2048] if b < 0x09 or (0x0e <= b <= 0x1f)
        )
        if non_printable / min(len(content_bytes), 2048) > 0.10:
            raise ContentSanitizationError(
                f"{path}: rejected — high proportion of non-printable bytes (likely binary)"
            )

    # ------------------------------------------------------------------
    # Decode to text for remaining checks (best-effort)
    # ------------------------------------------------------------------
    try:
        text = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise ContentSanitizationError(
            f"{path}: rejected — unable to decode content as text"
        )

    # ------------------------------------------------------------------
    # 2. Invisible / hidden Unicode characters
    # ------------------------------------------------------------------
    invisible_matches = _INVISIBLE_UNICODE_RE.findall(text)
    if invisible_matches:
        logger.warning(
            "%s: stripping %d invisible/hidden Unicode character(s) before upload",
            path, len(invisible_matches),
        )
        text = _INVISIBLE_UNICODE_RE.sub("", text)

    # ------------------------------------------------------------------
    # 3. Embedded base64 blobs — decode and check for nested prompts
    # ------------------------------------------------------------------
    for blob_match in _B64_BLOB_RE.finditer(text):
        blob = blob_match.group(0)
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8", errors="replace")
            if _PROMPT_INJECTION_RE.search(decoded):
                raise ContentSanitizationError(
                    f"{path}: rejected — base64-encoded prompt injection detected"
                )
        except (ValueError, UnicodeDecodeError):
            pass  # not valid base64 text — ignore

    # ------------------------------------------------------------------
    # 4. Leetspeak-normalised prompt injection
    # ------------------------------------------------------------------
    normalised = text.lower().translate(_LEET_MAP)
    if _PROMPT_INJECTION_RE.search(normalised):
        raise ContentSanitizationError(
            f"{path}: rejected — prompt injection pattern detected (including leetspeak variants)"
        )

    # Also check the original text (catches mixed-case without leet)
    if _PROMPT_INJECTION_RE.search(text):
        raise ContentSanitizationError(
            f"{path}: rejected — prompt injection directive detected"
        )

    # ------------------------------------------------------------------
    # 5. Suspicious shell commands
    # ------------------------------------------------------------------
    if _SHELL_CMD_RE.search(text):
        logger.warning(
            "%s: suspicious shell command pattern detected — flagging but allowing upload",
            path,
        )
        # Prepend a warning comment so the AI model is aware
        warning_header = (
            "# [SECURITY WARNING] This file contains patterns resembling shell commands.\n"
            "# Content has been flagged by the upload sanitizer.\n"
        )
        text = warning_header + text

    return text.encode("utf-8")

# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------

# Maximum file size (bytes) accepted for MCP transmission (5 MB)
_MAX_FILE_BYTES = 5 * 1024 * 1024

# Prompt-injection / jailbreak patterns to detect in file content
_PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(rb"ignore (all |previous |prior |above |the above |your |all previous )"
               rb"(instructions?|prompts?|rules?|constraints?|guidelines?)",
               re.IGNORECASE),
    re.compile(rb"you are now\.{0,10}(DAN|jailbreak|unrestricted|evil|unfiltered)",
               re.IGNORECASE),
    re.compile(rb"<\s*system\s*>", re.IGNORECASE),
    re.compile(rb"\[INST\]", re.IGNORECASE),
    re.compile(rb"###\s*(Instruction|System|Human|Assistant)\s*:", re.IGNORECASE),
    re.compile(rb"IGNORE PREVIOUS", re.IGNORECASE),
    re.compile(rb"disregard (all |your |the )?(previous |prior |above )?(instructions?|rules?)",
               re.IGNORECASE),
]


def _sanitize_file_content(raw: bytes, file_path: str) -> bytes:
    """Validate and sanitize raw file bytes before MCP transmission.

    Raises ``ValueError`` if the content is rejected outright.
    Returns sanitized bytes safe to base64-encode and forward.
    """
    # 1. Size guard — refuse oversized files
    if len(raw) > _MAX_FILE_BYTES:
        raise ValueError(
            f"File '{file_path}' exceeds maximum allowed size "
            f"({len(raw)} > {_MAX_FILE_BYTES} bytes); skipping MCP transmission."
        )

    # 2. Null-byte check — binary files that slipped through filtering
    if b"\x00" in raw:
        raise ValueError(
            f"File '{file_path}' contains null bytes (binary content); "
            "skipping MCP transmission."
        )

    # 3. Prompt-injection / jailbreak pattern detection
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(raw):
            raise ValueError(
                f"File '{file_path}' contains a potential prompt-injection payload "
                f"(matched pattern: {pattern.pattern!r}); skipping MCP transmission."
            )

    # 4. Strip leading/trailing whitespace from text content to normalise
    sanitized = raw.strip()

    return sanitized

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

# ---------------------------------------------------------------------------
# Tool allow list — ONLY tools enumerated here may be invoked via the MCP
# client. Any tool not on this list is denied and audited before the call
# is made. To add a tool, it must be reviewed and added explicitly here.
# ---------------------------------------------------------------------------
_TOOL_ALLOW_LIST: frozenset = frozenset({
    "scan_files",
    "get_policy_report",
    "list_policies",
    "get_aibom",
})

_TOOL_POLICY_VERSION = "v1.0.0"
_TOOL_POLICY_ACTOR = "gha_repo_scan"


def _audit_log(entry: dict) -> None:
    """Write an audit log entry to stderr (protected sink, not captured by
    stdout JSON output consumed by callers)."""
    print(json.dumps(entry), file=sys.stderr, flush=True)


def enforce_tool_allow_list(tool_name: str) -> None:
    """Raise PermissionError if *tool_name* is not on the explicit allow list.

    Always writes an audit record — approved or denied — so that every tool
    invocation attempt is traceable.

    Args:
        tool_name: The name of the MCP tool about to be invoked.

    Raises:
        PermissionError: When *tool_name* is not in ``_TOOL_ALLOW_LIST``.
    """
    allowed = tool_name in _TOOL_ALLOW_LIST
    audit_entry = {
        "event": "tool_invocation_allowed" if allowed else "tool_invocation_denied",
        "actor": _TOOL_POLICY_ACTOR,
        "tool_id": tool_name,
        "policy_version": _TOOL_POLICY_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if not allowed:
        audit_entry["denial_reason"] = (
            f"Tool '{tool_name}' is not present in the explicit allow list "
            f"(policy {_TOOL_POLICY_VERSION}). Add it to _TOOL_ALLOW_LIST "
            "after security review to permit invocation."
        )
        _audit_log(audit_entry)
        raise PermissionError(audit_entry["denial_reason"])
    _audit_log(audit_entry)


def _log_mcp_request(batch_index: int, tool_name: str, payload: Any) -> None:
    """Log an outgoing MCP server request."""
    logger.info(
        "MCP request | batch=%d tool=%s url=%s payload_keys=%s",
        batch_index,
        tool_name,
        MCP_SERVER_URL,
        list(payload.keys()) if isinstance(payload, dict) else type(payload).__name__,
    )
    logger.debug("MCP request payload | batch=%d payload=%s", batch_index, json.dumps(payload, default=str))


def _log_mcp_response(batch_index: int, tool_name: str, response: Any, elapsed: float) -> None:
    """Log an incoming MCP server response."""
    status = "ok" if response is not None else "null"
    if isinstance(response, dict):
        status = response.get("status", response.get("error", "ok"))
    logger.info(
        "MCP response | batch=%d tool=%s url=%s status=%s elapsed_sec=%.3f",
        batch_index,
        tool_name,
        MCP_SERVER_URL,
        status,
        elapsed,
    )
    logger.debug("MCP response payload | batch=%d response=%s", batch_index, json.dumps(response, default=str))

MAX_SCAN_WORKERS = 4
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://lineaje-identity-service.v2.prod.veedna.com"
    "/lineajeidentity/api/v1/auth/native/renew-access-token"
)

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
    _MAX_STRING_LEN = 2048
    _MAX_LIST_ITEMS = 500

    def _sanitize_str(s: Any) -> str:
        """Truncate strings to a safe maximum length."""
        s = str(s)
        return s[:_MAX_STRING_LEN] + "...[truncated]" if len(s) > _MAX_STRING_LEN else s

    def _sanitize_violation(v: Any) -> Dict[str, Any]:
        """Return only the allowed fields from a violation dict."""
        if not isinstance(v, dict):
            return {}
        allowed = {"rule", "severity", "file", "line", "message", "category"}
        return {k: _sanitize_str(v[k]) for k in allowed if k in v}

    def _sanitize_aibom_entry(e: Any) -> Dict[str, str]:
        """Return only the allowed fields from an AIBOM entry dict."""
        if not isinstance(e, dict):
            return {}
        allowed = {"name", "version", "type", "license", "purl"}
        return {k: _sanitize_str(e[k]) for k in allowed if k in e}

    def _sanitize_error(err: Any) -> str:
        """Return a sanitized, truncated error string."""
        return _sanitize_str(err)

    sanitized_violations = [
        _sanitize_violation(v)
        for v in (violations or [])[:_MAX_LIST_ITEMS]
    ]
    sanitized_aibom = [
        _sanitize_aibom_entry(e)
        for e in (aibom or [])[:_MAX_LIST_ITEMS]
    ]
    sanitized_errors = [
        _sanitize_error(e)
        for e in (scan_errors or [])[:100]
    ]
    sanitized_report = _sanitize_str(report) if report else ""

    return {
        "status": status if status in ("compliant", "non-compliant", "error") else "error",
        "scan_metadata": {
            "repo": _sanitize_str(repo),
            "branch": _sanitize_str(branch),
            "head_sha": _sanitize_str(head_sha),
            "source_code_repo": _sanitize_str(source_code_repo),
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": int(files_scanned),
            "batches": int(batches),
            "failed_batches": int(failed_batches),
        },
        "report": sanitized_report,
        "violations": sanitized_violations,
        "aibom": sanitized_aibom,
        "scan_errors": sanitized_errors,
    }

# ===========================================================================
# Audit logging — persistent append-only sink
# ===========================================================================

AUDIT_LOG_PATH = os.environ.get("SCAN_AUDIT_LOG", "/var/log/gha_repo_scan_audit.jsonl")
_AUDIT_MODEL_ID = os.environ.get("MCP_MODEL_ID", "mcp-policy-scanner")
_AUDIT_MODEL_VERSION = os.environ.get("MCP_MODEL_VERSION", "unknown")


def _audit_principal() -> str:
    """Return the acting principal: CI actor, git user, or OS user."""
    for env in ("GITHUB_ACTOR", "GIT_AUTHOR_NAME", "USER", "USERNAME"):
        val = os.environ.get(env, "")
        if val:
            return val
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _sha256_of(data: Any) -> str:
    """Return a SHA-256 hex digest of the JSON-serialised form of *data*."""
    raw = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def write_audit_record(
    *,
    trace_id: str,
    action: str,
    input_data: Any,
    output_data: Any,
    principal: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Append a single structured audit record to the persistent audit log.

    Raises RuntimeError (fail-closed) if the sink cannot be written to,
    so callers must handle or propagate the error — execution must NOT
    silently continue without a successful audit write.
    """
    record = {
        "trace_id": trace_id,
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "action": action,
        "principal": principal,
        "model_id": _AUDIT_MODEL_ID,
        "model_version": _AUDIT_MODEL_VERSION,
        "input_hash": _sha256_of(input_data),
        "output_hash": _sha256_of(output_data),
        **(extra or {}),
    }
    line = json.dumps(record, default=str)
    try:
        audit_dir = os.path.dirname(os.path.abspath(AUDIT_LOG_PATH))
        os.makedirs(audit_dir, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except Exception as exc:
        # Fail closed: surface the error so the caller can decide to abort.
        raise RuntimeError(
            f"AUDIT SINK UNREACHABLE — cannot write to {AUDIT_LOG_PATH!r}: {exc}"
        ) from exc


def emit_output(
    output: Dict[str, Any],
    *,
    trace_id: str,
    action: str = "scan_result",
    input_data: Any = None,
    principal: str = "",
) -> None:
    """
    Write the audit record first (fail-closed), then print to stdout.
    """
    write_audit_record(
        trace_id=trace_id,
        action=action,
        input_data=input_data if input_data is not None else {},
        output_data=output,
        principal=principal or _audit_principal(),
    )
    print(json.dumps(output, indent=2))


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
        emit_output(
            output,
            trace_id=trace_id if 'trace_id' in dir() else "pre-init",
            action="scan_error_missing_config",
            input_data={"repo": repo, "branch": branch},
            principal=_audit_principal(),
        )
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
        emit_output(
            output,
            trace_id="pre-init",
            action="scan_error_auth",
            input_data={"repo": repo, "branch": branch},
            principal=_audit_principal(),
        )
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    trace_id = str(uuid.uuid4())  # Shared correlation ID for all batches in this run
    principal = _audit_principal()
    logger.info("Audit trace_id=%s principal=%s", trace_id, principal)
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
        emit_output(
            output,
            trace_id=trace_id,
            action="scan_no_files",
            input_data={"source_path": source_path},
            principal=principal,
        )
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
        # Pass trace_id into the scan context so every batch log is correlated
        logger.info("Starting MCP batch scans trace_id=%s batches=%d", trace_id, len(batches))
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

    # Validate and sanitize LLM/MCP output for dynamic code execution primitives
    all_violations = _sanitize_llm_output_list(all_violations, "violations")
    all_aibom = _sanitize_llm_output_list(all_aibom, "aibom")
    combined_report = _sanitize_llm_output_str(combined_report, "report")

    # Sanitize and validate all MCP server output before use
    sanitized_violations = _sanitize_mcp_violations(all_violations)
    sanitized_aibom = _sanitize_mcp_aibom(all_aibom)
    sanitized_report = _sanitize_mcp_report(combined_report)

    if failed_batches_count and not sanitized_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=sanitized_aibom, report=sanitized_report,
            scan_errors=failure_details,
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
        violations=sanitized_violations, aibom=sanitized_aibom, report=sanitized_report,
        scan_errors=failure_details,
    )
    print(json.dumps(output, indent=2))
    return 0

# ===========================================================================
# CLI
# ===========================================================================

# ---------------------------------------------------------------------------
# MCP output sanitization helpers
# ---------------------------------------------------------------------------

_MAX_STRING_LEN = 65536  # maximum allowed length for any string field from MCP
_MAX_LIST_LEN = 10000    # maximum number of items allowed in violations/aibom lists
_ALLOWED_VIOLATION_KEYS = {
    "rule", "severity", "message", "file", "line", "column",
    "snippet", "recommendation", "category", "id",
}
_ALLOWED_AIBOM_KEYS = {
    "name", "version", "type", "license", "source", "file",
    "checksum", "purl", "supplier", "description",
}


def _sanitize_string(value: object, max_len: int = _MAX_STRING_LEN) -> str:
    """Coerce *value* to a plain string and truncate to *max_len* characters."""
    if not isinstance(value, str):
        value = str(value) if value is not None else ""
    # Strip null bytes and control characters that could cause issues downstream
    value = value.replace("\x00", "")
    return value[:max_len]


def _sanitize_mcp_record(
    record: object,
    allowed_keys: set,
) -> dict:
    """Return a sanitized copy of a single dict record from the MCP server.

    * Only keys present in *allowed_keys* are kept (unknown keys are dropped).
    * Every value is coerced to a plain, length-capped string.
    """
    if not isinstance(record, dict):
        logger.warning("MCP record is not a dict (type=%s); skipping", type(record).__name__)
        return {}
    sanitized: dict = {}
    for key in allowed_keys:
        if key in record:
            sanitized[key] = _sanitize_string(record[key])
    return sanitized


def _sanitize_mcp_violations(violations: object) -> list:
    """Validate and sanitize the violations list returned by the MCP server."""
    if not isinstance(violations, list):
        logger.warning(
            "MCP violations response is not a list (type=%s); treating as empty",
            type(violations).__name__,
        )
        return []
    if len(violations) > _MAX_LIST_LEN:
        logger.warning(
            "MCP violations list exceeds maximum length (%d > %d); truncating",
            len(violations), _MAX_LIST_LEN,
        )
        violations = violations[:_MAX_LIST_LEN]
    sanitized = []
    for idx, item in enumerate(violations):
        clean = _sanitize_mcp_record(item, _ALLOWED_VIOLATION_KEYS)
        if clean:
            sanitized.append(clean)
        else:
            logger.warning("MCP violation at index %d was invalid and has been dropped", idx)
    return sanitized


def _sanitize_mcp_aibom(aibom: object) -> list:
    """Validate and sanitize the AIBOM list returned by the MCP server."""
    if not isinstance(aibom, list):
        logger.warning(
            "MCP AIBOM response is not a list (type=%s); treating as empty",
            type(aibom).__name__,
        )
        return []
    if len(aibom) > _MAX_LIST_LEN:
        logger.warning(
            "MCP AIBOM list exceeds maximum length (%d > %d); truncating",
            len(aibom), _MAX_LIST_LEN,
        )
        aibom = aibom[:_MAX_LIST_LEN]
    sanitized = []
    for idx, item in enumerate(aibom):
        clean = _sanitize_mcp_record(item, _ALLOWED_AIBOM_KEYS)
        if clean:
            sanitized.append(clean)
        else:
            logger.warning("MCP AIBOM entry at index %d was invalid and has been dropped", idx)
    return sanitized


def _sanitize_mcp_report(report: object) -> str:
    """Validate and sanitize the combined report string returned by the MCP server."""
    if not isinstance(report, str):
        logger.warning(
            "MCP report is not a string (type=%s); coercing",
            type(report).__name__,
        )
    return _sanitize_string(report, max_len=_MAX_STRING_LEN * 10)  # reports may be larger


# ---------------------------------------------------------------------------
# LLM output sanitization
# ---------------------------------------------------------------------------

# Patterns that indicate dynamic code execution primitives that must not appear
# in LLM/MCP responses used by this agent.
_DANGEROUS_PATTERNS: list = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\bexecfile\s*\(', re.IGNORECASE),
    re.compile(r'\bcompile\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\(', re.IGNORECASE),
    re.compile(r'\bimportlib\.import_module\s*\(', re.IGNORECASE),
    re.compile(r'\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True', re.IGNORECASE | re.DOTALL),
    re.compile(r'\bos\s*\.\s*system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\s*\.\s*popen\s*\(', re.IGNORECASE),
    re.compile(r'\bctypes\b', re.IGNORECASE),
]


def _contains_dangerous_content(text: str) -> Optional[str]:
    """Return the first matching dangerous pattern description, or None if safe."""
    for pattern in _DANGEROUS_PATTERNS:
        m = pattern.search(text)
        if m:
            return pattern.pattern
    return None


def _sanitize_llm_output_str(text: str, field_name: str) -> str:
    """Validate a string field from LLM/MCP output for dangerous primitives.

    If a dangerous pattern is detected the offending content is replaced with
    a redaction notice and a warning is logged so the pipeline can continue
    safely while the issue is surfaced.
    """
    if not text:
        return text
    matched = _contains_dangerous_content(text)
    if matched:
        logger.warning(
            "[SECURITY] Dangerous code execution primitive detected in LLM/MCP "
            "output field '%s' (pattern: %s). Content redacted.",
            field_name, matched,
        )
        return "[REDACTED: LLM output contained a dangerous code execution primitive]"
    return text


def _sanitize_llm_output_list(items: list, field_name: str) -> list:
    """Validate a list of dicts/strings from LLM/MCP output.

    Each element is serialised to JSON and checked for dangerous primitives.
    Elements that contain dangerous content are replaced with a safe sentinel.
    """
    if not items:
        return items
    sanitized: list = []
    for idx, item in enumerate(items):
        try:
            serialised = json.dumps(item, ensure_ascii=False)
        except (TypeError, ValueError):
            serialised = str(item)
        matched = _contains_dangerous_content(serialised)
        if matched:
            logger.warning(
                "[SECURITY] Dangerous code execution primitive detected in LLM/MCP "
                "output field '%s'[%d] (pattern: %s). Entry redacted.",
                field_name, idx, matched,
            )
            sanitized.append({"redacted": True, "reason": "dangerous code execution primitive detected"})
        else:
            sanitized.append(item)
    return sanitized


# ---------------------------------------------------------------------------
# URL allowlist validation
# ---------------------------------------------------------------------------

_ALLOWED_HOSTNAMES: frozenset = frozenset({
    # Derive allowed hostnames from the hardcoded production constants so the
    # allowlist stays in sync with the defaults automatically.
    urllib.parse.urlparse(_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD).hostname,
    urllib.parse.urlparse(MCP_SERVER_URL).hostname,
})


def _validate_url_allowlist(url: str, param_name: str = "URL") -> str:
    """Validate *url* against the hostname allowlist.

    Returns the URL unchanged when it passes validation.
    Raises ``ValueError`` when the scheme is not https or the hostname is not
    in ``_ALLOWED_HOSTNAMES``.
    """
    if not url:
        return url
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        raise ValueError(f"{param_name} is not a valid URL: {url!r}") from exc
    if parsed.scheme not in ("https",):
        raise ValueError(
            f"{param_name} must use the https scheme, got {parsed.scheme!r}: {url!r}"
        )
    hostname = (parsed.hostname or "").lower()
    if hostname not in _ALLOWED_HOSTNAMES:
        raise ValueError(
            f"{param_name} hostname {hostname!r} is not in the allowed list "
            f"{sorted(_ALLOWED_HOSTNAMES)}: {url!r}"
        )
    return url


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
        help=f"MCP server URL (default: {MCP_SERVER_URL}); must be one of the allowed hostnames: {sorted(_ALLOWED_HOSTNAMES)}",
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

    # Validate user-supplied URLs against the allowlist before any HTTP is attempted.
    if args.mcp_server_url:
        try:
            _validate_url_allowlist(args.mcp_server_url, "--mcp-server-url")
        except ValueError as exc:
            logger.error("URL allowlist violation: %s", exc)
            err = {"status": "error", "scan_errors": [str(exc)]}
            print(json.dumps(err, indent=2))
            return 1

    renew_url_env = os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL", "")
    if renew_url_env:
        try:
            _validate_url_allowlist(renew_url_env, "LINEAJE_RENEW_ACCESS_TOKEN_URL")
        except ValueError as exc:
            logger.error("URL allowlist violation: %s", exc)
            err = {"status": "error", "scan_errors": [str(exc)]}
            print(json.dumps(err, indent=2))
            return 1

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error trace_id=%s", trace_id if 'trace_id' in locals() else 'pre-init')
        try:
            write_audit_record(
                trace_id=trace_id if 'trace_id' in locals() else 'pre-init',
                action="scan_unhandled_error",
                input_data={"repo": repo if 'repo' in locals() else ""},
                output_data={"error": str(locals().get('exc', 'unknown'))},
                principal=_audit_principal(),
            )
        except RuntimeError as audit_exc:
            logger.critical("AUDIT SINK UNREACHABLE during unhandled error: %s", audit_exc)
        err = {"status": "error", "scan_errors": ["An internal error occurred. Consult administrator."]}
        print(json.dumps(err, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
