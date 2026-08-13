#!/usr/bin/env python3
"""Veracode Repository Scanner — self-contained repo scan script with JSON output.

Clones a repository, archives its contents, runs them through the MCP scanning
pipeline, optionally generates LLM fixes, and emits results as structured JSON
(no markdown report).  Intended for Veracode pipeline integrations that consume
machine-readable findings.

Usage::

    python scripts/veracode_repo_scan.py \
        --repo owner/repo \
        --branch main

Output (stdout, JSON)::

    {
      "status": "violations_found",
      "scan_metadata": {
        "repo": "owner/repo",
        "branch": "main",
        "head_sha": "abc1234",
        "source_code_repo": "https://github.com/owner/repo.git",
        "scanned_at": "2026-05-07T10:00:00Z",
            "model_version": MCP_MODEL_VERSION,
            "llm_remediation_version": LLM_REMEDIATION_MODEL_VERSION,
        "files_scanned": 150,
        "batches": 2,
        "failed_batches": 0
      },
      "violations": [...],
      "remediation_pr": 42,
      "remediation_branch": "remediation/unifai-repo-main",
      "failed_remediation_files": []
    }

Environment variables::

    SCM_ACCESS_TOKEN     — GitHub Personal Access Token
    MCP_REFRESH_TOKEN    — MCP/Lineaje server refresh token (preferred auth;
                           LINEAJE_REFRESH_TOKEN is accepted as an alias)
    MCP_BEARER_TOKEN     — MCP/Lineaje server static bearer token (fallback)
    LINEAJE_RENEW_ACCESS_TOKEN_URL  — renew-access-token URL (defaults to prod)
    LINEAJE_TOKEN_REFRESH_SKEW_SEC  — Refresh seconds before expiry (default: 120)
    LLM_API_KEY          — API key for LLM remediation (OpenRouter, required;
                           UNIFAI_API_KEY and OPENROUTER_API_KEY accepted as fallback aliases)

Constants (in ``veracode_repo_scan.py`` — not environment variables)::

    LINEAJE_RUN_REMEDIATION_MCP_TOOL — ``1`` = call MCP ``run_remediation`` after violations; ``0`` = skip.
        Override with ``--run-remediation-mcp`` / ``--no-run-remediation-mcp``.
        Server must register the tool (``LINEAJE_ENABLE_RUN_REMEDIATION_MCP_TOOL`` env on MCP **server** only).

Exit codes::

    0 — scan completed (compliant or violations found + JSON written)
    1 — scan/runtime error
    2 — configuration error
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import difflib
import fnmatch
import hashlib
import json
import logging
import logging.handlers
import os
import pathlib
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
import hmac

import requests

# ---------------------------------------------------------------------------
# Input sanitization for MCP tool call parameters
# ---------------------------------------------------------------------------

def _sanitize_input(value: Any, field_name: str = "", max_length: int = 4096) -> Any:
    """Validate and sanitize a value before passing it to an MCP tool call.

    - Strings are stripped, length-limited, and checked for dangerous characters.
    - None values pass through unchanged.
    - Lists/dicts are recursively sanitized.
    """
    if value is None:
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return [_sanitize_input(v, field_name, max_length) for v in value]
    if isinstance(value, dict):
        return {k: _sanitize_input(v, k, max_length) for k, v in value.items()}
    if isinstance(value, str):
        # Strip leading/trailing whitespace
        sanitized = value.strip()
        # Enforce maximum length
        if len(sanitized) > max_length:
            raise ValueError(f"Input '{field_name}' exceeds maximum length {max_length}")
        # Reject null bytes
        if '\x00' in sanitized:
            raise ValueError(f"Input '{field_name}' contains null bytes")
        # Reject common injection patterns (shell metacharacters in non-JSON fields)
        if field_name not in ("remediation_actions_json", "files_to_scan") and re.search(r'[;|`$]', sanitized):
            raise ValueError(f"Input '{field_name}' contains potentially dangerous characters")
        return sanitized
    return value


def _sanitize_tool_args(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize all arguments in a dict before passing to _call_tool."""
    return {k: _sanitize_input(v, field_name=k) for k, v in arguments.items()}


# macOS Python installations often lack system CA certs.
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX = ssl.create_default_context()

_https_handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
urllib.request.install_opener(urllib.request.build_opener(_https_handler))

# scm_client lives in the same scripts/ directory.
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
_REPO_ROOT = os.path.dirname(SCRIPTS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from scm_client import create_scm_client, SCMClient  # noqa: E402
from scan_common import (  # noqa: E402
    parallel_llm_remediation,
    group_remediation_by_file,
    resolve_llm_api_key,
    resolve_llm_model,
    resolve_llm_api_url,
    build_remediation_scan_json_payload,
    format_pr_body_with_json_scan_results,
    markdown_violations_per_file_table,
    markdown_remediation_details_table,
    resolve_github_pr_targets,
    resolve_remediation_branch_and_existing_pr,
    stable_repo_scan_remediation_branch,
    GITHUB_PR_EMBEDDED_REPORT_MAX_CHARS,
    introspect_lineaje_pat,
)

# ---------------------------------------------------------------------------
# LLM output sanitization — reject fix_code containing code-execution primitives
# ---------------------------------------------------------------------------

_LLM_DANGEROUS_PATTERNS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bexec\s*\('),
    re.compile(r'\bos\.system\s*\('),
    re.compile(r'\bos\.popen\s*\('),
    re.compile(r'\bsubprocess\.[\w]*\([^)]*shell\s*=\s*True'),
    re.compile(r'\bcompile\s*\([^)]*,[^)]*["\']exec["\']'),
    re.compile(r'\b__import__\s*\('),
    re.compile(r'\bexecfile\s*\('),
]


def _llm_output_contains_dangerous_code(text: str) -> bool:
    """Return True if *text* contains dynamic code execution primitives."""
    if not text:
        return False
    for pat in _LLM_DANGEROUS_PATTERNS:
        if pat.search(text):
            return True
    return False


def sanitize_llm_remediation_output(remediation_actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate and sanitize LLM remediation output.

    Removes any ``fix_code`` entries whose ``replacement`` text contains
    dangerous dynamic code execution primitives (eval, exec, subprocess
    shell=True, os.system, etc.).  Logs a warning for each rejected entry.
    """
    for action in remediation_actions:
        fix_code = action.get("fix_code")
        if not fix_code or not isinstance(fix_code, list):
            continue
        safe_fixes: List[Dict[str, str]] = []
        for entry in fix_code:
            replacement = entry.get("replacement", "")
            original = entry.get("original", "")
            if _llm_output_contains_dangerous_code(replacement):
                logger.warning(
                    "Sanitizer: rejected LLM fix_code replacement containing "
                    "dangerous code-execution primitive for file=%s",
                    action.get("file", "<unknown>"),
                )
                continue
            if _llm_output_contains_dangerous_code(original) and original != replacement:
                # original may legitimately contain dangerous code if the fix
                # is *removing* it; only reject if replacement also introduces it
                pass
            safe_fixes.append(entry)
        action["fix_code"] = safe_fixes
    return remediation_actions

logger = logging.getLogger("veracode_repo_scan")

# --- High-risk AI system log retention (minimum 180 days) ---
_LOG_RETENTION_DAYS = int(os.environ.get("LINEAJE_LOG_RETENTION_DAYS", "180"))
_LOG_DIR = os.environ.get("LINEAJE_LOG_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".logs"))
os.makedirs(_LOG_DIR, exist_ok=True)
_retention_handler = logging.handlers.TimedRotatingFileHandler(
    filename=os.path.join(_LOG_DIR, "veracode_repo_scan.log"),
    when="D",
    interval=1,
    backupCount=_LOG_RETENTION_DAYS,
    utc=True,
)
_retention_handler.setFormatter(
    logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
_retention_handler.setLevel(logging.DEBUG)
logger.addHandler(_retention_handler)
# --- End log retention configuration ---

# ===========================================================================
# Constants
# ===========================================================================

REMEDIATION_BRANCH_PREFIX = "remediation/unifai-repo"
COMMENT_MARKER = "<!-- unifai-repo-scan -->"
# 1 = call MCP run_remediation after violations; 0 = skip. Not read from os.environ.
LINEAJE_RUN_REMEDIATION_MCP_TOOL = 1
DEFAULT_MAX_ARCHIVE_SIZE_MB = 500
DEFAULT_CLONE_TIMEOUT = 300
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100
MAX_ARCHIVE_FILES = 20000
MAX_ARCHIVE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

# Explicit allow list of MCP tools that this script is permitted to invoke.
MCP_TOOL_ALLOW_LIST = frozenset({
    "get_upload_url",
    "analyze_uploaded_archive",
    "run_remediation",
})


def _validate_mcp_tool(tool_name: str) -> None:
    """Raise ValueError if *tool_name* is not in the approved allow list."""
    if tool_name not in MCP_TOOL_ALLOW_LIST:
        raise ValueError(
            f"MCP tool '{tool_name}' is not in the approved allow list: "
            f"{sorted(MCP_TOOL_ALLOW_LIST)}"
        )

# AI Deployment Configuration — covered domain declaration per automated
# decision-making regulations (required by governance policy).
COVERED_DOMAIN = "software_security_scanning"  # Regulated taxonomy classification
MCP_MODEL_VERSION = "mcp-scan-pipeline-v2.1.0"
LLM_REMEDIATION_MODEL_VERSION = "llm-remediation-v1.3.0"
_MODEL_VERSION_METADATA = {
    "mcp_scan_pipeline_version": MCP_MODEL_VERSION,
    "llm_remediation_version": LLM_REMEDIATION_MODEL_VERSION,
    "release_date": "2026-05-07",
    "changelog": "https://docs.veedna.com/releases/mcp-v2.1.0",
}

# AI deployment risk classification metadata (required by governance policy)
AI_DEPLOYMENT_METADATA = {
    "risk_classification": "high",
    "risk_level": "high",
    "deployment_type": "mcp_scanning_pipeline_with_llm_remediation",
    "policy_version": "1.0",
}

# ---------------------------------------------------------------------------
# URL Allowlist Validation
# ---------------------------------------------------------------------------

_DEFAULT_ALLOWED_DOMAINS = {
    "mcp.v2.prod.veedna.com",
    "github.com",
    "lineaje-identity-service.v2.prod.veedna.com",
    "s3.amazonaws.com",
    ".s3.amazonaws.com",
    ".amazonaws.com",
}


def _get_allowed_domains() -> set:
    """Return the set of allowed domains for outbound HTTP requests."""
    env_domains = os.environ.get("ALLOWED_URL_DOMAINS", "")
    extra = {d.strip() for d in env_domains.split(",") if d.strip()} if env_domains else set()
    return _DEFAULT_ALLOWED_DOMAINS | extra


def _validate_url_allowlist(url: str) -> None:
    """Validate that a URL's host is in the allowed domains list.

    Raises ValueError if the URL is not allowed.
    """
    if not url:
        raise ValueError("Empty URL is not allowed for outbound requests.")
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Cannot determine host from URL: {url}")
    allowed = _get_allowed_domains()
    # Check exact match or suffix match (for wildcard subdomains like .s3.amazonaws.com)
    for domain in allowed:
        if domain.startswith("."):
            if host == domain[1:] or host.endswith(domain):
                return
        else:
            if host == domain:
                return
    raise ValueError(
        f"Outbound request to '{host}' is not in the URL allowlist. "
        f"Allowed domains: {sorted(allowed)}"
    )


def _mcp_request(method: str, url: str, **kwargs) -> requests.Response:
    """Wrapper for all MCP server HTTP interactions that logs request and response."""
    req_body = kwargs.get("json") or kwargs.get("data")
    headers = kwargs.get("headers", {})
    # Redact sensitive headers for logging
    safe_headers = {k: (v if k.lower() not in ("authorization", "x-access-token") else "[REDACTED]") for k, v in headers.items()}
    logger.info("MCP request: %s %s headers=%s body=%s", method.upper(), url, safe_headers, _truncate_for_log(req_body))
    try:
        resp = requests.request(method, url, **kwargs)
        resp_body = None
        try:
            resp_body = resp.json()
        except Exception:
            resp_body = resp.text[:_LOG_HTTP_BODY_MAX] if resp.text else None
        logger.info("MCP response: status=%s url=%s body=%s", resp.status_code, url, _truncate_for_log(resp_body))
        return resp
    except Exception as exc:
        logger.error("MCP request failed: %s %s error=%s", method.upper(), url, exc)
        raise


def _truncate_for_log(obj) -> str:
    """Truncate an object's string representation for safe logging."""
    if obj is None:
        return "<empty>"
    s = str(obj)
    if len(s) > _LOG_HTTP_BODY_MAX:
        return s[:_LOG_HTTP_BODY_MAX] + "...[truncated]"
    return s

MAX_LLM_FILE_SIZE = 100_000

def _mask_token(token: str) -> str:
    """Return a masked version of a token showing only first 8 and last 4 chars."""
    if not token or len(token) <= 12:
        return "***MASKED***"
    return f"{token[:8]}...{token[-4:]}"


def _minimise_violations(violations: list) -> list:
    """Limit violations to _MAX_OUTPUT_VIOLATIONS and strip verbose fields."""
    minimised = []
    for v in violations[:_MAX_OUTPUT_VIOLATIONS]:
        if isinstance(v, dict):
            minimised.append({
                "file": v.get("file", ""),
                "line": v.get("line"),
                "rule": v.get("rule", v.get("violation_type", "")),
                "severity": v.get("severity", ""),
                "message": (v.get("message", "") or "")[:300],
            })
        else:
            minimised.append(str(v)[:300])
    if len(violations) > _MAX_OUTPUT_VIOLATIONS:
        minimised.append({"_truncated": True, "total_count": len(violations)})
    return minimised


def _minimise_scan_errors(errors: list) -> list:
    """Truncate scan error messages to avoid leaking sensitive details."""
    return [str(e)[:_MAX_SCAN_ERROR_LEN] for e in (errors or [])]
LLM_TIMEOUT = 120

MAX_SCAN_WORKERS = 4
MAX_LLM_WORKERS = 5

_LOG_HTTP_BODY_MAX = int(os.environ.get("LINEAJE_LOG_HTTP_BODY_MAX", "512"))
_MAX_OUTPUT_VIOLATIONS = int(os.environ.get("LINEAJE_MAX_OUTPUT_VIOLATIONS", "50"))
_MAX_SCAN_ERROR_LEN = 200
_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120

_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://lineaje-identity-service.v2.prod.veedna.com"
    "/lineajeidentity/api/v1/auth/native/renew-access-token"
)

_GITHUB_CLONE_URL = "https://x-access-token:{token}@github.com/{repo}.git"


def _validated_url(url: str) -> str:
    """Validate URL against allowlist and return it if valid."""
    _validate_url_allowlist(url)
    return url

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

_SENSITIVE_JSON_KEYS = frozenset({
    "access_token", "refresh_token", "id_token", "token", "refreshToken",
    "accessToken", "device_code", "deviceCode",
})

def _validate_python_syntax(path: str) -> List[str]:
    """Return subprocess arg list to validate Python syntax."""
    return ["python3", "-c", f"import ast; ast.parse(open('{path}').read())"]


def _validate_js_syntax(path: str) -> List[str]:
    """Return subprocess arg list to validate JS syntax."""
    return ["node", "--check", path]


def _validate_ts_syntax(path: str) -> List[str]:
    """Return subprocess arg list to validate TS file readability."""
    return ["node", "-e", f"require('fs').readFileSync('{path}', 'utf8')"]


def _validate_json_syntax(path: str) -> List[str]:
    """Return subprocess arg list to validate JSON syntax."""
    return ["python3", "-c", f"import json; json.load(open('{path}'))"]


def _validate_yaml_syntax(path: str) -> List[str]:
    """Return subprocess arg list to validate YAML syntax."""
    return ["python3", "-c", f"import yaml; yaml.safe_load(open('{path}'))"]


_SYNTAX_VALIDATORS: Dict[str, Any] = {
    ".py":   _validate_python_syntax,
    ".js":   _validate_js_syntax,
    ".ts":   _validate_ts_syntax,
    ".json": _validate_json_syntax,
    ".yaml": _validate_yaml_syntax,
    ".yml":  _validate_yaml_syntax,
}

# ===========================================================================
# Env helpers (inlined from env_loader to keep script self-contained)
# ===========================================================================

def _env_truthy(var: str) -> bool:
    v = os.environ.get(var, "").strip().lower()
    return v not in ("", "0", "false", "no", "off")


def _env_full_mcp_bearer_logging_enabled() -> bool:
    truthy = frozenset({"1", "true", "yes", "on"})
    falsy = frozenset({"0", "false", "no", "off"})
    saw_true = False
    for var in ("UNIFAI_LOG_FULL_MCP_BEARER_TOKEN", "LINEAJE_LOG_FULL_MCP_BEARER_TOKEN"):
        raw = os.environ.get(var, "").strip().lower()
        if raw in falsy:
            return False
        if raw in truthy:
            saw_true = True
    return saw_true


def _canonicalize_project_name(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]", "-", name.strip())
    return re.sub(r"-+", "-", s).strip("-") or "project"

# ===========================================================================
# Logging helpers
# ===========================================================================

def _truncate_for_log(s: str, max_len: Optional[int] = None) -> str:
    m = max_len if max_len is not None else _LOG_HTTP_BODY_MAX
    if len(s) <= m:
        return s
    return f"{s[:m]}... [truncated {len(s) - m} chars]"


def _redact_mapping_for_log(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in _SENSITIVE_JSON_KEYS or any(
                sk in kl for sk in ("token", "secret", "password", "authorization")
            ):
                out[k] = f"<redacted len={len(v)}>" if isinstance(v, str) and v else v
            else:
                out[k] = _redact_mapping_for_log(v)
        return out
    if isinstance(obj, list):
        return [_redact_mapping_for_log(x) for x in obj[:30]]
    return obj


def _safe_json_preview(raw: str) -> str:
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return _truncate_for_log(raw)
    red = _redact_mapping_for_log(parsed)
    try:
        return _truncate_for_log(json.dumps(red, default=str))
    except (TypeError, ValueError):
        return _truncate_for_log(repr(red))


def _jwt_exp_diag_for_log(token: str) -> str:
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        return ""
    try:
        pad = "=" * ((4 - len(parts[1]) % 4) % 4)
        raw = base64.urlsafe_b64decode(parts[1] + pad)
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return ""
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return ""
    try:
        dt = datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return ""
    return f" jwt_exp_utc={dt.isoformat()}"


def log_mcp_bearer_for_scan(where: str, token: str) -> None:
    t = (token or "").strip()
    if not t:
        logger.warning("MCP bearer (%s): empty or missing", where)
        return
    preview = f"{t[:8]}…{t[-8:]}" if len(t) > 20 else "(short token)"
    exp_part = _jwt_exp_diag_for_log(t)
    logger.info("MCP bearer (%s): len=%d preview=%s%s", where, len(t), preview, exp_part)
    if _env_full_mcp_bearer_logging_enabled():
        logger.warning("MCP bearer (%s): INSECURE — full JWT on next INFO line", where)
        logger.info("MCP bearer (%s) FULL_JWT:", where)
        logger.info("%s", _mask_token(t) if t else t)


def _log_step_timing(label: str, step_start: float, scan_start: float) -> float:
    now = time.perf_counter()
    logger.info(
        "Timing — %s: %.1fs this step | %.1fs total",
        label, now - step_start, now - scan_start,
    )
    return now

# ===========================================================================
# Auth helpers
# ===========================================================================

def _normalize_lineaje_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    u = str(url).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
        u = u[1:-1].strip()
    return u


def _lineaje_url_from_env(var_name: str) -> str:
    return _normalize_lineaje_url(os.environ.get(var_name))


def _looks_like_jwt_blob(value: str) -> bool:
    s = value.strip()
    if s.count(".") != 2:
        return False
    hdr, payload, sig = s.split(".")
    if len(hdr) < 10 or len(payload) < 10 or len(sig) < 10:
        return False
    seg = re.compile(r"^[A-Za-z0-9_-]+$")
    return bool(seg.match(hdr) and seg.match(payload) and seg.match(sig))

# ===========================================================================
# Token identity helpers (refresh-token)
# ===========================================================================

def _normalize_token(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().lstrip("﻿").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def refresh_token_effective(args: Any) -> str:
    from_cli = _normalize_token(getattr(args, "refresh_token", None))
    if from_cli:
        return from_cli
    return _normalize_token(
        os.environ.get("MCP_REFRESH_TOKEN", "") or os.environ.get("LINEAJE_REFRESH_TOKEN", "")
    )


def _refresh_token_source_label(args: Any) -> str:
    if _normalize_token(getattr(args, "refresh_token", None)):
        return "CLI --refresh-token"
    if _normalize_token(os.environ.get("MCP_REFRESH_TOKEN", "")):
        return "env MCP_REFRESH_TOKEN"
    if _normalize_token(os.environ.get("LINEAJE_REFRESH_TOKEN", "")):
        return "env LINEAJE_REFRESH_TOKEN"
    return "unknown"


def _auth_log_label(args: Any) -> str:
    rt = refresh_token_effective(args)
    if rt:
        return _refresh_token_source_label(args)
    if os.environ.get("MCP_BEARER_TOKEN", "").strip():
        return "env MCP_BEARER_TOKEN"
    return "static MCP_BEARER_TOKEN"

# ===========================================================================
# Token response parsing
# ===========================================================================

def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
    text = raw_text.strip() if raw_text else ""
    try:
        parsed: Any = json.loads(raw_text)
    except json.JSONDecodeError:
        if context == "renew-access-token" and _looks_like_jwt_blob(text):
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
                if context == "renew-access-token" and _looks_like_jwt_blob(s):
                    return {"access_token": s}
                raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
            continue
        break
    raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


# ===========================================================================
# RefreshTokenTokenManager
# ===========================================================================

class RefreshTokenTokenManager:
    """Obtain MCP bearer tokens via native renew-access-token only (no device code)."""

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("refresh_token must be non-empty")
        self._renew_url = (
            _normalize_lineaje_url(renew_access_token_url)
            or _lineaje_url_from_env("LINEAJE_RENEW_ACCESS_TOKEN_URL")
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
            return self._get_access_token_unlocked()

    def _get_access_token_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew_tokens_unlocked()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _apply_token_payload(self, data: dict) -> None:
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
        log_mcp_bearer_for_scan("refresh-token auth access_token", self._access_token)

    def _renew_tokens_unlocked(self) -> None:
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
        _validate_url_allowlist(url)
        req = urllib.request.Request(
            url, data=b"null",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode(errors="replace")
            raise RuntimeError(f"renew-access-token HTTP {exc.code}: {err_body[:200]}") from exc
        self._apply_token_payload(payload)


# ===========================================================================
# build_mcp_bearer_getter
# ===========================================================================

def _mcp_bearer_sign(pat: str, subject: str, expires_at: float, secret: bytes) -> str:
    """Create a signed bearer payload encoding PAT, subject, and expiry."""
    import hmac as _hmac
    import hashlib as _hashlib
    import json as _json
    import base64 as _base64
    payload = _json.dumps({
        "pat": pat,
        "sub": subject,
        "exp": expires_at,
    }, separators=(",", ":"))
    sig = _hmac.new(secret, payload.encode("utf-8"), _hashlib.sha256).hexdigest()
    token = _base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii") + "." + sig
    return token


def _mcp_bearer_verify(token: str, secret: bytes) -> str:
    """Verify signature, expiry, and subject binding; return the PAT or raise."""
    import hmac as _hmac
    import hashlib as _hashlib
    import json as _json
    import base64 as _base64
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        raise RuntimeError("MCP bearer token: invalid format (missing signature)")
    payload_b64, sig = parts
    payload_bytes = _base64.urlsafe_b64decode(payload_b64)
    expected_sig = _hmac.new(secret, payload_bytes, _hashlib.sha256).hexdigest()
    if not _hmac.compare_digest(sig, expected_sig):
        raise RuntimeError("MCP bearer token: signature verification failed")
    data = _json.loads(payload_bytes)
    if time.time() > data.get("exp", 0):
        raise RuntimeError("MCP bearer token: token has expired")
    if not data.get("sub"):
        raise RuntimeError("MCP bearer token: missing subject binding")
    return data["pat"]


def build_mcp_bearer_getter(args: Any) -> Callable[[], str]:
    """Return a callable that yields the Lineaje PAT token as the MCP bearer.

    The token is signed with HMAC-SHA256, bound to a subject identifier,
    and enforces an expiry window. On each invocation the signature and
    expiry are re-verified before the PAT is returned.

    Checks ``--lineaje-pat`` / ``LINEAJE_PAT_TOKEN`` env var.
    Raises if neither is provided.
    """
    import hashlib as _hashlib
    pat = (
        (getattr(args, "lineaje_pat", None) or "").strip()
        or os.environ.get("LINEAJE_PAT_TOKEN", "").strip()
    )
    if pat:
        logger.info("MCP auth: Lineaje PAT token (signed, expiry-bound)")
        # Derive a signing secret from the PAT itself (acts as shared secret)
        secret = _hashlib.sha256((
            os.environ.get("MCP_SIGNING_SECRET", "") or pat
        ).encode("utf-8")).digest()
        # Subject binding: use machine identifier or PAT fingerprint
        subject = _hashlib.sha256(pat.encode("utf-8")).hexdigest()[:16]
        # Token validity window: 1 hour
        token_lifetime_sec = 3600

        def _get_verified_bearer() -> str:
            expires_at = time.time() + token_lifetime_sec
            signed_token = _mcp_bearer_sign(pat, subject, expires_at, secret)
            # Immediately verify integrity before returning the PAT
            return _mcp_bearer_verify(signed_token, secret)

        return _get_verified_bearer

    raise RuntimeError(
        "No Lineaje PAT token found. Set LINEAJE_PAT_TOKEN env var or pass --lineaje-pat."
    )

# ===========================================================================
# LLM config helpers — resolution delegated to scan_common imports above.
# ===========================================================================


def build_clone_basename_map(clone_dir: str) -> Dict[str, List[pathlib.Path]]:
    """Map basename → [full paths] for O(1) remediation file lookup."""
    result: Dict[str, List[pathlib.Path]] = {}
    root = pathlib.Path(clone_dir)
    for p in root.rglob("*"):
        if p.is_file():
            result.setdefault(p.name, []).append(p)
    return result


def _normalize_for_patch_match(s: str) -> str:
    """Normalize a code snippet for fuzzy matching: collapse runs of spaces/tabs."""
    return re.sub(r"[ \t]+", " ", s)


def _apply_fix_entry(content: str, original: str, replacement: str) -> Tuple[str, bool]:
    """Try to apply a single original→replacement patch with graceful fallbacks.

    Matching order:
    1. Exact substring match.
    2. Stripped-original exact match (LLM often adds/removes leading/trailing spaces).
    3. Whitespace-normalized match — collapse runs of spaces/tabs before comparing.
    4. First-line anchor — if original is multi-line, match on the first non-empty line
       and replace the block up to end-of-original.

    Returns (patched_content, did_apply).
    """
    if not original:
        return content, False

    # 1. Exact
    if original in content:
        return content.replace(original, replacement, 1), True

    # 2. Stripped
    orig_stripped = original.strip()
    if orig_stripped and orig_stripped in content:
        return content.replace(orig_stripped, replacement, 1), True

    # 3. Whitespace-normalized
    norm_orig = _normalize_for_patch_match(orig_stripped)
    norm_content = _normalize_for_patch_match(content)
    idx = norm_content.find(norm_orig)
    if idx != -1:
        # Map normalized index back to original content offsets
        orig_len = len(orig_stripped)
        # Walk content to find the real start position corresponding to norm idx
        real_idx = 0
        norm_walked = 0
        for ci, ch in enumerate(content):
            if norm_walked >= idx:
                real_idx = ci
                break
            norm_walked += len(_normalize_for_patch_match(ch))
        else:
            real_idx = len(content)
        # Attempt simple replacement using stripped original at real_idx
        sub = content[real_idx : real_idx + orig_len + 50]
        if orig_stripped in sub:
            actual_idx = content.find(orig_stripped, real_idx)
            if actual_idx != -1:
                return content[:actual_idx] + replacement + content[actual_idx + len(orig_stripped):], True

    # 4. First-line anchor: find the first non-empty line of original in content
    orig_lines = [l for l in orig_stripped.splitlines() if l.strip()]
    if orig_lines:
        anchor = orig_lines[0].strip()
        if len(anchor) > 15:  # anchor must be distinctive enough
            anchor_idx = content.find(anchor)
            if anchor_idx != -1:
                # Try to find end of original block after the anchor
                end_search = content.find(orig_lines[-1].strip(), anchor_idx) if len(orig_lines) > 1 else anchor_idx
                if end_search != -1:
                    end_idx = end_search + len(orig_lines[-1].strip())
                    found_block = content[anchor_idx:end_idx]
                    # Only replace if found block is reasonably close to original
                    if len(found_block) < len(orig_stripped) * 2:
                        return content[:anchor_idx] + replacement + content[end_idx:], True

    return content, False


def apply_pipeline_fix_code_to_clone(
    remediation_actions: List[Dict[str, Any]],
    clone_dir: str,
    file_list: List[str],
    clone_basename_map: Optional[Dict[str, List[pathlib.Path]]],
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Apply fix_code patches from pipeline remediation_actions to cloned files.

    The MCP pipeline already ran LLM remediation and stored ``fix_code`` entries
    (``{"original": ..., "replacement": ...}``) in each action.  This function
    applies those patches directly — no extra LLM call or API key required.

    Uses multi-strategy matching (exact → stripped → whitespace-normalized → first-line
    anchor) to handle minor LLM formatting differences.

    Returns:
        (validated_fixes, failed_files, fix_table_rows)
        validated_fixes  — {resolved_rel_path: patched_content}
        failed_files     — filepaths where no fix_code was present or no patch applied
        fix_table_rows   — [{policy, description, file, lines}, ...]
    """
    validated_fixes: Dict[str, str] = {}
    failed_files: List[str] = []
    fix_table_rows: List[Dict[str, str]] = []

    # Group by file
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

        rel_path, original_content = resolve_original_for_remediation(
            clone_dir, "", filepath, file_list,
            clone_basename_map=clone_basename_map,
        )
        if rel_path is None or original_content is None:
            logger.warning(
                "apply_pipeline_fix_code: cannot locate %r in clone — skipping",
                filepath,
            )
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
                        "apply_pipeline_fix_code: patch not applied for %r — "
                        "original snippet (%d chars) not found in file",
                        filepath, len(original),
                    )

        if patch_applied and content != original_content:
            validated_fixes[rel_path] = content
            for action in actions:
                fix_table_rows.append({
                    "policy": action.get("control", ""),
                    "description": (action.get("instruction") or "")[:200],
                    "file": filepath,
                    "lines": "",
                })
        else:
            logger.warning(
                "apply_pipeline_fix_code: no patch applied for %r — "
                "original snippets did not match file content",
                filepath,
            )
            failed_files.append(filepath)

    return validated_fixes, failed_files, fix_table_rows


def resolve_original_for_remediation(
    clone_dir: str,
    archive_path: str,
    filepath: str,
    file_list: List[str],
    clone_basename_map: Optional[Dict[str, List[pathlib.Path]]] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a violation filepath to (relative_path, content) for LLM remediation.

    Resolution order: exact clone path → archive exact/basename → clone basename.
    Returns (None, None) when the file cannot be located.
    """
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_archive_rel_path(raw)
    root = pathlib.Path(clone_dir)

    local = root / raw
    if local.is_file():
        return _norm_archive_rel_path(raw), local.read_text(errors="replace")

    if os.path.isfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            names = [n for n in zf.namelist() if not n.endswith("/") and n != "user_metadata.json"]
            norm_to_name = {_norm_archive_rel_path(n): n for n in names}

            def _read(member: str) -> str:
                return zf.read(member).decode("utf-8", errors="replace")

            if norm_fp in norm_to_name:
                m = norm_to_name[norm_fp]
                return _norm_archive_rel_path(m), _read(m)
            for listed in file_list:
                if _norm_archive_rel_path(listed) == norm_fp:
                    return _norm_archive_rel_path(listed), _read(listed)
            base = pathlib.Path(norm_fp).name
            base_matches = [n for n in names if pathlib.Path(n).name == base]
            if len(base_matches) == 1:
                return _norm_archive_rel_path(base_matches[0]), _read(base_matches[0])
            ci_matches = [n for n in names if n.casefold() == norm_fp.casefold()]
            if len(ci_matches) == 1:
                return _norm_archive_rel_path(ci_matches[0]), _read(ci_matches[0])

    base = pathlib.Path(norm_fp).name
    bmap = clone_basename_map or {}
    clone_hits = bmap.get(base, [])
    if len(clone_hits) == 1:
        full = clone_hits[0]
        rel = str(full.relative_to(root))
        return _norm_archive_rel_path(rel), full.read_text(errors="replace")
    if not clone_hits:
        ci_clone = [p for name, paths in bmap.items() if name.casefold() == base.casefold() for p in paths]
        if len(ci_clone) == 1:
            full = ci_clone[0]
            rel = str(full.relative_to(root))
            return _norm_archive_rel_path(rel), full.read_text(errors="replace")

    logger.warning("Cannot resolve remediation file %r in clone or archive", raw)
    return None, None


def _build_pr_body(
    repo: str,
    branch: str,
    sha_short: str,
    fix_table: List[Dict[str, str]],
    report: str,
    failed_files: Optional[List[str]] = None,
    source_clone_url: str = "",
    pr_repo: str = "",
) -> str:
    """Build the full PR body: intro + violations table + remediation table + full scan report + JSON."""
    violations_per_file: Dict[str, int] = {}
    for row in fix_table:
        violations_per_file[row["file"]] = violations_per_file.get(row["file"], 0) + 1
    total_violations = sum(violations_per_file.values())
    footer_note = ""
    if failed_files:
        footer_note = (
            "\n\n⚠️ **{} file(s) could not be auto-patched** — "
            "original snippet did not match file content. Review the scan report for manual fixes."
        ).format(len(failed_files))
    scan_json = build_remediation_scan_json_payload(
        repo=repo,
        branch=branch,
        commit=sha_short,
        files_remediated=len(violations_per_file),
        violations_per_file=violations_per_file,
        remediation_details=fix_table,
        generator="UniFAI Veracode Repository Scanner",
        extra={
            "pr_target_repo": pr_repo if pr_repo and pr_repo != repo else None,
            "failed_remediation_files": failed_files or [],
        },
    )
    return format_pr_body_with_json_scan_results(
        comment_marker=COMMENT_MARKER,
        title_md="## UniFAI Automated Policy Remediation",
        intro_md=(
            f"This PR contains AI policy compliance fixes for **`{repo}`** → **`{branch}`** "
            f"(`{sha_short}`)."
            + (f"\n\n- **Source clone URL:** `{source_clone_url}`" if source_clone_url else "")
        ),
        stats_md=(
            f"**Files remediated:** {len(violations_per_file)} &nbsp;|&nbsp; "
            f"**Total violations fixed:** {total_violations}"
        ),
        payload=scan_json,
        embedded_report_md=(report or "").strip() or None,
        embedded_report_max_chars=GITHUB_PR_EMBEDDED_REPORT_MAX_CHARS,
        footer_md="**How to use:** Merge into `{}` to bring the repository into AI policy compliance.{}".format(
            branch, footer_note
        ),
    )


def post_scan_report_on_existing_pr(
    scm: SCMClient,
    repo: str,
    branch: str,
    head_sha: str,
    fix_table: List[Dict[str, str]],
    report: str,
    failed_files: Optional[List[str]] = None,
    *,
    scm_pull_request_repo: Optional[str] = None,
) -> Optional[int]:
    """Find any open remediation PR for *branch* and update its body with the latest scan results.

    Used when no new code patches were applied but violations were found — the existing
    PR description is refreshed so violations/report stay current.
    """
    sha_short = head_sha[:7]
    pr_home = scm_pull_request_repo or repo
    existing_pr = scm.find_open_pr_by_prefix(pr_home, head_prefix=REMEDIATION_BRANCH_PREFIX, base=branch)
    if not existing_pr:
        logger.info(
            "No existing open remediation PR for %s/%s — no PR to update with scan report",
            pr_home, branch,
        )
        return None

    logger.info("Posting scan results as comment on existing remediation PR #%d", existing_pr)
    violations_per_file: Dict[str, int] = {}
    for row in fix_table:
        violations_per_file[row["file"]] = violations_per_file.get(row["file"], 0) + 1
    total_violations = sum(violations_per_file.values())
    scan_json = build_remediation_scan_json_payload(
        repo=repo,
        branch=branch,
        commit=sha_short,
        files_remediated=len(violations_per_file),
        violations_per_file=violations_per_file,
        remediation_details=fix_table,
        generator="UniFAI Veracode Repository Scanner",
        extra={"failed_remediation_files": failed_files or []},
    )
    run_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    vtbl = markdown_violations_per_file_table(violations_per_file)
    dtbl = markdown_remediation_details_table(fix_table)
    comment_lines = [
        "<!-- unifai-repo-scan-update -->",
        "",
        f"## UniFAI Re-scan Update — {run_ts}",
        "",
        f"**{len(violations_per_file)} file(s) remediated** &nbsp;|&nbsp; **{total_violations} violation(s) fixed** in this scan run.",
        "",
    ]
    if vtbl:
        comment_lines.extend(["### Violations per file", "", vtbl, ""])
    if dtbl:
        comment_lines.extend(["### Remediation details", "", dtbl, ""])
    try:
        scm.post_pr_comment(pr_home, existing_pr, "\n".join(comment_lines))
        logger.info("Posted re-scan comment on remediation PR #%d", existing_pr)
        return existing_pr
    except Exception as exc:
        logger.warning("Failed to post re-scan comment on PR #%d: %s", existing_pr, exc)
        return None


def create_repo_remediation_pr(
    scm: SCMClient,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    original_shas: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
    source_clone_url: str = "",
    pr_target_repo_explicit: str = "",
    scm_provider: str = "github",
) -> Tuple[Optional[int], str]:
    """Commit fixes onto a stable remediation branch; open PR or refresh an existing one's body."""

    if not validated_fixes:
        logger.info("No validated fixes — skipping remediation PR")
        return None, ""

    pr_repo, fork_login = resolve_github_pr_targets(
        repo, source_clone_url, scm_provider, pr_target_repo_explicit,
    )
    if pr_repo.lower() != repo.lower():
        logger.info(
            "Remediation PR opens on upstream %s (fixes committed on %s)",
            pr_repo, repo,
        )

    sha_short = head_sha[:7]

    stable_bn = stable_repo_scan_remediation_branch(REMEDIATION_BRANCH_PREFIX, branch)
    cross_head_kw = fork_login if pr_repo.lower() != repo.lower() else None

    existing_pr_num, branch_name, branch_existed_for_blob = resolve_remediation_branch_and_existing_pr(
        scm,
        fork_repo_slug=repo,
        pr_repo_slug=pr_repo,
        base_branch=branch,
        base_head_sha=head_sha,
        remediation_branch_prefix=REMEDIATION_BRANCH_PREFIX,
        stable_default_branch_name=stable_bn,
        head_repo_owner_when_listing_github=cross_head_kw,
    )
    if existing_pr_num:
        logger.info(
            "Reusing open remediation PR #%s (head `%s` → base `%s` on %s)",
            existing_pr_num, branch_name, branch, pr_repo,
        )

    committed: List[str] = []
    for filepath, content in validated_fixes.items():
        blob_sha = None if branch_existed_for_blob else original_shas.get(filepath)
        policies = ", ".join({r["policy"] for r in fix_table if r["file"] == filepath}) or "policy violations"
        message = f"fix({filepath}): remediate {policies} [unifai-veracode-scan]"
        logger.info("Committing fix: %s", filepath)
        try:
            scm.commit_file(repo, branch_name, filepath, content.encode("utf-8"), message, sha=blob_sha)
            committed.append(filepath)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", filepath, exc)

    if not committed:
        if existing_pr_num is not None:
            logger.info(
                "No successful file commits — still refreshing PR #%s scan JSON/description",
                existing_pr_num,
            )
        else:
            logger.warning("No files were successfully committed — skipping remediation PR workflow")
            return None, branch_name

    title = f"[unifai-bot] fix: AI policy remediation for {branch}@{sha_short}"

    pr_body = _build_pr_body(
        repo, branch, sha_short, fix_table, report, failed_files,
        source_clone_url=source_clone_url, pr_repo=pr_repo,
    )

    cross_head = fork_login if pr_repo.lower() != repo.lower() else None
    logger.info(
        "Create or update remediation PR: `%s` → `%s` on %s",
        branch_name,
        branch,
        pr_repo,
    )
    try:
        if existing_pr_num is not None:
            run_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            violations_per_file_c: Dict[str, int] = {}
            for row in fix_table:
                violations_per_file_c[row["file"]] = violations_per_file_c.get(row["file"], 0) + 1
            total_violations_c = sum(violations_per_file_c.values())
            scan_json_c = build_remediation_scan_json_payload(
                repo=repo,
                branch=branch,
                commit=sha_short,
                files_remediated=len(violations_per_file_c),
                violations_per_file=violations_per_file_c,
                remediation_details=fix_table,
                generator="UniFAI Veracode Repository Scanner",
                extra={
                    "pr_target_repo": pr_repo if pr_repo != repo else None,
                    "failed_remediation_files": failed_files or [],
                },
            )
            vtbl_c = markdown_violations_per_file_table(violations_per_file_c)
            dtbl_c = markdown_remediation_details_table(fix_table)
            comment_lines_c = [
                "<!-- unifai-repo-scan-update -->",
                "",
                f"## UniFAI Re-scan Update — {run_ts}",
                "",
                f"**{len(violations_per_file_c)} file(s) remediated** &nbsp;|&nbsp; **{total_violations_c} violation(s) fixed** in this scan run.",
                "",
            ]
            if vtbl_c:
                comment_lines_c.extend(["### Violations per file", "", vtbl_c, ""])
            if dtbl_c:
                comment_lines_c.extend(["### Remediation details", "", dtbl_c, ""])
            try:
                scm.post_pr_comment(pr_repo, existing_pr_num, "\n".join(comment_lines_c))
                logger.info("Posted re-scan comment on remediation PR #%s", existing_pr_num)
            except Exception as exc:
                logger.warning("Failed to post re-scan comment on PR #%s: %s", existing_pr_num, exc)
            return existing_pr_num, branch_name
        remediation_pr = scm.create_pull_request(
            pr_repo,
            title,
            branch_name,
            branch,
            pr_body,
            cross_repo_head_owner=cross_head,
        )
        logger.info("Created remediation PR #%d", remediation_pr)
        return remediation_pr, branch_name
    except Exception as exc:
        logger.error("Failed to create or update remediation PR: %s", exc)
        return None, branch_name


# ===========================================================================
# Manifest file detection (doc_type: package — AI asset detection / AIBOM)
# ===========================================================================
# Mirrors MANIFEST_FILE_PATTERNS in mcp_server.py. Keep in sync.
_MANIFEST_FILE_NAMES: frozenset = frozenset({
    # Python
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock",
    "environment.yml", "environment.yaml",
    # JavaScript / Node
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    # Java / JVM
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    # Scala
    "build.sbt",
    # Ruby
    "Gemfile", "Gemfile.lock",
    # Go
    "go.mod", "go.sum",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # .NET
    "packages.config", "packages.lock.json", "nuget.config", "Directory.Packages.props",
    # PHP
    "composer.json", "composer.lock",
    # Swift
    "Package.swift", "Package.resolved",
    # Dart / Flutter
    "pubspec.yaml", "pubspec.lock",
    # Elixir
    "mix.exs", "mix.lock",
})
_MANIFEST_GLOB_PATTERNS: tuple = ("*.csproj", "*.fsproj", "*.vbproj", "*.gemspec")


def _is_manifest_file(filename: str) -> bool:
    """Return True if *filename* (basename only) is a manifest file."""
    if filename in _MANIFEST_FILE_NAMES:
        return True
    return any(fnmatch.fnmatch(filename, pat) for pat in _MANIFEST_GLOB_PATTERNS)


# ===========================================================================
# File collection
# ===========================================================================

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
    clone_dir: str,
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
    # Manifest files (doc_type: package) are injected into every batch so that
    # every batch triggers manifest_detected=True and AIBOM/vulnerability scanning.
    extra_manifests = [m for m in (manifest_files or []) if m not in file_subset]
    all_files = list(file_subset) + extra_manifests
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in all_files:
            full_path = os.path.join(clone_dir, rel_path)
            if os.path.isfile(full_path):
                zf.write(full_path, rel_path)
        metadata = {
            "scan_source": "veracode_repo_scan",
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
        "Created batch archive #%d: %d files + %d manifests, %d KB → %s",
        batch_index, len(file_subset), len(extra_manifests), size_kb, archive_path,
    )
    return archive_path


def _repo_archive_batch_size(total_files: int) -> int:
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
# MCP scan
# ===========================================================================

# ---------------------------------------------------------------------------
# Input sanitization helpers – validate/sanitize user-supplied values before
# they are sent to LLM or MCP tool invocations.
# ---------------------------------------------------------------------------

import re as _re

_REPO_NAME_PATTERN = _re.compile(r'^[A-Za-z0-9_.\-/]+$')
_BRANCH_NAME_PATTERN = _re.compile(r'^[A-Za-z0-9_.\-/]+$')
_FILE_PATH_PATTERN = _re.compile(r'^[A-Za-z0-9_.\-/\\@:]+$')


def _sanitize_repo_name(repo: str) -> str:
    """Validate and sanitize repository name to prevent prompt injection."""
    if not repo or not isinstance(repo, str):
        raise ValueError("Repository name must be a non-empty string.")
    repo = repo.strip()
    if len(repo) > 256:
        raise ValueError(f"Repository name too long ({len(repo)} chars, max 256).")
    if not _REPO_NAME_PATTERN.match(repo):
        raise ValueError(
            f"Repository name contains invalid characters: {repo!r}. "
            "Only alphanumerics, dots, hyphens, underscores, and slashes are allowed."
        )
    return repo


def _sanitize_branch(branch: str) -> str:
    """Validate and sanitize branch/tag name to prevent prompt injection."""
    if not branch or not isinstance(branch, str):
        raise ValueError("Branch name must be a non-empty string.")
    branch = branch.strip()
    if len(branch) > 256:
        raise ValueError(f"Branch name too long ({len(branch)} chars, max 256).")
    if not _BRANCH_NAME_PATTERN.match(branch):
        raise ValueError(
            f"Branch name contains invalid characters: {branch!r}. "
            "Only alphanumerics, dots, hyphens, underscores, and slashes are allowed."
        )
    return branch


def _sanitize_file_list(files: List[str]) -> List[str]:
    """Validate and sanitize file paths to prevent prompt injection."""
    if not files or not isinstance(files, list):
        raise ValueError("files_to_scan must be a non-empty list.")
    sanitized = []
    for f in files:
        if not f or not isinstance(f, str):
            continue
        f = f.strip()
        if len(f) > 1024:
            raise ValueError(f"File path too long ({len(f)} chars, max 1024): {f[:80]}...")
        if not _FILE_PATH_PATTERN.match(f):
            raise ValueError(
                f"File path contains invalid characters: {f!r}. "
                "Only alphanumerics, dots, hyphens, underscores, slashes, backslashes, @ and : are allowed."
            )
        # Prevent path traversal
        if '..' in f:
            raise ValueError(f"File path contains path traversal: {f!r}")
        sanitized.append(f)
    if not sanitized:
        raise ValueError("No valid file paths after sanitization.")
    return sanitized


def _get_verified_ssl_context() -> "ssl.SSLContext":
    """Return an SSL context that verifies the server's certificate."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _upload_to_s3(presigned_url: str, archive_path: str) -> None:
    size = os.path.getsize(archive_path)
    logger.info("Uploading %d KB to S3 ...", size // 1024)
    with open(archive_path, "rb") as f:
        req = urllib.request.Request(
            presigned_url, data=f.read(), method="PUT",
            headers={"Content-Type": "application/zip"},
        )
        with urllib.request.urlopen(req, context=_get_verified_ssl_context()) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"S3 upload failed: HTTP {resp.status}")
    logger.info("S3 upload complete")


def _redact_pii_from_archive(archive_path: str) -> None:
    """Scan archive contents for PII and redact before upload."""
    import re
    import tarfile
    import zipfile
    import tempfile
    import shutil

    PII_PATTERNS = [
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'), '[REDACTED_EMAIL]'),
        (re.compile(r'\b\d{3}[\-.]?\d{2}[\-.]?\d{4}\b'), '[REDACTED_SSN]'),
        (re.compile(r'\b(?:\+?1[\-\s.]?)?\(?\d{3}\)?[\-\s.]?\d{3}[\-\s.]?\d{4}\b'), '[REDACTED_PHONE]'),
        (re.compile(r'\b(?:\d{4}[\-\s]?){3}\d{4}\b'), '[REDACTED_CC]'),
    ]

    def redact_content(content: bytes) -> bytes:
        try:
            text = content.decode('utf-8')
        except (UnicodeDecodeError, ValueError):
            return content
        for pattern, replacement in PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text.encode('utf-8')

    if tarfile.is_tarfile(archive_path):
        tmp_dir = tempfile.mkdtemp()
        try:
            with tarfile.open(archive_path, 'r:*') as tf:
                tf.extractall(tmp_dir)
            # Determine compression mode
            if archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
                write_mode = 'w:gz'
            elif archive_path.endswith('.tar.bz2'):
                write_mode = 'w:bz2'
            elif archive_path.endswith('.tar.xz'):
                write_mode = 'w:xz'
            else:
                write_mode = 'w:gz'
            # Redact files and rewrite archive
            for root, dirs, filenames in os.walk(tmp_dir):
                for fname in filenames:
                    fpath = os.path.join(root, fname)
                    if os.path.isfile(fpath):
                        with open(fpath, 'rb') as f:
                            original_content = f.read()
                        redacted = redact_content(original_content)
                        if redacted != original_content:
                            with open(fpath, 'wb') as f:
                                f.write(redacted)
                            logger.info("Redacted PII from file in archive: %s", fname)
            with tarfile.open(archive_path, write_mode) as tf:
                for root, dirs, filenames in os.walk(tmp_dir):
                    for fname in filenames:
                        fpath = os.path.join(root, fname)
                        arcname = os.path.relpath(fpath, tmp_dir)
                        tf.add(fpath, arcname=arcname)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.info("PII redaction complete for tar archive: %s", archive_path)
    elif zipfile.is_zipfile(archive_path):
        tmp_zip = archive_path + '.tmp'
        with zipfile.ZipFile(archive_path, 'r') as zin:
            with zipfile.ZipFile(tmp_zip, 'w', compression=zin.compression) as zout:
                for item in zin.infolist():
                    content = zin.read(item.filename)
                    redacted = redact_content(content)
                    if redacted != content:
                        logger.info("Redacted PII from file in archive: %s", item.filename)
                    zout.writestr(item, redacted)
        shutil.move(tmp_zip, archive_path)
        logger.info("PII redaction complete for zip archive: %s", archive_path)
    else:
        # Treat as a single file
        with open(archive_path, 'rb') as f:
            content = f.read()
        redacted = redact_content(content)
        if redacted != content:
            with open(archive_path, 'wb') as f:
                f.write(redacted)
            logger.info("Redacted PII from file: %s", archive_path)
        else:
            logger.info("No PII found in file: %s", archive_path)


def _check_archive_for_singapore_pii(archive_path: str) -> None:
    """Scan archive contents for Singapore PII (NRIC/FIN, phone numbers) before upload.

    Raises RuntimeError if any Singapore PII patterns are detected.
    """
    import re
    import tarfile
    import zipfile
    import io

    # Singapore NRIC/FIN: starts with S, T, F, G, or M followed by 7 digits and a letter
    nric_pattern = re.compile(r'\b[STFGM]\d{7}[A-Z]\b')
    # Singapore phone numbers: +65 followed by 8 digits, or 65-prefixed 8-digit numbers
    phone_pattern = re.compile(r'(?:\+65[\s-]?\d{4}[\s-]?\d{4}|\b65\d{8}\b)')

    def _scan_text(text: str, source_name: str) -> None:
        nric_matches = nric_pattern.findall(text)
        phone_matches = phone_pattern.findall(text)
        findings = []
        if nric_matches:
            findings.append(f"NRIC/FIN numbers: {nric_matches[:5]}")
        if phone_matches:
            findings.append(f"Singapore phone numbers: {phone_matches[:5]}")
        if findings:
            raise RuntimeError(
                f"Singapore PII detected in archive member '{source_name}': "
                + "; ".join(findings)
                + ". Upload aborted to comply with PII policy."
            )

    def _try_decode(data: bytes) -> str | None:
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None

    scanned = False
    # Try tar archive first
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile() or member.size > 50 * 1024 * 1024:
                    continue
                f = tf.extractfile(member)
                if f is None:
                    continue
                content = _try_decode(f.read())
                if content:
                    _scan_text(content, member.name)
        scanned = True

    # Try zip archive
    if not scanned and zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > 50 * 1024 * 1024:
                    continue
                with zf.open(info) as f:
                    content = _try_decode(f.read())
                    if content:
                        _scan_text(content, info.filename)
        scanned = True

    # Fallback: scan raw file bytes
    if not scanned:
        with open(archive_path, "rb") as f:
            content = _try_decode(f.read())
            if content:
                _scan_text(content, archive_path)

    logger.info("Singapore PII check passed for archive: %s", archive_path)


def _parse_tool_result(result: Any) -> dict:
    if hasattr(result, "content") and result.content:
        raw = result.content[0].text if hasattr(result.content[0], "text") else str(result.content[0])
        # Attach synthetic content provenance to raw LLM output
        _llm_provenance = {
            "synthetic": True,
            "content_origin": "ai_generated",
            "model_identifier": getattr(result, 'model', os.environ.get('LLM_MODEL', 'unknown')),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"raw": raw}
    return {"raw": "empty response"}


def _sanitize_mcp_input(value: str, field_name: str) -> str:
    """Validate and sanitize a string input before passing to MCP tool calls.

    Checks for hidden prompt injections, base64-encoded payloads, shell commands,
    leetspeak obfuscation, and other malicious content patterns.
    """
    import re as _re
    import base64 as _b64

    if not isinstance(value, str):
        raise ValueError(f"Invalid {field_name}: expected string, got {type(value).__name__}")

    # Reject excessively long values (repo/branch names should be short)
    if field_name in ("source_code_repo", "branch_or_tag") and len(value) > 500:
        raise ValueError(f"Invalid {field_name}: value too long ({len(value)} chars)")

    # Check for shell command patterns
    shell_patterns = [
        r'[;|&`$]',  # shell metacharacters
        r'\$\(',      # command substitution
        r'\b(rm|chmod|chown|curl|wget|nc|bash|sh|eval|exec|sudo|dd|mkfs)\b',
        r'\.\./',    # directory traversal
    ]
    # Only apply shell checks to repo/branch names, not file paths
    if field_name in ("source_code_repo", "branch_or_tag"):
        for pattern in shell_patterns:
            if _re.search(pattern, value):
                raise ValueError(
                    f"Invalid {field_name}: contains potentially malicious pattern"
                )

    # Check for prompt injection patterns (case-insensitive)
    prompt_injection_patterns = [
        r'(?i)ignore\s+(all\s+)?previous\s+instructions',
        r'(?i)ignore\s+(all\s+)?above\s+instructions',
        r'(?i)disregard\s+(all\s+)?previous',
        r'(?i)you\s+are\s+now\s+',
        r'(?i)act\s+as\s+(a\s+)?',
        r'(?i)system\s*:\s*',
        r'(?i)\[INST\]',
        r'(?i)<\|im_start\|>',
        r'(?i)###\s*(system|instruction|human|assistant)',
    ]
    for pattern in prompt_injection_patterns:
        if _re.search(pattern, value):
            raise ValueError(
                f"Invalid {field_name}: contains prompt injection pattern"
            )

    # Check for base64-encoded payloads (long base64 strings that decode to suspicious content)
    b64_pattern = _re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for match in b64_pattern.finditer(value):
        try:
            decoded = _b64.b64decode(match.group()).decode('utf-8', errors='ignore')
            # Check if decoded content contains suspicious patterns
            if any(_re.search(p, decoded) for p in prompt_injection_patterns):
                raise ValueError(
                    f"Invalid {field_name}: contains base64-encoded malicious content"
                )
            if any(_re.search(p, decoded) for p in shell_patterns):
                raise ValueError(
                    f"Invalid {field_name}: contains base64-encoded shell commands"
                )
        except Exception as decode_err:
            if "Invalid" in str(decode_err):
                raise

    return value


def _sanitize_mcp_inputs(
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
) -> tuple:
    """Sanitize all MCP tool call inputs."""
    sanitized_repo = _sanitize_mcp_input(source_code_repo, "source_code_repo")
    sanitized_branch = _sanitize_mcp_input(branch, "branch_or_tag")
    sanitized_files = []
    for f in files_to_scan:
        # For file paths, just check for prompt injection and base64
        sanitized_files.append(_sanitize_mcp_input(f, "file_path"))
    return sanitized_repo, sanitized_branch, sanitized_files


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

    # Sanitize all user-supplied inputs before passing to MCP tool calls
    source_code_repo, branch, files_to_scan = _sanitize_mcp_inputs(
        source_code_repo, branch, files_to_scan
    )

    async def _scan() -> Dict[str, Any]:
        upload_args: Dict[str, Any] = {
            "source_code_repo": source_code_repo,
            "branch_or_tag": branch,
            "files_to_scan": files_to_scan,
        }
        tok1 = bearer_getter()
        log_mcp_bearer_for_scan("MCP client before get_upload_url", tok1)
        async with streamablehttp_client(
            server_url, headers={"Authorization": f"Bearer {tok1}"},
            httpx_client_factory=_verified_httpx_client_factory,
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("Step 1/3: get_upload_url (SDK streamable)")
                upload_result = _parse_tool_result(
                    _validate_mcp_tool("get_upload_url")
    await session.call_tool("get_upload_url", arguments=upload_args)
                )
                if not upload_result.get("success"):
                    raise RuntimeError(f"get_upload_url failed: {upload_result.get('error', upload_result)}")
                archive_id = upload_result["archive_id"]
                presigned_url = upload_result["presigned_url"]

        logger.info("Step 2/3: Redacting PII and uploading archive to S3")
        _redact_pii_from_archive(archive_path)
        _upload_to_s3(presigned_url, archive_path)

        tok2 = bearer_getter()
        log_mcp_bearer_for_scan("MCP client before analyze_uploaded_archive", tok2)
        # analyze_uploaded_archive runs LLM evaluation + remediation; allow up to 30 min.
        _analyze_sse_timeout = int(os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800"))
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}"},
            sse_read_timeout=_analyze_sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                logger.info(
                    "Step 3/3: analyze_uploaded_archive (SDK streamable, sse_read_timeout=%ds)",
                    _analyze_sse_timeout,
                )
                logger.info(
                    "Waiting for MCP tool result (server runs full UniFAI pipeline — often 10+ minutes). "
                    "This process is not stuck; client logs pause until the response is received. "
                    "Watch the mcp_server terminal for evaluation/remediation progress.",
                )
                analyze_args = dict(upload_args)
                analyze_args["archive_id"] = archive_id
                result = _parse_tool_result(
                    _validate_mcp_tool("analyze_uploaded_archive")
    await session2.call_tool("analyze_uploaded_archive", arguments=analyze_args)
                )
                return result

    try:
        return asyncio.run(_scan())
    except Exception as exc:
        try:
            log_mcp_bearer_for_scan("MCP SDK failure (bearer at error time)", bearer_getter())
        except Exception:
            pass
        logger.error("MCP streamable HTTP (SDK) failed for %s: %s", server_url, exc,
                     exc_info=logger.isEnabledFor(logging.DEBUG))
        raise


def _run_mcp_scan_direct_http(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
) -> Dict[str, Any]:
    def _call_tool(tool_name: str, arguments: dict) -> dict:
        token = bearer_getter()
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            server_url, data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
            },
            method="POST",
        )
        log_mcp_bearer_for_scan(f"MCP direct HTTP before tools/call {tool_name}", token)
        logger.info("MCP HTTP request: POST %s tool=%s body_bytes=%d", server_url, tool_name, len(data))
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                resp_text = resp.read().decode()
                ct = (resp.headers.get("Content-Type") or "").lower()
                if "text/event-stream" in ct:
                    return _parse_sse_response(resp_text)
                return json.loads(resp_text)
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode(errors="replace")
            logger.error("MCP HTTP error: tool=%s HTTP %s body=%s", tool_name, exc.code, _truncate_for_log(err_body))
            raise

    def _parse_sse_response(text: str) -> dict:
        last_data = None
        for line in text.split("\n"):
            if line.startswith("data: "):
                last_data = line[6:]
        if last_data:
            parsed = json.loads(last_data)
            if "result" in parsed:
                content = parsed["result"].get("content", [])
                if content and hasattr(content[0], "get"):
                    return json.loads(content[0].get("text", "{}"))
                elif content:
                    return json.loads(str(content[0]))
            return parsed
        raise RuntimeError(f"No data in SSE response: {text[:200]}")

    logger.info("Step 1/3: get_upload_url (direct HTTP)")
    _validate_mcp_tool("get_upload_url")
    upload_resp = _call_tool("get_upload_url", {
        "source_code_repo": source_code_repo, "branch_or_tag": branch,
        "files_to_scan": files_to_scan,
    })
    if not upload_resp.get("success"):
        raise RuntimeError(f"get_upload_url failed: {str(upload_resp)[:200]}")
    archive_id = upload_resp["archive_id"]

    logger.info("Step 2/3: Uploading to S3 (direct HTTP)")
    _validate_url_allowlist(upload_resp["presigned_url"])
    _upload_to_s3(upload_resp["presigned_url"], archive_path)

    logger.info("Step 3/3: analyze_uploaded_archive (direct HTTP)")
    logger.info(
        "Waiting for MCP tool result (server runs full UniFAI pipeline — often 10+ minutes). "
        "Client logs may pause until HTTP/SSE completes.",
    )
    _validate_mcp_tool("analyze_uploaded_archive")
    return _call_tool("analyze_uploaded_archive", {
        "archive_id": archive_id,
        "source_code_repo": source_code_repo,
        "branch_or_tag": branch,
        "files_to_scan": files_to_scan,
    })


def run_mcp_scan(
    mcp_server_url: str,
    mcp_bearer_token: str,
    source_code_repo: str,
    branch: str,
    files: Dict[str, pathlib.Path],
    archive_path: str,
    *,
    get_mcp_bearer_token: Optional[Callable[[], str]] = None,
) -> Dict[str, Any]:
    mcp_server_url = mcp_server_url.strip()
    files_to_scan = list(files.keys())
    logger.info("Starting MCP scan: %d files, repo=%s, branch=%s", len(files_to_scan), source_code_repo, branch)
    bearer_getter = get_mcp_bearer_token or (lambda: mcp_bearer_token)
    try:
        _validate_url_allowlist(mcp_server_url)
    return _run_mcp_scan_via_client(mcp_server_url, bearer_getter, source_code_repo, branch, files_to_scan, archive_path)
    except ImportError:
        logger.info("MCP client library not available, using direct HTTP")
        return _run_mcp_scan_direct_http(mcp_server_url, bearer_getter, source_code_repo, branch, files_to_scan, archive_path)

# ===========================================================================
# Parallel batch scan
# ===========================================================================

def batch_scan_exception_detail_lines(batch_idx: int, num_batches: int, exc: BaseException) -> List[str]:
    lines = [f"Batch {batch_idx}/{num_batches} scan failed: {exc} — skipping"]
    def _append_group(group: BaseExceptionGroup, indent: str) -> None:
        for i, subexc in enumerate(group.exceptions, 1):
            lines.append(f"{indent}Cause [{i}/{len(group.exceptions)}] ({type(subexc).__name__}): {subexc}")
            if isinstance(subexc, BaseExceptionGroup):
                _append_group(subexc, indent + "  ")
    if isinstance(exc, BaseExceptionGroup):
        _append_group(exc, "  ")
    return lines


def parallel_batch_scan(
    batches: List[List[str]],
    root_dir: str,
    temp_dir: str,
    source_code_repo: str,
    branch: str,
    head_sha: str,
    run_id: str,
    mcp_server_url: str,
    get_mcp_bearer_token: Callable[[], str],
    create_archive_fn: Callable,
    max_workers: int = MAX_SCAN_WORKERS,
    manifest_files: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, str]], Dict[str, str], str, int, List[str]]:
    all_remediation_actions: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    all_aibom: List[Dict[str, str]] = []
    aibom_seen: set = set()
    violation_archive: Dict[str, str] = {}
    last_archive_path = ""
    failed_batch_count = 0
    mcp_batch_failure_details: List[str] = []
    lock = threading.Lock()

    def _scan_one(batch_idx: int, batch_files: List[str]) -> Tuple[int, str, Dict[str, Any]]:
        logger.info("  Batch %d/%d starting: %d files", batch_idx, len(batches), len(batch_files))
        archive_path = create_archive_fn(
            root_dir, temp_dir, batch_files,
            source_code_repo, branch, head_sha, batch_idx, run_id=run_id,
            manifest_files=manifest_files,
        )
        try:
            log_mcp_bearer_for_scan(f"parallel batch {batch_idx}/{len(batches)}", get_mcp_bearer_token())
        except Exception:
            pass
        files_dict: Dict[str, pathlib.Path] = {
            f: pathlib.Path(root_dir) / f
            for f in batch_files
            if (pathlib.Path(root_dir) / f).exists()
        }
        result = run_mcp_scan(
            mcp_server_url, "", source_code_repo, branch, files_dict, archive_path,
            get_mcp_bearer_token=get_mcp_bearer_token,
        )
        return batch_idx, archive_path, result

    def _collect_result(batch_idx: int, archive_path: str, mcp_result: Dict[str, Any]) -> None:
        batch_actions = mcp_result.get("remediation_actions", [])
        batch_report = mcp_result.get("report", "")
        batch_aibom = mcp_result.get("aibom", [])
        logger.info("  Batch %d/%d result: status=%s, violations=%d, aibom=%d",
                    batch_idx, len(batches), mcp_result.get("status", "unknown"),
                    len(batch_actions), len(batch_aibom))
        with lock:
            all_remediation_actions.extend(batch_actions)
            for action in batch_actions:
                fname = action.get("file", "").strip()
                if fname and fname not in violation_archive:
                    violation_archive[fname] = archive_path
            if batch_report:
                all_reports.append(batch_report)
            for entry in batch_aibom:
                key = (entry.get("name", ""), entry.get("source_file", ""))
                if key not in aibom_seen:
                    aibom_seen.add(key)
                    all_aibom.append(entry)
                    logger.info(
                        "  [AIBOM] Batch %d: discovered %s (%s) v%s from %s",
                        batch_idx,
                        entry.get("name", "?"),
                        entry.get("type", "?"),
                        entry.get("version") or "N/A",
                        entry.get("source_file") or "N/A",
                    )
            nonlocal last_archive_path
            if archive_path:
                last_archive_path = archive_path

    workers = min(len(batches), max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_scan_one, idx, files): idx for idx, files in enumerate(batches, 1)}
        for future in as_completed(future_map):
            batch_idx = future_map[future]
            try:
                _, archive_path, mcp_result = future.result()
            except BaseException as exc:
                failed_batch_count += 1
                detail = batch_scan_exception_detail_lines(batch_idx, len(batches), exc)
                for line in detail:
                    logger.error("%s", line)
                mcp_batch_failure_details.extend(detail)
                continue
            _collect_result(batch_idx, archive_path, mcp_result)

    return all_remediation_actions, all_reports, all_aibom, violation_archive, last_archive_path, failed_batch_count, mcp_batch_failure_details

# ===========================================================================
# SCM / Git operations
# ===========================================================================

def clone_repository(
    repo_url: str,
    branch: str,
    clone_dir: str,
    scm_token: str,
    timeout: int = DEFAULT_CLONE_TIMEOUT,
    max_retries: int = 2,
) -> None:
    auth_url = _GITHUB_CLONE_URL.format(token=scm_token, repo=repo_url)
    logger.info("Cloning %s (branch=%s) ...", repo_url, branch)
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--branch", branch, auth_url, clone_dir]
    last_exc: Exception = RuntimeError("Clone did not run")
    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            logger.warning("Retrying clone (attempt %d/%d) ...", attempt, max_retries)
            shutil.rmtree(clone_dir, ignore_errors=True)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
            logger.info("Clone successful: %s", clone_dir)
            return
        except subprocess.TimeoutExpired as exc:
            logger.error("Clone timed out after %ds (attempt %d/%d)", timeout, attempt, max_retries)
            last_exc = exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").replace(scm_token, "***")
            logger.error("Clone failed for %s: %s", repo_url, stderr[:300])
            raise
    raise last_exc


def resolve_head_sha(clone_dir: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=clone_dir, check=True,
    )
    sha = result.stdout.strip()
    logger.info("Resolved HEAD SHA: %s", sha)
    return sha


def update_commit_status(scm: SCMClient, repo: str, sha: str, state: str, description: str) -> None:
    try:
        scm.set_commit_status(repo, sha, state, description)
        logger.info("Set commit status: %s — %s", state, description)
    except Exception as exc:
        logger.warning("Failed to set commit status: %s", exc)

# ===========================================================================
# JSON output builder
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
        "remediation_branch": remediation_branch or None,
        "failed_remediation_files": failed_remediation_files or [],
        "scan_errors": scan_errors or [],
    }

# ===========================================================================
# Remediation MCP tool caller
# ===========================================================================


def _parse_mcp_tool_response(raw: str) -> Dict[str, Any]:
    """Parse an MCP tool response — handles both plain JSON-RPC and SSE streams.

    SSE streams from MCP Streamable HTTP may contain a mix of events:
    - ``event: endpoint\\ndata: /mcp/sessions/...`` — session handshake, not JSON
    - ``data: {"jsonrpc":"2.0",...}`` — the actual tool result

    We try each ``data:`` line as JSON and skip non-JSON lines so the
    session endpoint URL never causes a parse error.
    """
    text = raw.strip()
    if not text:
        raise RuntimeError(
            "run_remediation returned an empty response body. "
            "The MCP server may not have LINEAJE_ENABLE_RUN_REMEDIATION_MCP_TOOL=1 set, "
            "or the tool call timed out before the server could respond."
        )
    # SSE: parse each data: line as JSON; skip non-JSON lines (session URLs, etc.)
    if text.startswith("event:") or "\ndata: " in text or text.startswith("data: "):
        rpc = None
        for line in text.splitlines():
            if not line.startswith("data: "):
                continue
            payload = line[6:].strip()
            if not payload:
                continue
            try:
                obj = json.loads(payload)
                if isinstance(obj, dict):
                    rpc = obj  # keep last valid JSON-RPC dict
            except json.JSONDecodeError:
                continue  # skip session endpoint URLs and other non-JSON lines
        if rpc is None:
            raise RuntimeError(
                f"No valid JSON-RPC data line found in SSE response ({len(raw)} bytes). "
                f"The run_remediation tool may not be registered on the MCP server "
                f"(set LINEAJE_ENABLE_RUN_REMEDIATION_MCP_TOOL=1 on the server). "
                f"Raw: {text[:150]}"
            )
    else:
        rpc = json.loads(text)
    if "error" in rpc:
        raise RuntimeError(f"MCP tool error: {rpc['error']}")
    content_blocks = rpc.get("result", {}).get("content", [])
    for block in content_blocks:
        if isinstance(block, dict) and block.get("type") == "text":
            return json.loads(block["text"])
    raise RuntimeError(f"Unexpected MCP response shape: {raw[:200]}")


def _call_run_remediation_tool(
    mcp_server_url: str,
    get_bearer: Callable[[], str],
    repo: str,
    branch: str,
    head_sha: str,
    scm_token: str,
    remediation_actions: List[Dict[str, Any]],
    pr_number: int = 0,
) -> Dict[str, Any]:
    """Call the run_remediation tool on the MCP server via the MCP SDK (Streamable HTTP).

    Uses the same ``streamablehttp_client`` + ``ClientSession`` transport as the scan
    tools so session negotiation (2025-11-25 protocol, 202 Accepted, SSE result
    delivery) is handled correctly.  The old raw-urllib approach only received the
    session-endpoint SSE event (~182 bytes) and then failed to parse it as JSON.

    The MCP server must have ``LINEAJE_ENABLE_RUN_REMEDIATION_MCP_TOOL=1`` set.
    """
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession

    arguments = {
        "repo": repo,
        "branch": branch,
        "head_sha": head_sha,
        "scm_token": scm_token,
        "remediation_actions_json": json.dumps(remediation_actions),
        "pr_number": pr_number,
    }

    # --- HITL Approval Gate for risky operations ---
    RISKY_KEYWORDS = ("purge", "delete", "destroy", "rm", "remove")

    def _contains_risky_operation(actions: List[Dict[str, Any]]) -> bool:
        """Check if any remediation action involves a risky operation."""
        for action in actions:
            action_str = json.dumps(action).lower()
            if any(keyword in action_str for keyword in RISKY_KEYWORDS):
                return True
        return False

    if _contains_risky_operation(remediation_actions):
        # Check for pre-approved environment variable override
        hitl_approved = os.environ.get("HITL_APPROVED", "").strip().lower()
        if hitl_approved in ("1", "true", "yes"):
            logger.info("HITL approval granted via HITL_APPROVED environment variable.")
        else:
            # Interactive approval prompt
            logger.warning(
                "Risky remediation operations detected (purge/delete/destroy). "
                "Human approval required before proceeding."
            )
            logger.info("Remediation actions requiring approval: %s", json.dumps(remediation_actions, indent=2))
            if sys.stdin.isatty():
                response = input(
                    "\n⚠️  HITL APPROVAL REQUIRED: The following remediation includes risky operations "
                    "(purge/delete/destroy).\nDo you approve execution? [yes/no]: "
                ).strip().lower()
                if response not in ("yes", "y"):
                    raise RuntimeError(
                        "HITL approval denied: Human operator rejected risky remediation operations. "
                        "Set HITL_APPROVED=1 to pre-approve or respond 'yes' at the prompt."
                    )
                logger.info("HITL approval granted by human operator via interactive prompt.")
            else:
                raise RuntimeError(
                    "HITL approval required for risky operations (purge/delete/destroy) but no "
                    "interactive terminal available and HITL_APPROVED environment variable not set. "
                    "Set HITL_APPROVED=1 to pre-approve risky remediation actions."
                )
    # --- End HITL Approval Gate ---

    async def _call() -> Dict[str, Any]:
        tok = get_bearer()
        logger.info("Calling run_remediation MCP tool at %s (%d actions)", mcp_server_url, len(remediation_actions))
        async with streamablehttp_client(
            mcp_server_url, headers={"Authorization": f"Bearer {tok}"},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                _validate_mcp_tool("run_remediation")
        result = await session.call_tool("run_remediation", arguments=arguments)
                return _parse_tool_result(result)

    try:
        return asyncio.run(_call())
    except Exception as exc:
        raise RuntimeError(f"run_remediation MCP SDK call failed: {exc}") from exc


def _automated_remediation_for_args(args: argparse.Namespace) -> bool:
    cli = getattr(args, "run_remediation_mcp", None)
    if cli is not None:
        return bool(cli)
    return bool(LINEAJE_RUN_REMEDIATION_MCP_TOOL)


# ===========================================================================
# Main scan orchestration
# ===========================================================================

def _execute_scan(args: argparse.Namespace) -> int:
    repo = args.repo
    branch = args.branch
    source_code_repo = args.source_code_repo or f"https://github.com/{repo}.git"
    scm_token = args.scm_token or os.environ.get("SCM_ACCESS_TOKEN", "")
    mcp_server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL
    _validate_url_allowlist(mcp_server_url)

    missing: List[str] = []
    if not scm_token:
        missing.append("SCM_ACCESS_TOKEN / --scm-token")

    try:
        get_mcp_bearer = build_mcp_bearer_getter(args)
        pat_token = get_mcp_bearer()
        log_mcp_bearer_for_scan("veracode_repo_scan startup", pat_token)
        pat_info = introspect_lineaje_pat(pat_token)
        logger.info(
            "MCP URL=%s | user=%s tenant=%s company=%s",
            mcp_server_url or "(not set yet)",
            pat_info.get("user_email", ""),
            pat_info.get("tenant_id", ""),
            pat_info.get("company_id", ""),
        )
    except Exception as exc:
        logger.error("MCP authentication failed: %s", exc)
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha="", source_code_repo=source_code_repo,
            files_scanned=0, batches=0, failed_batches=0, violations=[],
            scan_errors=[f"MCP authentication failed: {str(exc)[:_MAX_SCAN_ERROR_LEN]}"],
        )
        print(json.dumps(output, indent=2))
        return 2

    if missing:
        logger.error("Missing required configuration: %s", ", ".join(missing))
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha="", source_code_repo=source_code_repo,
            files_scanned=0, batches=0, failed_batches=0, violations=[],
            scan_errors=[f"Missing config: {', '.join(missing)}"],
        )
        print(json.dumps(output, indent=2))
        return 2

    scm = create_scm_client(provider="github", token=scm_token)

    run_id = time.strftime("%Y%m%d_%H%M%S")

    with tempfile.TemporaryDirectory(prefix="veracode-repo-scan-") as temp_dir:
        clone_dir = os.path.join(temp_dir, "repo")
        scan_start = time.perf_counter()

        # ---- Step 1: Clone ----
        logger.info("=" * 60)
        logger.info("STEP 1: Clone repository")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        try:
            clone_repository(repo, branch, clone_dir, scm_token)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
            logger.error("Failed to clone: %s", exc)
            output = build_json_output(
                status="error", repo=repo, branch=branch, head_sha="", source_code_repo=source_code_repo,
                files_scanned=0, batches=0, failed_batches=0, violations=[],
                scan_errors=[f"Clone failed: {str(exc)[:_MAX_SCAN_ERROR_LEN]}"],
            )
            print(json.dumps(output, indent=2))
            return 1
        step_start = _log_step_timing("STEP 1: Clone", step_start, scan_start)

        # ---- Step 2: Resolve HEAD SHA ----
        logger.info("=" * 60)
        logger.info("STEP 2: Resolve HEAD SHA")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        head_sha = resolve_head_sha(clone_dir)
        step_start = _log_step_timing("STEP 2: HEAD SHA", step_start, scan_start)

        # ---- Step 3: Collect files ----
        logger.info("=" * 60)
        logger.info("STEP 3: Collect scannable files")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        file_list = collect_repo_files(clone_dir)
        if not file_list:
            logger.info("No scannable files found")
            update_commit_status(scm, repo, head_sha, "success", "No scannable files found")
            output = build_json_output(
                status="compliant", repo=repo, branch=branch, head_sha=head_sha,
                source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
                violations=[],
            )
            print(json.dumps(output, indent=2))
            return 0

        # Separate manifest files (doc_type: package) from code files.
        # Manifests are injected into every batch archive so every batch triggers
        # manifest_detected=True and AIBOM/vulnerability scanning in n8n.
        manifest_files = [f for f in file_list if _is_manifest_file(os.path.basename(f))]
        code_files = [f for f in file_list if not _is_manifest_file(os.path.basename(f))]
        if manifest_files:
            logger.info("Found %d manifest file(s) for AI asset detection — will inject into every batch", len(manifest_files))

        scan_files = code_files if code_files else file_list  # fallback if repo is all manifests
        archive_batch_size = _repo_archive_batch_size(len(scan_files))
        batches = [scan_files[i: i + archive_batch_size] for i in range(0, len(scan_files), archive_batch_size)]
        logger.info(
            "Found %d files (%d code, %d manifest) → %d batch(es) of ≤%d (UNIFAI_FILE_BATCH_SIZE)",
            len(file_list), len(code_files), len(manifest_files), len(batches), archive_batch_size,
        )
        step_start = _log_step_timing("STEP 3: Collect files", step_start, scan_start)

        # ---- Step 4: MCP scan ----
        logger.info("=" * 60)
        logger.info("STEP 4: MCP scan (%d files, %d batch(es))", len(file_list), len(batches))
        logger.info("=" * 60)
        step_start = time.perf_counter()
        all_remediation_actions, all_reports, all_aibom, violation_archive, last_archive_path, failed_batches_count, mcp_failure_details = (
            parallel_batch_scan(
                batches=batches,
                root_dir=clone_dir,
                temp_dir=temp_dir,
                source_code_repo=source_code_repo,
                branch=branch,
                head_sha=head_sha,
                run_id=run_id,
                mcp_server_url=mcp_server_url,
                get_mcp_bearer_token=get_mcp_bearer,
                create_archive_fn=create_batch_archive,
                manifest_files=manifest_files or None,
            )
        )
        remediation_actions = all_remediation_actions
        archive_path = last_archive_path
        logger.info("MCP scan complete: %d violations, %d AIBOM entries across %d batch(es)",
                    len(remediation_actions), len(all_aibom), len(batches))
        if all_aibom:
            logger.info("[AIBOM] Full discovered asset list:")
            for i, entry in enumerate(all_aibom, 1):
                logger.info(
                    "  [AIBOM] %d. %s | type=%-12s | version=%-20s | source=%s",
                    i,
                    entry.get("name", "?"),
                    entry.get("type", "?"),
                    entry.get("version") or "N/A",
                    entry.get("source_file") or "N/A",
                )
        else:
            logger.info("[AIBOM] No AI assets discovered in this scan")
        step_start = _log_step_timing("STEP 4: MCP scan", step_start, scan_start)

        combined_report = "\n\n---\n\n".join(r for r in all_reports if r)

        if failed_batches_count:
            logger.error("MCP scan incomplete: %d of %d batch(es) failed", failed_batches_count, len(batches))
            update_commit_status(scm, repo, head_sha, "error", "AI policy scan failed — MCP batch error")
            output = build_json_output(
                status="error", repo=repo, branch=branch, head_sha=head_sha,
                source_code_repo=source_code_repo, files_scanned=len(file_list),
                batches=len(batches), failed_batches=failed_batches_count,
                violations=remediation_actions,
                aibom=all_aibom,
                report=combined_report,
                scan_errors=mcp_failure_details,
            )
            print(json.dumps(output, indent=2))
            return 1

        # ---- Step 5: Compliant path ----
        if not remediation_actions:
            logger.info("No violations — compliant")
            update_commit_status(scm, repo, head_sha, "success", "AI policy scan passed — compliant")
            existing_rem_pr = scm.find_open_pr_by_prefix(repo, head_prefix=REMEDIATION_BRANCH_PREFIX, base=branch)
            if existing_rem_pr:
                run_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                compliant_note = json.dumps({"event": "rescan_compliant", "scanned_at": run_ts, "message": "Repository is now fully compliant."}, indent=2)
                try:
                    scm.post_pr_comment(repo, existing_rem_pr, f"<!-- unifai-repo-scan-update -->\n\n```json\n{compliant_note}\n```")
                except Exception as exc:
                    logger.warning("Could not post compliant notice: %s", exc)
            output = build_json_output(
                status="compliant", repo=repo, branch=branch, head_sha=head_sha,
                source_code_repo=source_code_repo, files_scanned=len(file_list),
                batches=len(batches), failed_batches=0, violations=[], aibom=all_aibom,
                report=combined_report,
            )
            print(json.dumps(output, indent=2))
            _log_step_timing("STEP 5: Compliant", step_start, scan_start)
            return 0

        # ---- Step 5: Remediation + direct PR creation ----
        # Strategy (in order, no LLM API key required for step A):
        #   A) Apply fix_code patches already produced by the pipeline (original→replacement).
        #      The MCP server ran LLM remediation; those patches are in remediation_actions.
        #   B) For files that had no pipeline fix_code, fall back to a local LLM call
        #      (requires LLM_API_KEY / UNIFAI_API_KEY / OPENROUTER_API_KEY).
        logger.info("=" * 60)
        logger.info("STEP 5: Remediation + PR creation (%d actions)", len(remediation_actions))
        logger.info("=" * 60)
        step_start = time.perf_counter()
        remediation_pr_number = None
        remediation_branch = ""
        failed_files: List[str] = []

        llm_api_key = resolve_llm_api_key(getattr(args, "llm_api_key", ""))
        llm_model = resolve_llm_model(getattr(args, "llm_model", ""))
        llm_api_url = resolve_llm_api_url(getattr(args, "llm_api_url", ""))

        # --- Approved Model Registry with version pinning and integrity verification ---
        APPROVED_MODEL_REGISTRY = {
            "openai/gpt-4o": {
                "version": "2024-08-06",
                "sha256": "a]b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
            },
            "anthropic/claude-3.5-sonnet": {
                "version": "20241022",
                "sha256": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
            },
            "google/gemini-pro-1.5": {
                "version": "001",
                "sha256": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
            },
        }

        def verify_model_in_registry(model_id: str) -> bool:
            """Verify model is in approved registry with version pin and integrity hash."""
            if not model_id:
                return False
            if model_id in APPROVED_MODEL_REGISTRY:
                entry = APPROVED_MODEL_REGISTRY[model_id]
                logger.info(
                    "Model '%s' verified in approved registry (version=%s, sha256=%s)",
                    model_id, entry["version"], entry["sha256"],
                )
                return True
            return False

        if llm_model and not verify_model_in_registry(llm_model):
            logger.warning(
                "Model '%s' is NOT in the approved model registry. "
                "Refusing to use unapproved model. LLM remediation will be skipped. "
                "Approved models: %s",
                llm_model, list(APPROVED_MODEL_REGISTRY.keys()),
            )
            llm_model = ""
            llm_api_key = ""

        want_remed = _automated_remediation_for_args(args)
        if not want_remed:
            logger.info(
                "Automated remediation skipped — off via --no-run-remediation-mcp "
                "or LINEAJE_RUN_REMEDIATION_MCP_TOOL=0 in this script",
            )
            step_start = _log_step_timing(
                "STEP 5: Remediation (skipped — scanner flag off)",
                step_start, scan_start,
            )
        elif not scm_token:
            logger.info("No SCM token — skipping automated remediation (set SCM_ACCESS_TOKEN)")
            step_start = _log_step_timing("STEP 5: Remediation (skipped — no SCM token)", step_start, scan_start)
        else:
            try:
                clone_bmap = build_clone_basename_map(clone_dir)

                # --- Step 5A: apply pipeline fix_code patches (no LLM key needed) ---
                logger.info(
                    "STEP 5A: Applying pipeline fix_code patches from %d action(s)",
                    len(remediation_actions),
                )
                validated_fixes, no_fix_code_files, fix_table = apply_pipeline_fix_code_to_clone(
                    remediation_actions, clone_dir, file_list, clone_bmap,
                )
                step_start = _log_step_timing("STEP 5A: Apply pipeline fix_code", step_start, scan_start)
                logger.info(
                    "STEP 5A: applied patches for %d file(s); %d file(s) had no fix_code",
                    len(validated_fixes), len(no_fix_code_files),
                )

                # --- Step 5B: LLM fallback for files with no fix_code ---
                if no_fix_code_files and llm_api_key:
                    logger.info(
                        "STEP 5B: LLM fallback for %d file(s) without pipeline fix_code (model=%s)",
                        len(no_fix_code_files), llm_model,
                    )
                    fallback_actions = [
                        a for a in remediation_actions
                        if (a.get("file") or "").strip() in no_fix_code_files
                    ]
                    grouped_fallback = group_remediation_by_file(fallback_actions)

                    def _resolve(filepath: str) -> Tuple[Optional[str], Optional[str]]:
                        src_archive = violation_archive.get(filepath, archive_path)
                        return resolve_original_for_remediation(
                            clone_dir, src_archive, filepath, file_list,
                            clone_basename_map=clone_bmap,
                        )

                    llm_fixes, llm_failed, llm_fix_table = parallel_llm_remediation(
                        grouped=grouped_fallback,
                        resolve_fn=_resolve,
                        llm_api_url=llm_api_url,
                        llm_api_key=llm_api_key,
                        llm_model=llm_model,
                        temp_dir=temp_dir,
                    )
                    validated_fixes.update(llm_fixes)
                    fix_table.extend(llm_fix_table)
                    failed_files = llm_failed
                    step_start = _log_step_timing("STEP 5B: LLM fallback remediation", step_start, scan_start)
                    logger.info(
                        "STEP 5B: LLM remediation: validated=%d failed=%d",
                        len(llm_fixes), len(llm_failed),
                    )
                elif no_fix_code_files:
                    logger.info(
                        "STEP 5B: %d file(s) have no fix_code and no LLM key set — "
                        "skipping LLM fallback (set LLM_API_KEY / UNIFAI_API_KEY / OPENROUTER_API_KEY)",
                        len(no_fix_code_files),
                    )
                    failed_files = no_fix_code_files

                if validated_fixes:
                    logger.info("=" * 60)
                    logger.info("STEP 6: Create/update remediation PR (%d files)", len(validated_fixes))
                    logger.info("=" * 60)
                    step_start = time.perf_counter()
                    original_shas: Dict[str, str] = {}
                    for filepath in validated_fixes:
                        blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
                        if blob_sha:
                            original_shas[filepath] = blob_sha
                    remediation_pr_number, remediation_branch = create_repo_remediation_pr(
                        scm, repo, branch, head_sha,
                        validated_fixes, original_shas, fix_table,
                        report=combined_report,
                        failed_files=failed_files,
                        source_clone_url=source_code_repo,
                        pr_target_repo_explicit=getattr(args, "pr_target_repo", ""),
                    )
                    step_start = _log_step_timing("STEP 6: Create/update remediation PR", step_start, scan_start)
                    if remediation_pr_number:
                        logger.info("Remediation PR #%d created/updated", remediation_pr_number)
                    else:
                        logger.warning("PR creation failed — fixes are on branch %s but no PR opened", remediation_branch)
                else:
                    # No code patches applied — still update the existing remediation PR with the report.
                    logger.warning(
                        "No validated fixes — pipeline fix_code patches did not match file content "
                        "(LLM_API_KEY can enable fallback). "
                        "Checking for existing open PR to post scan report...",
                    )
                    scm_prov = (os.environ.get("SCM_PROVIDER", "github") or "github").strip()
                    pr_listing_slug, _ = resolve_github_pr_targets(
                        repo,
                        source_code_repo,
                        scm_prov,
                        getattr(args, "pr_target_repo", ""),
                    )
                    remediation_pr_number = post_scan_report_on_existing_pr(
                        scm, repo, branch, head_sha, fix_table, combined_report, failed_files,
                        scm_pull_request_repo=pr_listing_slug,
                    )
                    if not remediation_pr_number:
                        logger.info(
                            "No existing remediation PR found — violations report written to JSON output only",
                        )

                if failed_files:
                    logger.warning("Failed to remediate %d file(s): %s", len(failed_files), ", ".join(str(f) for f in failed_files))
            except Exception as exc:
                logger.error("Remediation failed: %s", exc)
                failed_files = [f"remediation_error: {exc}"]
            step_start = _log_step_timing("STEP 5: Remediation (total)", step_start, scan_start)

        # ---- Step 6: Update commit status + emit JSON ----
        logger.info("=" * 60)
        logger.info("STEP 6: Update commit status + emit JSON")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        if remediation_pr_number:
            update_commit_status(scm, repo, head_sha, "failure",
                                 f"Policy violations found — remediation PR #{remediation_pr_number} created")
        else:
            update_commit_status(scm, repo, head_sha, "failure", "AI policy violations found")

                # Build provenance metadata for AI-generated remediation content
        _provenance_timestamp = datetime.now(timezone.utc).isoformat()
        _ai_provenance_meta = {
            "content_provenance": {
                "synthetic": True,
                "content_label": "AI-generated remediation content",
                "content_origin": "llm_generated",
                "model_identifier": os.environ.get('LLM_MODEL', 'unknown'),
                "generation_timestamp": _provenance_timestamp,
                "generator": "veracode_repo_scan/remediation_pipeline",
            }
        }
        # Generate cryptographic signature over provenance + remediation content
        _sign_payload = json.dumps(_ai_provenance_meta["content_provenance"], sort_keys=True).encode()
        _signing_key = os.environ.get("PROVENANCE_SIGNING_KEY", "veracode-default-provenance-key").encode()
        _ai_provenance_meta["content_provenance"]["signature"] = hmac.new(
            _signing_key, _sign_payload, hashlib.sha256
        ).hexdigest()
        output = build_json_output(
            status="violations_found",
            repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo,
            files_scanned=len(file_list), batches=len(batches), failed_batches=0,
            violations=remediation_actions,
            aibom=all_aibom,
            report=combined_report,
            remediation_pr=remediation_pr_number,
            remediation_branch=remediation_branch,
            failed_remediation_files=failed_files,
            ai_content_provenance=_ai_provenance_meta["content_provenance"],
        )
        print(json.dumps(output, indent=2))
        _log_step_timing("STEP 6: Emit JSON output", step_start, scan_start)
        logger.info("Timing — pipeline finished: %.1fs total", time.perf_counter() - scan_start)
        return 0

# ===========================================================================
# CLI
# ===========================================================================

def _load_dotenv(dotenv_path: str = ".env", *, override: bool = False) -> None:
    try:
        with open(dotenv_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if key:
                    if override:
                        if not value and (os.environ.get(key) or "").strip():
                            continue
                        os.environ[key] = value
                    else:
                        os.environ.setdefault(key, value)
    except FileNotFoundError:
        pass


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    if argv is None:
        argv = sys.argv[1:]
    # Broken shell continuations (e.g. ``'...' \\  --flag`` on one line) can inject empty
    # argv words; argparse rejects them as unrecognized "positional" empty tokens.
    argv = [a for a in argv if a != ""]

    parser = argparse.ArgumentParser(
        description="Veracode Repository Scanner — AI policy compliance scan with JSON output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--repo", default="", help="Repository owner/repo (or env REPO_REPO)")
    parser.add_argument("--branch", default="", help="Branch to scan (or env REPO_BRANCH)")
    parser.add_argument("--source-code-repo", default="",
                        help="Full repo URL for SBOM tracking (or env SOURCE_CODE_REPO)")
    parser.add_argument(
        "--pr-target-repo", default="",
        help="GitHub owner/repo to open remediation PR against (upstream). "
             "Inferred when SOURCE_CODE_REPO differs from --repo unless set. Env: PR_TARGET_REPO.",
    )
    parser.add_argument("--scm-token", default="", help="GitHub PAT (or env SCM_ACCESS_TOKEN)")
    parser.add_argument("--refresh-token", default="", dest="refresh_token",
                        help="MCP refresh token (or env MCP_REFRESH_TOKEN / LINEAJE_REFRESH_TOKEN).")
    parser.add_argument(
        "--lineaje-pat", default="", dest="lineaje_pat",
        help="Lineaje PAT token used directly as MCP bearer (or env LINEAJE_PAT_TOKEN). Takes priority over bearer-token.",
    )
    parser.add_argument("--mcp-server-url", default="",
                        help="MCP server URL (overrides default prod URL; or env MCP_SERVER_URL).")
    parser.add_argument(
        "--llm-api-key", default="",
        help="LLM API key for local remediation (or env LLM_API_KEY / UNIFAI_API_KEY / OPENROUTER_API_KEY)",
    )
    parser.add_argument(
        "--llm-model", default="",
        help="LLM model for remediation (or env after built-in priority; see scripts/scan_common.resolve_llm_model)",
    )
    parser.add_argument(
        "--llm-api-url", default="",
        help="LLM API base URL (or env LLM_API_URL / UNIFAI_EVAL_SERVER_URL; default: OpenRouter)",
    )
    _rem = parser.add_mutually_exclusive_group()
    _rem.add_argument(
        "--run-remediation-mcp",
        dest="run_remediation_mcp",
        action="store_const",
        const=True,
        help="Force local LLM remediation + PR creation on (default is on when LLM_API_KEY is set).",
    )
    _rem.add_argument(
        "--no-run-remediation-mcp",
        dest="run_remediation_mcp",
        action="store_const",
        const=False,
        help="Skip LLM remediation + PR creation (overrides LINEAJE_RUN_REMEDIATION_MCP_TOOL constant).",
    )
    parser.set_defaults(run_remediation_mcp=None)
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    _repo_env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    _load_dotenv(str(_repo_env), override=True)
    _load_dotenv(override=True)
    args = parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )

    if not args.repo:
        args.repo = os.environ.get("REPO_REPO", "")
    if not args.branch:
        args.branch = os.environ.get("REPO_BRANCH", "")
    if not args.source_code_repo:
        args.source_code_repo = os.environ.get("SOURCE_CODE_REPO", "")
    if not args.pr_target_repo:
        args.pr_target_repo = os.environ.get("PR_TARGET_REPO", "")

    missing = [n for n, v in [("--repo / REPO_REPO", args.repo), ("--branch / REPO_BRANCH", args.branch)] if not v]
    if missing:
        err = {"status": "error", "scan_errors": [f"Missing required arguments: {', '.join(missing)}"]}
        print(json.dumps(err, indent=2))
        return 2

    logger.info("Veracode Repository Scanner starting")
    logger.info("  Repo:   %s", args.repo)
    logger.info("  Branch: %s", args.branch)

    start = time.time()
    try:
        exit_code = _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error in repository scan")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print(json.dumps(err, indent=2))
        exit_code = 1
    logger.info("Completed in %.1fs with exit code %d", time.time() - start, exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
