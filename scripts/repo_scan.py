#!/usr/bin/env python3
"""UniFAI Repository Scanner — CLI tool for scanning full repositories for AI policy compliance.

Clones a repository, archives its contents, runs them through the MCP scanning pipeline,
and optionally creates a remediation PR when violations are found.

Unlike pr_scan.py (which scans PR diffs), this script scans the **entire** repository
at a given branch, enabling scheduled / ad-hoc governance checks outside the PR flow.

Usage::

    python scripts/repo_scan.py \
        --provider github \
        --repo owner/repo \
        --branch main

Environment variables (preferred for CI)::

    SCM_PROVIDER         — SCM provider: github | bitbucket | gitlab (default: github)
    SCM_ACCESS_TOKEN     — SCM access token (GitHub PAT, Bitbucket app password, GitLab PAT)
    MCP_BEARER_TOKEN     — MCP server bearer token (Keycloak JWT)
    MCP_DEVICE_CODE      — Native device code (alternative to bearer; exchanges for tokens)
    DEVICE_CODE          — Alias for MCP_DEVICE_CODE
    MCP_REFRESH_TOKEN    — Native refresh token (alternative to device code and bearer). POSTs to renew-access-token only; do not combine with MCP_DEVICE_CODE
    LINEAJE_REFRESH_TOKEN — Alias for MCP_REFRESH_TOKEN (or optional scripts/mcp.json → ``refresh_token`` when bearer_token is empty)
    LINEAJE_FETCH_ACCESS_TOKEN_URL   — fetch-access-token base URL (no ``?deviceCode=``). Default: ``https://lineaje-identity-service.v2.prod.veedna.com/lineajeidentity/api/v1/auth/native/fetch-access-token``
    LINEAJE_RENEW_ACCESS_TOKEN_URL   — renew-access-token URL (same identity host as fetch for prod). Default: ``https://lineaje-identity-service.v2.prod.veedna.com/lineajeidentity/api/v1/auth/native/renew-access-token`` when MCP is v2 prod / env unset
    LINEAJE_TOKEN_REFRESH_SKEW_SEC   — Refresh this many seconds before expiry (default: ``120``)
    LINEAJE_DEVICE_CODE_POLL_TIMEOUT_SEC — Max seconds to poll when OIDC returns authorization_pending (default: ``300``)
    LINEAJE_DEVICE_CODE_POLL_INTERVAL_SEC — Seconds between polls (default: ``5``)
    MCP_SERVER_URL       — MCP server endpoint (e.g. https://mcp.example.com/mcp)
    UNIFAI_LOG_FULL_MCP_BEARER_TOKEN / LINEAJE_LOG_FULL_MCP_BEARER_TOKEN — Full JWT logging **defaults to on**
        when unset; set ``0`` / ``false`` / ``no`` / ``off`` to disable (recommended for production).
        INFO logs always include ``jwt_exp_utc`` when the bearer is a JWT.
    LLM_API_KEY          — API key for remediation LLM calls (OpenRouter; ``Authorization: Bearer``)
    UNIFAI_API_KEY / OPENROUTER_API_KEY — Fallback if ``LLM_API_KEY`` is unset (same bearer format)
    LLM_MODEL / UNIFAI_REMED_MODEL / UNIFAI_EVAL_MODEL — Remediation model (built-in default: ``anthropic/claude-sonnet-4.6``; see ``scripts/scan_common.py`` ``DEFAULT_LLM_MODEL``)
    LLM_API_URL / UNIFAI_EVAL_SERVER_URL — OpenAI-compatible base or full …/chat/completions URL (blank LLM_API_URL falls back).
        Built-in defaults when unset/blank: ``LLM_API_URL`` and ``LLM_MODEL`` are defined as ``DEFAULT_LLM_API_URL`` / ``DEFAULT_LLM_MODEL`` in ``scripts/scan_common.py``. ``LLM_API_KEY`` defaults to empty in source (``DEFAULT_LLM_API_KEY``) — set credentials in env only.
    LINEAJE_LOG_FILE / AIPO_LOG_FILE — Append all logs (this tool, ``scan_common``, child loggers)
        to a UTF-8 text file; parent directories are created. Or pass ``--log-file PATH`` for one run.
        **Not tied to MCP host.** When unset and MCP URL is not loopback (e.g. deployed MCP),
        a file under repo ``logs/`` is chosen automatically unless ``LINEAJE_SCAN_NO_AUTO_REMOTE_LOG=1``.

Constants (in this file — not environment variables)::

    LINEAJE_RUN_REMEDIATION_MCP_TOOL — ``1`` = after violations, run LLM remediation and open a remediation PR
        (remote clone mode); ``0`` = skip. Override with ``--run-remediation-mcp`` / ``--no-run-remediation-mcp``.

Exit codes::

    0 — scan completed (compliant or violations posted)
    1 — scan/runtime error
    2 — configuration error
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import logging
import os
import pathlib
import ssl
import subprocess
import sys
import tempfile
import time
from functools import partial
import urllib.error
import urllib.request
import zipfile
from typing import Any, Callable, Dict, List, Optional, Tuple

# macOS Python installations often lack system CA certs. Install a certifi-backed
# SSL context globally so urllib calls to S3/GitHub/etc. don't fail.
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX = ssl.create_default_context()

_https_handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
urllib.request.install_opener(urllib.request.build_opener(_https_handler))

# Ensure scripts/ directory is on the path so we can import scm_client
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
_REPO_ROOT = os.path.dirname(SCRIPTS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from scm_client import create_scm_client, SCMClient  # noqa: E402
from config import (  # noqa: E402
    REPO_SCAN_COMMENT_MARKER,
    REPO_REMEDIATION_BRANCH_PREFIX,
    DEFAULT_UNIFAI_FILE_BATCH_SIZE,
)
from scan_common import (  # noqa: E402
    _ARCHIVE_EXCLUDE,
    _ARCHIVE_EXCLUDE_GLOBS,
    _BINARY_EXTENSIONS,
    MAX_ARCHIVE_FILES,
    MAX_ARCHIVE_SIZE_BYTES,
    DEFAULT_LLM_API_URL,
    DEFAULT_LLM_MODEL,
    _short_description,
    compute_line_changes,
    _upload_to_s3,
    run_mcp_scan,
    group_remediation_by_file,
    generate_fix_with_llm,
    validate_code,
    post_or_update_comment as _post_or_update_comment,
    resolve_llm_api_key,
    resolve_llm_api_url,
    resolve_llm_model,
    apply_llm_os_environ_defaults,
    log_effective_llm_remediation_config,
    detect_project_metadata,
    collect_manifest_files,
    collect_repo_files,
    collect_scannable_files,
    skill_scan_archive_metadata,
    load_mcp_config,
    parallel_batch_scan,
    parallel_llm_remediation,
    canonicalize_project_name,
    build_mcp_bearer_getter,
    introspect_lineaje_pat,
    log_mcp_bearer_for_scan,
    device_code_effective,
    refresh_token_effective,
    lineaje_native_auth_log_label,
    _refresh_token_effective_with_mcp_file,
    _mcp_refresh_from_file_when_no_bearer,
    build_remediation_scan_json_payload,
    format_pr_body_with_json_scan_results,
    markdown_remediation_details_table,
    markdown_violations_per_file_table,
    resolve_github_pr_targets,
    resolve_remediation_branch_and_existing_pr,
    stable_repo_scan_remediation_branch,
    GITHUB_PR_EMBEDDED_REPORT_MAX_CHARS,
)
from skill_remediation import (  # noqa: E402
    SkillRename,
    apply_skill_block_renames,
    commit_content_fixes,
    commit_skill_block_renames,
    filter_actions_for_llm_remediation,
    has_skill_block_remediation_actions,
)

logger = logging.getLogger("repo_scan")

# 1 = remote mode: LLM remediation + remediation PR after violations; 0 = skip. Not read from os.environ.
LINEAJE_RUN_REMEDIATION_MCP_TOOL = 1


def _automated_remediation_for_args(args: argparse.Namespace) -> bool:
    cli = getattr(args, "run_remediation_mcp", None)
    if cli is not None:
        return bool(cli)
    return bool(LINEAJE_RUN_REMEDIATION_MCP_TOOL)


def _log_step_timing(label: str, step_start: float, scan_start: float) -> float:
    """Log wall time for the step just completed and cumulative time since scan_start."""
    now = time.perf_counter()
    logger.info(
        "Timing — %s: %.1fs this step | %.1fs total",
        label,
        now - step_start,
        now - scan_start,
    )
    return now


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Constants sourced from config.py; local aliases kept for backward compatibility.
COMMENT_MARKER = REPO_SCAN_COMMENT_MARKER
REMEDIATION_BRANCH_PREFIX = REPO_REMEDIATION_BRANCH_PREFIX
DEFAULT_MAX_ARCHIVE_SIZE_MB = 500
DEFAULT_CLONE_TIMEOUT = 300
# DEFAULT_UNIFAI_FILE_BATCH_SIZE imported from config.py above.


def _build_mcp_bearer_getter(
    args: argparse.Namespace,
    *,
    mcp_cfg_fallback_token: str = "",
    mcp_cfg_refresh_token: str = "",
) -> Callable[[], str]:
    """Delegate to :func:`scan_common.build_mcp_bearer_getter` (keeps script API stable)."""
    return build_mcp_bearer_getter(
        args,
        mcp_cfg_fallback_token=mcp_cfg_fallback_token,
        mcp_cfg_refresh_token=mcp_cfg_refresh_token,
    )


# Auth URL templates per SCM provider
_AUTH_URL_TEMPLATES = {
    "github": "https://x-access-token:{token}@github.com/{repo}.git",
    "bitbucket": "https://x-token-auth:{token}@bitbucket.org/{repo}.git",
    "gitlab": "https://oauth2:{token}@gitlab.com/{repo}.git",
}


def _repo_archive_batch_size(total_files: int) -> int:
    """Return repository archive batch size from UNIFAI_FILE_BATCH_SIZE.

    ``UNIFAI_FILE_BATCH_SIZE`` is the single source of truth for file batching.
    For repository archives, 0 or a negative value means "all files in one
    archive" because ``range(..., step=0)`` is invalid.
    """
    raw = (os.environ.get("UNIFAI_FILE_BATCH_SIZE") or "").strip()
    if not raw:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    try:
        size = int(raw)
    except ValueError:
        logger.warning(
            "Invalid UNIFAI_FILE_BATCH_SIZE=%r; using default %d",
            raw,
            DEFAULT_UNIFAI_FILE_BATCH_SIZE,
        )
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    if size <= 0:
        return max(1, total_files)
    return size


# ===========================================================================
# 1. Clone Repository
# ===========================================================================

def clone_repository(
    repo_url: str,
    branch: str,
    clone_dir: str,
    scm_token: str,
    provider: str,
    timeout: int = DEFAULT_CLONE_TIMEOUT,
    max_retries: int = 2,
) -> None:
    """Clone a repository (shallow, single branch) into *clone_dir*.

    Builds an authenticated URL based on the SCM provider and runs ``git clone``.
    Retries up to *max_retries* times on timeout (handles transient GitHub hangs).
    """
    template = _AUTH_URL_TEMPLATES.get(provider)
    if not template:
        raise ValueError(f"Unsupported SCM provider: {provider}")

    auth_url = template.format(token=scm_token, repo=repo_url)
    logger.info("Cloning %s (branch=%s, provider=%s) ...", repo_url, branch, provider)

    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--branch", branch, auth_url, clone_dir]

    last_exc: Exception = RuntimeError("Clone did not run")
    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            logger.warning("Retrying clone (attempt %d/%d) ...", attempt, max_retries)
            # Remove partial clone dir before retry
            import shutil
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
            raise  # auth/not-found errors — no point retrying

    raise last_exc


# ===========================================================================
# 2. Archive Creation (Repo-specific)
# ===========================================================================

# collect_repo_files is imported from scan_common (shared with MCP server tool)

def create_batch_archive(
    clone_dir: str,
    archive_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: int = 0,
    run_id: str = "",
    skill_paths: Optional[List[str]] = None,
) -> str:
    """Create a zip archive for a specific subset of files.

    Args:
        clone_dir: Root of the cloned repository.
        archive_dir: Directory to write the zip into.
        file_subset: Repo-relative paths to include (pre-filtered by caller).
        source_code_repo: Full repo URL (for metadata).
        branch: Branch name (for metadata).
        head_sha: HEAD commit SHA (for metadata).
        batch_index: Used to give each batch archive a unique name.
        run_id: Unused — kept for API compatibility.

    Returns:
        Path to the created zip archive.
    """
    archive_path = os.path.join(archive_dir, f"repo_scan_batch_{batch_index}.zip")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in file_subset:
            full_path = os.path.join(clone_dir, rel_path)
            if os.path.isfile(full_path):
                zf.write(full_path, rel_path)

        metadata = {
            "scan_source": "repo_scan",
            "repo": source_code_repo,
            "branch": branch,
            "head_sha": head_sha,
            "scan_type": "full_repository",
            "batch_index": batch_index,
            "batch_file_count": len(file_subset),
        }
        if skill_paths is not None:
            metadata.update(skill_scan_archive_metadata(skill_paths))
        zf.writestr("user_metadata.json", json.dumps(metadata, indent=2))

    size_kb = os.path.getsize(archive_path) // 1024
    logger.info(
        "Created batch archive #%d: %d files, %d KB → %s",
        batch_index, len(file_subset), size_kb, archive_path,
    )
    return archive_path


def _norm_archive_rel_path(p: str) -> str:
    """Normalize a repo-relative path for comparison (POSIX-style, no ./ prefix)."""
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def build_clone_basename_map(clone_dir: str) -> Dict[str, List[pathlib.Path]]:
    """Walk the clone and return a mapping of basename → [full paths].

    Built once before the remediation loop so basename lookups are O(1)
    instead of a fresh rglob per file.
    """
    result: Dict[str, List[pathlib.Path]] = {}
    root = pathlib.Path(clone_dir)
    for p in root.rglob("*"):
        if p.is_file():
            result.setdefault(p.name, []).append(p)
    return result


def resolve_original_for_remediation(
    clone_dir: str,
    archive_path: str,
    filepath: str,
    file_list: List[str],
    clone_basename_map: Optional[Dict[str, List[pathlib.Path]]] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve remediation *filepath* to ``(relative_path, utf-8 text)``.

    Resolution order:
    1. Exact path match in the cloned working tree.
    2. Exact / normalised match inside the batch archive.
    3. Unique basename match inside the batch archive.
    4. Case-insensitive match inside the batch archive.
    5. Unique basename match across the entire clone (via pre-built map).
    6. Case-insensitive unique basename match across the clone.

    Returns:
        ``(resolved_relative_path, content)`` or ``(None, None)`` if not found.
    """
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_archive_rel_path(raw)
    root = pathlib.Path(clone_dir)

    # 1. Exact path in clone
    local = root / raw
    if local.is_file():
        return _norm_archive_rel_path(raw), local.read_text(errors="replace")

    # 2–4. Archive-based lookups
    if os.path.isfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            names = [
                n for n in zf.namelist()
                if not n.endswith("/") and n != "user_metadata.json"
            ]
            norm_to_name = {_norm_archive_rel_path(n): n for n in names}

            def _read(member: str) -> str:
                return zf.read(member).decode("utf-8", errors="replace")

            # 2a. Exact normalised match
            if norm_fp in norm_to_name:
                m = norm_to_name[norm_fp]
                logger.info("Remediation path %r — using archive member %r (exact)", raw, m)
                return _norm_archive_rel_path(m), _read(m)

            # 2b. Match against file_list from the same archive build
            for listed in file_list:
                if _norm_archive_rel_path(listed) == norm_fp:
                    logger.info("Remediation path %r — matched file_list entry %r", raw, listed)
                    return _norm_archive_rel_path(listed), _read(listed)

            # 3. Unique basename match inside archive
            base = pathlib.Path(norm_fp).name
            base_matches = [n for n in names if pathlib.Path(n).name == base]
            if len(base_matches) == 1:
                m = base_matches[0]
                logger.info(
                    "Remediation path %r — resolved via unique basename to archive member %r",
                    raw, m,
                )
                return _norm_archive_rel_path(m), _read(m)

            # 4. Case-insensitive unique match inside archive
            ci_matches = [n for n in names if n.casefold() == norm_fp.casefold()]
            if len(ci_matches) == 1:
                m = ci_matches[0]
                logger.info(
                    "Remediation path %r — resolved via case-insensitive match to %r",
                    raw, m,
                )
                return _norm_archive_rel_path(m), _read(m)
    else:
        logger.warning("Archive missing for fallback read: %s", archive_path)

    # 5–6. Full-clone basename lookups (catches files in other batches)
    base = pathlib.Path(norm_fp).name
    bmap = clone_basename_map or {}

    # 5. Unique basename in clone
    clone_hits = bmap.get(base, [])
    if len(clone_hits) == 1:
        full = clone_hits[0]
        rel = str(full.relative_to(root))
        logger.info(
            "Remediation path %r — resolved via clone basename map to %r", raw, rel
        )
        return _norm_archive_rel_path(rel), full.read_text(errors="replace")

    # 6. Case-insensitive unique basename in clone
    if not clone_hits:
        ci_clone = [
            p for name, paths in bmap.items()
            if name.casefold() == base.casefold()
            for p in paths
        ]
        if len(ci_clone) == 1:
            full = ci_clone[0]
            rel = str(full.relative_to(root))
            logger.info(
                "Remediation path %r — resolved via clone case-insensitive basename to %r",
                raw, rel,
            )
            return _norm_archive_rel_path(rel), full.read_text(errors="replace")

    if len(clone_hits) > 1:
        logger.warning(
            "Remediation path %r — ambiguous: %d clone matches for basename %r: %s",
            raw, len(clone_hits), base,
            [str(p.relative_to(root)) for p in clone_hits[:5]],
        )

    logger.warning(
        "Cannot resolve remediation file %r — not in clone and not in archive %s",
        raw, archive_path,
    )
    return None, None


# ===========================================================================
# 3. PR Existence Check
# ===========================================================================

def check_pr_exists(scm: SCMClient, repo: str, pr_number: int) -> bool:
    """Check whether a PR (or merge request) exists and is open.

    Returns True if the PR exists, False otherwise.
    """
    try:
        existing = scm.find_open_pr(repo, head="", base="")
        # find_open_pr may not work for direct lookup — fall back to checking
        # the PR comment endpoint as a lightweight existence probe.
    except Exception:
        pass

    # Try fetching comments as a lightweight existence check
    try:
        scm.find_bot_comment(repo, pr_number, COMMENT_MARKER)
        return True
    except Exception:
        logger.debug("PR #%d not found or not accessible in %s", pr_number, repo)
        return False



# ===========================================================================
# 4. Resolve HEAD SHA
# ===========================================================================

def resolve_head_sha(clone_dir: str) -> str:
    """Resolve the HEAD commit SHA from a cloned repository."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        cwd=clone_dir,
        check=True,
    )
    sha = result.stdout.strip()
    logger.info("Resolved HEAD SHA: %s", sha)
    return sha


# ===========================================================================
# 5. Commit Status Helper
# ===========================================================================

def update_commit_status(
    scm: SCMClient,
    repo: str,
    sha: str,
    state: str,
    description: str,
) -> None:
    """Update the commit status on a SHA.

    States: pending, success, failure, error
    """
    try:
        scm.set_commit_status(repo, sha, state, description)
        logger.info("Set commit status: %s — %s", state, description)
    except Exception as exc:
        logger.warning("Failed to set commit status: %s", exc)


# ===========================================================================
# 6. Remediation PR (repo-scan specific)
# ===========================================================================

def _post_rescan_comment(
    scm: SCMClient,
    repo: str,
    pr_number: int,
    committed_files: List[str],
    fix_table: List[Dict[str, str]],
) -> None:
    """Post a follow-up comment on an existing remediation PR summarising this re-scan.

    Each re-scan appends a new comment (no idempotency marker) so the PR
    accumulates a chronological history of what each scan run fixed.
    """
    run_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # Per-file violation counts for this run
    violations_per_file: Dict[str, int] = {}
    for row in fix_table:
        f = row["file"]
        violations_per_file[f] = violations_per_file.get(f, 0) + 1
    total_violations = sum(violations_per_file.values())

    scan_json = build_remediation_scan_json_payload(
        repo=repo,
        branch="",
        commit="",
        files_remediated=len(committed_files),
        violations_per_file=violations_per_file,
        remediation_details=fix_table,
        generator="UniFAI Repository Scanner",
        extra={
            "update_kind": "rescan",
            "committed_files": list(committed_files),
            "run_timestamp_utc": run_ts,
        },
    )
    table_blocks: List[str] = []
    vtbl = markdown_violations_per_file_table(violations_per_file)
    if vtbl:
        table_blocks.extend(["### Violations per file", "", vtbl, ""])
    dtbl = markdown_remediation_details_table(fix_table)
    if dtbl:
        table_blocks.extend(["### Remediation details", "", dtbl, ""])

    lines = [
        f"<!-- unifai-repo-scan-update -->",
        "",
        f"## UniFAI Re-scan Update — {run_ts}",
        "",
        f"**{len(committed_files)} file(s) remediated** &nbsp;|&nbsp; **{total_violations} violation(s) fixed** in this scan run.",
        "",
        *table_blocks,
        "✅ All fixes validated — syntax check passed.",
        "",
        f"_Generated by UniFAI Repository Scanner at {run_ts}_",
    ]

    body = "\n".join(lines)
    try:
        scm.post_pr_comment(repo, pr_number, body)
        logger.info("Posted re-scan summary comment on PR #%d", pr_number)
    except Exception as exc:
        logger.warning("Failed to post re-scan comment on PR #%d: %s", pr_number, exc)


def create_repo_remediation_pr(
    scm: SCMClient,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    original_shas: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    skill_renames: Optional[List[SkillRename]] = None,
    report: str = "",
    failed_files: Optional[List[str]] = None,
    source_clone_url: str = "",
    pr_target_repo_explicit: str = "",
    scm_provider: str = "github",
) -> Tuple[Optional[int], str]:
    """Create a remediation branch, commit fixes, and open a PR for a repo scan.

    Pull requests are POSTed via :func:`~scm_client.GitHubClient.create_pull_request` on
    ``pr_target_repo`` when *source_clone_url* (or explicit override) references an upstream
    ``owner/repo`` different from *repo* (fork workflow).

    Args:
        scm: SCM client instance.
        repo: Repository slug where the branch lives (fork when scanning forks).
        branch: Base branch scanned.
        head_sha: HEAD commit SHA of that branch.
        validated_fixes: Mapping of ``filepath → fixed_content``.
        original_shas: Mapping of ``filepath → blob_sha`` on *branch* before commits.
        fix_table: Rows of {policy, description, file, lines} for the PR body tables.
        report: Verbatim MCP / LINEAJE markdown report for the PR body.
        failed_files: Optional remediation failures for footer context.
        source_clone_url: URL used when inferring upstream vs fork (GitHub HTTPS/SSH).
        pr_target_repo_explicit: Force PR base repo slug ``owner/repo`` (upstream).
        scm_provider: ``github``, ``gitlab``, … — fork→upstream is GitHub-specific today.

    Returns:
        *(remediation PR number or None, remediation branch name)*.
    """
    if not validated_fixes and not skill_renames:
        logger.info("No validated fixes — skipping remediation PR")
        return None, ""

    pr_repo, fork_login = resolve_github_pr_targets(
        repo, source_clone_url, scm_provider, pr_target_repo_explicit,
    )
    if pr_repo.lower() != repo.lower():
        logger.info(
            "Remediation PR opens on upstream %s (fixes committed on fork %s, head qualifier %s)",
            pr_repo, repo, fork_login,
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
    renames = skill_renames or []
    if renames:
        committed.extend(
            commit_skill_block_renames(
                scm, repo, branch_name, renames, original_shas,
                branch_existed_for_blob=branch_existed_for_blob,
                commit_tag="unifai-repo-scan",
            )
        )
    renamed_old = {old for old, _, _ in renames}
    committed.extend(
        commit_content_fixes(
            scm, repo, branch_name, validated_fixes, original_shas, fix_table,
            branch_existed_for_blob=branch_existed_for_blob,
            commit_tag="unifai-repo-scan",
            skip_paths=renamed_old,
        )
    )

    if not committed:
        if existing_pr_num is not None:
            logger.info("No successful file commits — still refreshing PR #%s scan JSON/description", existing_pr_num)
        else:
            logger.warning("No files were successfully committed — skipping remediation PR workflow")
            return None, branch_name

    title = f"[unifai-bot] fix: AI policy remediation for {branch}@{sha_short}"

    violations_per_file: Dict[str, int] = {}
    for row in fix_table:
        violations_per_file[row["file"]] = violations_per_file.get(row["file"], 0) + 1
    total_violations = sum(violations_per_file.values())

    footer_extra = ""
    if failed_files:
        footer_extra = "\n\n**Remediation engine:** Some files failed automated fix application — inspect logs.\n"

    scan_json = build_remediation_scan_json_payload(
        repo=repo,
        branch=branch,
        commit=sha_short,
        files_remediated=len(validated_fixes),
        violations_per_file=violations_per_file,
        remediation_details=fix_table,
        generator="UniFAI Repository Scanner",
        extra={
            "pr_target_repo": pr_repo if pr_repo != repo else None,
            "report_available": bool((report or "").strip()),
            "failed_remediation_files": failed_files or [],
        },
    )
    body = format_pr_body_with_json_scan_results(
        comment_marker=COMMENT_MARKER,
        title_md="## UniFAI Automated Policy Remediation",
        intro_md=(
            f"This PR contains AI policy compliance fixes for **`{repo}`** "
            f"(push target) merging into **`{branch}`** @ `{sha_short}`.\n\n"
            f"- **Remediation PR repo:** `{pr_repo}`\n"
            f"- **Clone / scan URL hint:** `{source_clone_url or '—'}`"
        ),
        stats_md=(
            f"**Files remediated:** {len(validated_fixes)} &nbsp;|&nbsp; "
            f"**Total violations fixed:** {total_violations}"
        ),
        payload=scan_json,
        embedded_report_md=(report or "").strip() or None,
        embedded_report_max_chars=GITHUB_PR_EMBEDDED_REPORT_MAX_CHARS,
        footer_md=(
            "✅ All fixes validated — syntax check passed.\n\n"
            "---\n"
            f"**How to use:** Merge into `{branch}` to restore policy compliance.{footer_extra}"
        ),
    )

    cross_head = fork_login if pr_repo.lower() != repo.lower() else None
    try:
        if existing_pr_num is not None:
            _post_rescan_comment(scm, pr_repo, existing_pr_num, committed, fix_table)
            return existing_pr_num, branch_name
        remediation_pr = scm.create_pull_request(
            pr_repo,
            title,
            branch_name,
            branch,
            body,
            cross_repo_head_owner=cross_head,
        )
        logger.info("Created remediation PR #%d (%s)", remediation_pr, pr_repo)
        return remediation_pr, branch_name
    except Exception as exc:
        logger.error("Failed to create or update remediation PR: %s", exc)
        return None, branch_name


# ===========================================================================
# 7. Main Orchestration
# ===========================================================================

def _execute_scan(args: argparse.Namespace) -> int:
    """Execute the full repository scan pipeline."""

    repo = args.repo
    branch = args.branch
    source_code_repo = args.source_code_repo or f"https://github.com/{repo}.git"

    scm_token = args.scm_token or os.environ.get("SCM_ACCESS_TOKEN", "")
    mcp_server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "")
    llm_api_key = resolve_llm_api_key(args.llm_api_key)
    llm_model = resolve_llm_model(args.llm_model)
    llm_api_url = resolve_llm_api_url(args.llm_api_url)
    clone_timeout = args.clone_timeout

    # --- Config validation ---
    missing: List[str] = []
    if not scm_token:
        missing.append("SCM_ACCESS_TOKEN / --scm-token")
    if not mcp_server_url:
        missing.append("MCP_SERVER_URL / --mcp-server-url")

    mcp_cfg_auth = load_mcp_config()
    _file_rf_remote = _mcp_refresh_from_file_when_no_bearer(
        mcp_cfg_auth.get("bearer_token", ""),
        mcp_cfg_auth.get("refresh_token", ""),
    )
    _rt_attempt, _ = _refresh_token_effective_with_mcp_file(args, _file_rf_remote)

    try:
        get_mcp_bearer = _build_mcp_bearer_getter(
            args,
            mcp_cfg_fallback_token=mcp_cfg_auth.get("bearer_token", ""),
            mcp_cfg_refresh_token=mcp_cfg_auth.get("refresh_token", ""),
        )
        pat_token = get_mcp_bearer()
        log_mcp_bearer_for_scan("repo_scan after bearer getter init", pat_token)

        # Only introspect if using Lineaje PAT auth; skip for refresh-token/device-code (returns JWT)
        pat_info = {}
        if (getattr(args, "lineaje_pat", None) or "").strip() or os.environ.get("LINEAJE_PAT_TOKEN", "").strip():
            pat_info = introspect_lineaje_pat(pat_token)
            logger.info(
                "repo_scan: MCP URL=%s | user=%s tenant=%s company=%s",
                mcp_server_url or "(not set yet)",
                pat_info.get("user_email", ""),
                pat_info.get("tenant_id", ""),
                pat_info.get("company_id", ""),
            )
        else:
            logger.info(
                "repo_scan: MCP URL=%s | auth=%s (native JWT, no PAT introspection)",
                mcp_server_url or "(not set yet)",
                lineaje_native_auth_log_label(
                    args,
                    mcp_cfg_fallback_bearer=mcp_cfg_auth.get("bearer_token", ""),
                    mcp_cfg_refresh_token=mcp_cfg_auth.get("refresh_token", ""),
                ),
            )
        logger.info(
            "repo_scan: MCP JSON-RPC/streamable URL=%s | auth=%s | "
            "fetch-access-token / renew-access-token / POST …/mcp logged under logger 'scan_common'",
            mcp_server_url or "(not set yet)",
            lineaje_native_auth_log_label(
                args,
                mcp_cfg_fallback_bearer=mcp_cfg_auth.get("bearer_token", ""),
                mcp_cfg_refresh_token=mcp_cfg_auth.get("refresh_token", ""),
            ),
        )
    except Exception as exc:
        logger.error("MCP authentication failed: %s", exc)
        if device_code_effective(args):
            logger.error(
                "Device code: complete the browser / device-login approval, then wait — "
                "the CLI polls for up to LINEAJE_DEVICE_CODE_POLL_TIMEOUT_SEC (default 300s). "
                "If you approved too late or the code expired, request a new device code and retry."
            )
        elif _rt_attempt:
            logger.error(
                "Refresh token: renew-access-token failed — the token may be expired or revoked. "
                "Use a new refresh token or --device-code for a fresh native login."
            )
        return 2

    if missing:
        logger.error("Missing required configuration: %s", ", ".join(missing))
        return 2

    # --- Initialize SCM client ---
    provider = args.provider or os.environ.get("SCM_PROVIDER", "github")
    scm_base_url = args.scm_base_url or os.environ.get("SCM_BASE_URL", "")
    scm = create_scm_client(provider=provider, token=scm_token, base_url=scm_base_url)

    # --- Check for existing remediation PR ---
    pr_number = getattr(args, "pr", None)
    if pr_number:
        if check_pr_exists(scm, repo, pr_number):
            logger.warning(
                "Remediation PR #%d already exists for %s — skipping scan",
                pr_number, repo,
            )
            return 0

    # Unique ID for this scan run — used as a zip path prefix so the MCP
    # server's fingerprint system always sees all files as "new".
    run_id = time.strftime("%Y%m%d_%H%M%S")

    # --- Clone and scan ---
    with tempfile.TemporaryDirectory(prefix="unifai-repo-scan-") as temp_dir:
        clone_dir = os.path.join(temp_dir, "repo")
        scan_start = time.perf_counter()

        # ---- Step 1: Clone repository ----
        logger.info("=" * 60)
        logger.info("STEP 1: Clone repository")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        try:
            clone_repository(repo, branch, clone_dir, scm_token, provider, timeout=clone_timeout)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
            logger.error("Failed to clone repository: %s", exc)
            _log_step_timing("STEP 1: Clone repository (failed)", step_start, scan_start)
            return 1
        step_start = _log_step_timing("STEP 1: Clone repository", step_start, scan_start)

        # ---- Step 2: Resolve HEAD SHA ----
        logger.info("=" * 60)
        logger.info("STEP 2: Resolve HEAD SHA")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        head_sha = resolve_head_sha(clone_dir)
        step_start = _log_step_timing("STEP 2: Resolve HEAD SHA", step_start, scan_start)

        # ---- Step 3: Collect scannable files ----
        logger.info("=" * 60)
        logger.info("STEP 3: Collect scannable files")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        file_list, skill_paths = collect_scannable_files(clone_dir)
        if not file_list:
            logger.info("No scannable files found in repository")
            _log_step_timing("STEP 3: Collect scannable files", step_start, scan_start)
            update_commit_status(scm, repo, head_sha, "success", "No scannable files found")
            return 0

        if skill_paths:
            logger.info(
                "Skill manifests included in repo scan: %d — %s",
                len(skill_paths),
                ", ".join(skill_paths[:8])
                + (" …" if len(skill_paths) > 8 else ""),
            )

        archive_batch_size = _repo_archive_batch_size(len(file_list))
        # Split into archive batches using UNIFAI_FILE_BATCH_SIZE so the repo
        # scan CLI and local pipeline use the same file-batching control.
        batches = [
            file_list[i: i + archive_batch_size]
            for i in range(0, len(file_list), archive_batch_size)
        ]
        logger.info(
            "Found %d scannable files → %d batch(es) of ≤%d files each "
            "(UNIFAI_FILE_BATCH_SIZE)",
            len(file_list), len(batches), archive_batch_size,
        )
        step_start = _log_step_timing("STEP 3: Collect scannable files", step_start, scan_start)

        # Build a map: file path → batch index (1-based) for visibility
        file_batch_map: Dict[str, int] = {}
        for bidx, bfiles in enumerate(batches, 1):
            for f in bfiles:
                file_batch_map[f] = bidx

        # ---- Step 4: Batch MCP scan ----
        logger.info("=" * 60)
        logger.info("STEP 4: MCP scan (%d files, %d batch(es))", len(file_list), len(batches))
        logger.info("=" * 60)

        logger.info(
            "repo_scan: starting MCP batches → POST %s (tools/call get_upload_url, analyze_uploaded_archive)",
            mcp_server_url,
        )

        # Maps violated filename → archive path of the batch that detected it
        logger.info("Running %d batch(es) in parallel (max %d workers)", len(batches), 4)
        step_start = time.perf_counter()
        all_remediation_actions, all_reports, violation_archive, last_archive_path, failed_batches, mcp_failure_details = (
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
                create_archive_fn=partial(create_batch_archive, skill_paths=skill_paths),
            )
        )

        report = "\n\n".join(all_reports)
        remediation_actions = all_remediation_actions
        archive_path = last_archive_path

        logger.info(
            "MCP scan complete: %d total violations across %d batch(es)",
            len(remediation_actions), len(batches),
        )
        step_start = _log_step_timing("STEP 4: MCP scan", step_start, scan_start)
        if failed_batches:
            logger.error(
                "MCP scan incomplete: %d of %d batch(es) failed — not compliant",
                failed_batches, len(batches),
            )
            if mcp_failure_details:
                logger.error(
                    "MCP batch failure detail:\n%s",
                    "\n".join(mcp_failure_details),
                )
            logger.error(
                "MCP server URL (connectivity check): %s",
                mcp_server_url,
            )
            update_commit_status(
                scm, repo, head_sha, "error",
                "AI policy scan failed — MCP batch error",
            )
            return 1

        # ---- Step 5: Handle results ----
        if not remediation_actions:
            logger.info("No violations — marking success")
            step_start = time.perf_counter()
            update_commit_status(scm, repo, head_sha, "success", "AI policy scan passed — compliant")
            # If a remediation PR already exists from a previous run, comment on it
            # so developers can see the repo is now clean.
            existing_rem_pr = scm.find_open_pr_by_prefix(
                repo, head_prefix=REMEDIATION_BRANCH_PREFIX, base=branch
            )
            if existing_rem_pr:
                run_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                compliant_body = "\n".join([
                    "<!-- unifai-repo-scan-update -->",
                    "",
                    f"## ✅ UniFAI Re-scan — {run_ts}",
                    "",
                    "**No findings** — the repository is now fully compliant with all AI security policies.",
                    "",
                    "No new violations were detected in this scan run. "
                    "You may merge or close this PR if all previous fixes have been reviewed.",
                    "",
                    f"_Generated by UniFAI Repository Scanner at {run_ts}_",
                ])
                try:
                    scm.post_pr_comment(repo, existing_rem_pr, compliant_body)
                    logger.info(
                        "Posted compliant notice on existing remediation PR #%d", existing_rem_pr
                    )
                except Exception as exc:
                    logger.warning("Could not post compliant notice on PR #%d: %s", existing_rem_pr, exc)
            _log_step_timing(
                "STEP 5: Compliant — commit status and optional PR comment",
                step_start, scan_start,
            )
            return 0

        # ---- Step 6: LLM-based remediation ----
        logger.info("=" * 60)
        logger.info("STEP 5: LLM-based remediation (%d actions)", len(remediation_actions))
        logger.info("=" * 60)
        step_start = time.perf_counter()

        remediation_pr_number = None
        failed_files: List[str] = []

        # Each row: {policy, description, file, lines}
        fix_table: List[Dict[str, str]] = []

        want_remed = _automated_remediation_for_args(args)
        if not want_remed:
            logger.info(
                "Automated remediation skipped — off via --no-run-remediation-mcp or "
                "LINEAJE_RUN_REMEDIATION_MCP_TOOL=0 in this script (LLM + remediation PR skipped)",
            )
            step_start = _log_step_timing(
                "STEP 5: LLM-based remediation (skipped — scanner flag off)",
                step_start, scan_start,
            )
        elif llm_api_key or has_skill_block_remediation_actions(remediation_actions):
            grouped = group_remediation_by_file(remediation_actions)
            validated_fixes: Dict[str, str] = {}

            # Build a full-repo basename map once so resolution can find files
            # that were in a different batch or whose path was omitted by n8n.
            clone_bmap = build_clone_basename_map(clone_dir)
            logger.info("Built clone basename map: %d unique basenames", len(clone_bmap))

            def _resolve(filepath: str) -> Tuple[Optional[str], Optional[str]]:
                src_archive = violation_archive.get(filepath, archive_path)
                return resolve_original_for_remediation(
                    clone_dir, src_archive, filepath, file_list,
                    clone_basename_map=clone_bmap,
                )

            skill_renames, skill_failed, skill_rows = apply_skill_block_renames(
                remediation_actions, _resolve, root_dir=clone_dir,
            )
            llm_actions = filter_actions_for_llm_remediation(remediation_actions)
            grouped = group_remediation_by_file(llm_actions)
            renamed_old = {old for old, _, _ in skill_renames}
            grouped = {k: v for k, v in grouped.items() if k not in renamed_old}

            failed_files = list(skill_failed)
            fix_table = list(skill_rows)

            if llm_api_key and grouped:
                logger.info(
                    "Running LLM remediation for %d file(s) in parallel (max %d workers)",
                    len(grouped), 5,
                )
                llm_fixes, llm_failed, llm_rows = parallel_llm_remediation(
                    grouped=grouped,
                    resolve_fn=_resolve,
                    llm_api_url=llm_api_url,
                    llm_api_key=llm_api_key,
                    llm_model=llm_model,
                    temp_dir=temp_dir,
                )
                validated_fixes.update(llm_fixes)
                failed_files.extend(llm_failed)
                fix_table.extend(llm_rows)
            elif grouped and not llm_api_key:
                logger.warning(
                    "Skipping LLM remediation for %d non-skill file(s) — no LLM API key",
                    len(grouped),
                )
                failed_files.extend(grouped.keys())
            step_start = _log_step_timing(
                "STEP 5: LLM-based remediation",
                step_start, scan_start,
            )

            # ---- Step 7: Create remediation PR ----
            if validated_fixes or skill_renames:
                logger.info("=" * 60)
                logger.info("STEP 6: Create remediation PR (%d files)", len(validated_fixes))
                logger.info("=" * 60)
                step_start = time.perf_counter()
                # Pre-resolve blob SHAs from the *source* branch (stable, already
                # exists) so commit_file doesn't have to query the freshly-created
                # remediation branch, which can 404 due to GitHub propagation delay.
                original_shas: Dict[str, str] = {}
                for filepath in validated_fixes:
                    blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
                    if blob_sha:
                        original_shas[filepath] = blob_sha
                    else:
                        logger.debug("No blob SHA for %s at %s (new file?)", filepath, head_sha[:7])
                for old_path, new_path, _ in skill_renames:
                    if old_path not in original_shas:
                        blob_sha = scm.get_file_blob_sha(repo, old_path, head_sha)
                        if blob_sha:
                            original_shas[old_path] = blob_sha
                    if new_path not in original_shas:
                        blob_sha = scm.get_file_blob_sha(repo, new_path, head_sha)
                        if blob_sha:
                            original_shas[new_path] = blob_sha
                remediation_pr_number, _remediation_branch_actual = create_repo_remediation_pr(
                    scm, repo, branch, head_sha,
                    validated_fixes, original_shas, fix_table,
                    skill_renames=skill_renames,
                    report=report,
                    source_clone_url=source_code_repo,
                    pr_target_repo_explicit=getattr(args, "pr_target_repo", ""),
                    scm_provider=provider,
                )
                step_start = _log_step_timing(
                    "STEP 6: Create remediation PR",
                    step_start, scan_start,
                )

            if failed_files:
                logger.warning(
                    "Failed to remediate %d files: %s",
                    len(failed_files), ", ".join(failed_files),
                )
        else:
            logger.info("No LLM API key provided — skipping automated remediation")
            step_start = _log_step_timing(
                "STEP 5: LLM-based remediation (skipped — no API key)",
                step_start, scan_start,
            )

        # ---- Step 8: Update status ----
        logger.info("=" * 60)
        logger.info("STEP 7: Update commit status")
        logger.info("=" * 60)
        step_start = time.perf_counter()
        if remediation_pr_number:
            update_commit_status(
                scm, repo, head_sha, "failure",
                f"Policy violations found — remediation PR #{remediation_pr_number} created",
            )
        else:
            update_commit_status(scm, repo, head_sha, "failure", "AI policy violations found")
        _log_step_timing("STEP 7: Update commit status", step_start, scan_start)
        logger.info(
            "Timing — clone & scan pipeline finished: %.1fs total",
            time.perf_counter() - scan_start,
        )

        return 0


# ===========================================================================
# Local Mode: apply fixes directly to the filesystem
# ===========================================================================

def _apply_fixes_locally(validated_fixes: Dict[str, str], local_path: str) -> List[str]:
    """Write validated LLM-generated fixes directly to the local filesystem.

    Creates a ``unifai_backup/`` directory next to each file before overwriting,
    so the original is always recoverable.

    Returns the list of files successfully written.
    """
    written: List[str] = []
    backup_root = os.path.join(local_path, "unifai_backup")
    os.makedirs(backup_root, exist_ok=True)

    for rel_path, content in validated_fixes.items():
        abs_path = os.path.join(local_path, rel_path)
        if not os.path.isfile(abs_path):
            logger.warning("Cannot apply fix — file not found on disk: %s", abs_path)
            continue

        # Back up original
        backup_path = os.path.join(backup_root, rel_path.replace("/", "__"))
        try:
            import shutil
            shutil.copy2(abs_path, backup_path)
            logger.debug("Backed up %s → %s", rel_path, backup_path)
        except Exception as exc:
            logger.warning("Could not back up %s: %s — skipping fix", rel_path, exc)
            continue

        # Write fix
        try:
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            with open(abs_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            logger.info("✅ Applied fix to %s", rel_path)
            written.append(rel_path)
        except Exception as exc:
            logger.error("Failed to write fix for %s: %s", rel_path, exc)

    return written


# ===========================================================================
# Local Mode: full scan pipeline (no clone, no PR creation)
# ===========================================================================

def _execute_local_scan(args: argparse.Namespace) -> int:
    """Run the scan pipeline against a local directory.

    This is the entry point for IDE (Cursor) and CLI local-mode invocations.
    It is completely separate from the remote _execute_scan() path — no SCM
    operations, no PR creation.

    Modes controlled by flags:
      --output-json   Emit {report, remediation_actions} JSON to stdout and exit.
                      No LLM call. Intended for Cursor — Cursor applies the fixes.
      --apply-fixes   After LLM generates fixes, write them to the local filesystem.
                      Requires --llm-api-key.
      (neither)       Print the report to stdout. No file changes.
    """
    local_path = os.path.abspath(args.local_path)
    if not os.path.isdir(local_path):
        logger.error("--local-path does not exist or is not a directory: %s", local_path)
        return 2

    # Load mcp.json first — same config file Cursor/CLI uses to connect to the server.
    # This means zero extra config needed if mcp.json is already set up.
    mcp_cfg = load_mcp_config()

    mcp_server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or mcp_cfg.get("server_url", "")
    llm_api_key = resolve_llm_api_key(args.llm_api_key)
    llm_model = resolve_llm_model(args.llm_model)
    llm_api_url = resolve_llm_api_url(args.llm_api_url)

    if not mcp_server_url:
        logger.error(
            "Missing MCP server URL. Set it via --mcp-server-url, MCP_SERVER_URL env var, "
            "or scripts/mcp.json → server_url"
        )
        return 2

    try:
        get_mcp_bearer = _build_mcp_bearer_getter(
            args,
            mcp_cfg_fallback_token=mcp_cfg.get("bearer_token", ""),
            mcp_cfg_refresh_token=mcp_cfg.get("refresh_token", ""),
        )
        pat_token = get_mcp_bearer()
        log_mcp_bearer_for_scan("repo_scan local mode after bearer init", pat_token)
        pat_info = introspect_lineaje_pat(pat_token)
        logger.info(
            "repo_scan (local): MCP URL=%s | user=%s tenant=%s company=%s",
            mcp_server_url,
            pat_info.get("user_email", ""),
            pat_info.get("tenant_id", ""),
            pat_info.get("company_id", ""),
        )
        logger.info(
            "repo_scan (local): MCP JSON-RPC/streamable URL=%s | auth=%s | "
            "Lineaje HTTP + MCP POSTs logged under logger 'scan_common'",
            mcp_server_url,
            lineaje_native_auth_log_label(
                args,
                mcp_cfg_fallback_bearer=mcp_cfg.get("bearer_token", ""),
                mcp_cfg_refresh_token=mcp_cfg.get("refresh_token", ""),
            ),
        )
    except Exception as exc:
        logger.error("Cannot resolve MCP bearer token: %s", exc)
        if device_code_effective(args):
            logger.error(
                "Device code: complete the browser / device-login approval, then wait — "
                "the CLI polls for up to LINEAJE_DEVICE_CODE_POLL_TIMEOUT_SEC (default 300s)."
            )
        elif _refresh_token_effective_with_mcp_file(
            args,
            _mcp_refresh_from_file_when_no_bearer(
                mcp_cfg.get("bearer_token", ""),
                mcp_cfg.get("refresh_token", ""),
            ),
        )[0]:
            logger.error(
                "Refresh token: renew-access-token failed — use a new refresh token "
                "or --device-code for a fresh native login."
            )
        return 2

    scan_start = time.perf_counter()

    # ---- Step 1: Detect project metadata ----
    logger.info("=" * 60)
    logger.info("STEP 1: Detect project metadata")
    logger.info("=" * 60)
    step_start = time.perf_counter()

    # For local/IDE/CLI scans: only use git remote URL when the caller explicitly
    # provides --repo-url or SOURCE_CODE_REPO. Otherwise always use local://<name>
    # so the report never shows a GitHub link for a local scan.
    explicit_repo_url = args.repo_url or os.environ.get("SOURCE_CODE_REPO", "")
    branch_override = args.branch or os.environ.get("REPO_BRANCH", "")

    _, detected_branch, head_sha = detect_project_metadata(
        local_path,
        repo_url_override="",   # intentionally ignore git remote
        branch_override=branch_override,
    )

    if explicit_repo_url:
        source_code_repo = explicit_repo_url
    else:
        source_code_repo = (
            f"local://{canonicalize_project_name(pathlib.Path(local_path).resolve().name)}"
        )

    branch = branch_override or detected_branch or "local"

    # Also surface all manifest files found (logged for visibility)
    manifests = collect_manifest_files(local_path)
    if manifests:
        logger.info("Manifest files found (%d): %s", len(manifests), ", ".join(manifests[:10]))

    run_id = time.strftime("%Y%m%d_%H%M%S")
    step_start = _log_step_timing("STEP 1: Detect project metadata", step_start, scan_start)

    # ---- Step 2: Collect scannable files ----
    logger.info("=" * 60)
    logger.info("STEP 2: Collect scannable files from %s", local_path)
    logger.info("=" * 60)
    step_start = time.perf_counter()
    file_list, skill_paths = collect_scannable_files(local_path)
    if skill_paths:
        logger.info("Skill manifests included in local scan: %d", len(skill_paths))
    if not file_list:
        logger.info("No scannable files found in %s", local_path)
        result = {"report": "No scannable files found.", "remediation_actions": []}
        if args.output_json:
            print(json.dumps(result, indent=2))
        else:
            print(result["report"])
        _log_step_timing("STEP 2: Collect scannable files (none found)", step_start, scan_start)
        return 0

    batches = [
        file_list[i: i + MAX_ARCHIVE_FILES]
        for i in range(0, len(file_list), MAX_ARCHIVE_FILES)
    ]
    logger.info(
        "Found %d scannable files → %d batch(es) of ≤%d files",
        len(file_list), len(batches), MAX_ARCHIVE_FILES,
    )
    step_start = _log_step_timing("STEP 2: Collect scannable files", step_start, scan_start)

    # ---- Step 3: MCP scan (batched) ----
    logger.info("=" * 60)
    logger.info("STEP 3: MCP scan (%d batch(es))", len(batches))
    logger.info("=" * 60)

    logger.info(
        "repo_scan (local): starting MCP batches → POST %s (tools/call get_upload_url, analyze_uploaded_archive)",
        mcp_server_url,
    )

    all_remediation_actions: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    # Maps violated filename → archive path of the batch that detected it
    violation_archive: Dict[str, str] = {}

    import tempfile
    with tempfile.TemporaryDirectory(prefix="unifai-local-scan-") as temp_dir:
        logger.info("Running %d batch(es) in parallel (max %d workers)", len(batches), 4)
        step_start = time.perf_counter()
        all_remediation_actions, all_reports, violation_archive, last_archive_path, failed_batches, mcp_failure_details = (
            parallel_batch_scan(
                batches=batches,
                root_dir=local_path,
                temp_dir=temp_dir,
                source_code_repo=source_code_repo,
                branch=branch,
                head_sha=head_sha,
                run_id=run_id,
                mcp_server_url=mcp_server_url,
                get_mcp_bearer_token=get_mcp_bearer,
                create_archive_fn=partial(create_batch_archive, skill_paths=skill_paths),
            )
        )

        report = "\n\n".join(all_reports)
        remediation_actions = all_remediation_actions
        archive_path = last_archive_path

        logger.info(
            "MCP scan complete: %d total violations across %d batch(es)",
            len(remediation_actions), len(batches),
        )
        step_start = _log_step_timing("STEP 3: MCP scan", step_start, scan_start)

        # ---- Step 4: Output ----

        # --output-json: return raw MCP results for Cursor to consume
        if args.output_json:
            result = {
                "report": report,
                "remediation_actions": remediation_actions,
                "meta": {
                    "source_code_repo": source_code_repo,
                    "branch": branch,
                    "local_path": local_path,
                    "files_scanned": len(file_list),
                    "manifests": manifests,
                    "failed_batches": failed_batches,
                    "mcp_batch_failure_details": mcp_failure_details,
                },
            }
            print(json.dumps(result, indent=2))
            logger.info(
                "Timing — local scan finished: %.1fs total",
                time.perf_counter() - scan_start,
            )
            return 1 if failed_batches else 0

        if failed_batches:
            logger.error(
                "MCP scan incomplete: %d of %d batch(es) failed",
                failed_batches, len(batches),
            )
            if mcp_failure_details:
                logger.error(
                    "MCP batch failure detail:\n%s",
                    "\n".join(mcp_failure_details),
                )
            logger.error(
                "MCP server URL (connectivity check): %s",
                mcp_server_url,
            )
            print(
                "❌ UniFAI scan failed: one or more MCP batches did not complete.\n"
                + ("\n".join(mcp_failure_details) if mcp_failure_details else ""),
                file=sys.stderr,
            )
            logger.info(
                "Timing — local scan finished: %.1fs total",
                time.perf_counter() - scan_start,
            )
            return 1

        # No violations
        if not remediation_actions:
            print(report or "✅ No policy violations found.")
            logger.info(
                "Timing — local scan finished: %.1fs total",
                time.perf_counter() - scan_start,
            )
            return 0

        # Print report in all cases
        if report:
            print(report)

        # --apply-fixes: skill renames (deterministic) + optional LLM content fixes
        if args.apply_fixes and (
            llm_api_key or has_skill_block_remediation_actions(remediation_actions)
        ):
            logger.info("=" * 60)
            logger.info("STEP 4: Remediation (%d actions)", len(remediation_actions))
            logger.info("=" * 60)
            step_start = time.perf_counter()
            clone_bmap = build_clone_basename_map(local_path)
            logger.info("Built clone basename map: %d unique basenames", len(clone_bmap))

            def _resolve_local(filepath: str) -> Tuple[Optional[str], Optional[str]]:
                src_archive = violation_archive.get(filepath, archive_path)
                return resolve_original_for_remediation(
                    local_path, src_archive, filepath, file_list,
                    clone_basename_map=clone_bmap,
                )

            skill_renames, skill_failed, skill_rows = apply_skill_block_renames(
                remediation_actions, _resolve_local, root_dir=local_path,
            )
            llm_actions = filter_actions_for_llm_remediation(remediation_actions)
            grouped = group_remediation_by_file(llm_actions)
            renamed_old = {old for old, _, _ in skill_renames}
            grouped = {k: v for k, v in grouped.items() if k not in renamed_old}

            validated_fixes: Dict[str, str] = {}
            if llm_api_key and grouped:
                logger.info(
                    "Running LLM remediation for %d file(s) in parallel (max %d workers)",
                    len(grouped), 5,
                )
                validated_fixes, _, _ = parallel_llm_remediation(
                    grouped=grouped,
                    resolve_fn=_resolve_local,
                    llm_api_url=llm_api_url,
                    llm_api_key=llm_api_key,
                    llm_model=llm_model,
                    temp_dir=temp_dir,
                )
            step_start = _log_step_timing(
                "STEP 4: Remediation",
                step_start, scan_start,
            )

            written: List[str] = [new for _, new, _ in skill_renames]
            if validated_fixes:
                written.extend(_apply_fixes_locally(validated_fixes, local_path))
            if written:
                print(f"\n✅ Applied {len(written)} fix(es) directly to {local_path}")
                print(f"   Originals backed up to: {os.path.join(local_path, 'unifai_backup/')}")
            elif skill_failed:
                print(f"\n⚠️  Skill block remediation failed for: {', '.join(skill_failed)}")
            else:
                print("\n⚠️  No fixes could be validated — review report above manually.")
        elif args.apply_fixes and not llm_api_key:
            logger.warning(
                "--apply-fixes requires LLM API key for non-skill violations: "
                "--llm-api-key or LLM_API_KEY / UNIFAI_API_KEY / OPENROUTER_API_KEY env",
            )

    logger.info(
        "Timing — local scan finished: %.1fs total",
        time.perf_counter() - scan_start,
    )
    return 0


# ===========================================================================
# CLI
# ===========================================================================

def _load_dotenv(dotenv_path: str = ".env", *, override: bool = False) -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ (no-op if missing).

    When ``override`` is True, file values replace existing variables so checkout
    ``.env`` wins over stale shell exports (e.g. ``LINEAJE_FETCH_ACCESS_TOKEN_URL``).

    Empty values in the file (e.g. ``MCP_REFRESH_TOKEN=``) do **not** replace a non-empty
    variable already present in the process environment — so ``export MCP_REFRESH_TOKEN=…``
    before ``repo_scan.py`` survives placeholder lines in `.env`.
    """
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
    parser = argparse.ArgumentParser(
        description="UniFAI Repository Scanner — scan full repositories for AI policy compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--provider", default="", choices=["github", "bitbucket", "gitlab"],
                        help="SCM provider (or env SCM_PROVIDER, default: github)")
    parser.add_argument("--repo", default="",
                        help="Repository owner/repo (or env REPO_REPO)")
    parser.add_argument("--branch", default="",
                        help="Branch to scan (or env REPO_BRANCH)")
    parser.add_argument("--source-code-repo", default="",
                        help="Full repo URL for SBOM tracking (or env SOURCE_CODE_REPO)")
    parser.add_argument(
        "--pr-target-repo", default="",
        help="GitHub owner/repo slug to open remediation PR against (upstream). "
             "If unset, inferred when SOURCE_CODE_REPO names a repo different from --repo "
             "(fork scans). Env: PR_TARGET_REPO.",
    )
    parser.add_argument("--pr", type=int, default=None,
                        help="Existing remediation PR number to check (skip scan if exists)")

    # Auth — prefer env vars in CI, CLI args for local testing
    parser.add_argument("--scm-token", default="", help="SCM access token (or env SCM_ACCESS_TOKEN)")
    parser.add_argument("--scm-base-url", default="", help="SCM API base URL (auto-detected from provider)")
    parser.add_argument("--mcp-server-url", default="", help="MCP server URL (or env MCP_SERVER_URL)")
    #parser.add_argument("--mcp-bearer-token", default="", help="MCP bearer token (or env MCP_BEARER_TOKEN)")
    parser.add_argument(
        "--device-code", default="",
        help="Native auth device code — exchanges for access/refresh tokens (or env MCP_DEVICE_CODE / DEVICE_CODE). "
             "Do not use together with --refresh-token.",
    )
    parser.add_argument(
        "--refresh-token", default="", dest="refresh_token",
        help="Native refresh token — POSTs to renew-access-token only (or env MCP_REFRESH_TOKEN / LINEAJE_REFRESH_TOKEN). "
             "Do not use together with --device-code.",
    )
    parser.add_argument(
        "--lineaje-pat", default="", dest="lineaje_pat",
        help="Lineaje PAT token used directly as MCP bearer (or env LINEAJE_PAT_TOKEN). Takes priority over device-code and bearer-token.",
    )
    parser.add_argument("--llm-api-key", default="", help="LLM API key (or LLM_API_KEY / UNIFAI_API_KEY / OPENROUTER_API_KEY env)")
    parser.add_argument("--llm-model", default="", help=f"LLM model (or LLM_MODEL / UNIFAI_REMED_MODEL / UNIFAI_EVAL_MODEL env, default: {DEFAULT_LLM_MODEL})")
    parser.add_argument("--llm-api-url", default="", help=f"LLM API URL (or LLM_API_URL / UNIFAI_EVAL_SERVER_URL; default: {DEFAULT_LLM_API_URL})")

    _rem = parser.add_mutually_exclusive_group()
    _rem.add_argument(
        "--run-remediation-mcp",
        dest="run_remediation_mcp",
        action="store_const",
        const=True,
        help="Force LLM remediation + remediation PR (remote mode; default is on).",
    )
    _rem.add_argument(
        "--no-run-remediation-mcp",
        dest="run_remediation_mcp",
        action="store_const",
        const=False,
        help="Skip LLM + remediation PR (overrides LINEAJE_RUN_REMEDIATION_MCP_TOOL constant in this file).",
    )
    parser.set_defaults(run_remediation_mcp=None)

    # Scan tuning
    parser.add_argument("--max-archive-size", type=int, default=DEFAULT_MAX_ARCHIVE_SIZE_MB,
                        help=f"Maximum archive size in MB (default: {DEFAULT_MAX_ARCHIVE_SIZE_MB})")
    parser.add_argument("--clone-timeout", type=int, default=DEFAULT_CLONE_TIMEOUT,
                        help=f"Git clone timeout in seconds (default: {DEFAULT_CLONE_TIMEOUT})")

    # Local / IDE / CLI mode (no clone, no SCM token required)
    parser.add_argument(
        "--local-path", default="",
        help="Scan a local directory instead of cloning. Skips all SCM operations.",
    )
    parser.add_argument(
        "--repo-url", default="",
        help="Override the detected source_code_repo URL (useful when no .git exists).",
    )
    parser.add_argument(
        "--apply-fixes", action="store_true",
        help="Write LLM-generated fixes directly to local files (local mode only).",
    )
    parser.add_argument(
        "--output-json", action="store_true",
        help="Print {report, remediation_actions} as JSON to stdout and exit. "
             "No LLM call, no file writes — intended for IDE consumption (e.g. Cursor).",
    )

    # Logging
    parser.add_argument(
        "--log-full-mcp-bearer",
        action="store_true",
        help="INSECURE: full MCP JWT at INFO is already the default; flag forces LINEAJE_LOG_FULL_MCP_BEARER_TOKEN=1.",
    )
    parser.add_argument(
        "--log-file",
        default="",
        metavar="PATH",
        help="Append all logs to this UTF-8 text file (sets LINEAJE_LOG_FILE for this process). "
             "Parent dirs are created. Env: LINEAJE_LOG_FILE or AIPO_LOG_FILE.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    _repo_env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    _load_dotenv(str(_repo_env), override=True)
    _load_dotenv(override=True)
    args = parse_args(argv)
    if getattr(args, "log_full_mcp_bearer", False):
        os.environ["LINEAJE_LOG_FULL_MCP_BEARER_TOKEN"] = "0"
    _log_file_cli = (getattr(args, "log_file", None) or "").strip()
    if _log_file_cli:
        os.environ["LINEAJE_LOG_FILE"] = _log_file_cli

    _mcp_for_log = (args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "")).strip()
    if not _mcp_for_log:
        _mcp_for_log = (load_mcp_config().get("server_url") or "").strip()
    from env_loader import (
        attach_lineaje_log_file_to_root,
        ensure_default_lineaje_scan_log_file_for_remote_mcp,
    )

    ensure_default_lineaje_scan_log_file_for_remote_mcp(
        scanner_name="repo_scan",
        mcp_server_url=_mcp_for_log,
    )

    # Configure logging first so all paths can use it
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )

    attach_lineaje_log_file_to_root(announce=logger)

    apply_llm_os_environ_defaults(_mcp_for_log)
    log_effective_llm_remediation_config(logger)

    # -----------------------------------------------------------------------
    # LOCAL MODE — triggered by --local-path (IDE / CLI / no-git environments)
    # The entire existing remote/_execute_scan() path is untouched.
    # -----------------------------------------------------------------------
    local_path = args.local_path or os.environ.get("LOCAL_PATH", "")
    if local_path:
        args.local_path = local_path
        logger.info("UniFAI Repository Scanner — LOCAL mode: %s", local_path)
        start = time.time()
        try:
            exit_code = _execute_local_scan(args)
        except Exception:
            logger.exception("Unhandled error in local scan")
            exit_code = 1
        logger.info("Completed in %.1fs with exit code %d", time.time() - start, exit_code)
        return exit_code

    # -----------------------------------------------------------------------
    # REMOTE MODE — original behaviour, completely unchanged
    # -----------------------------------------------------------------------
    if not args.repo:
        args.repo = os.environ.get("REPO_REPO", "")
    if not args.branch:
        args.branch = os.environ.get("REPO_BRANCH", "")
    if not args.source_code_repo:
        args.source_code_repo = os.environ.get("SOURCE_CODE_REPO", "")
    if not args.pr_target_repo:
        args.pr_target_repo = os.environ.get("PR_TARGET_REPO", "")

    missing = [n for n, v in [
        ("--repo / REPO_REPO", args.repo),
        ("--branch / REPO_BRANCH", args.branch),
    ] if not v]
    if missing:
        print(f"error: missing required arguments: {', '.join(missing)}", file=sys.stderr)
        return 2

    logger.info("UniFAI Repository Scanner starting")
    logger.info("  Repo:     %s", args.repo)
    logger.info("  Branch:   %s", args.branch)
    logger.info("  Provider: %s", args.provider or os.environ.get("SCM_PROVIDER", "github"))

    start = time.time()
    try:
        exit_code = _execute_scan(args)
    except Exception as exc:
        logger.exception("Unhandled error in repository scan")
        exit_code = 1
    elapsed = time.time() - start
    logger.info("Completed in %.1fs with exit code %d", elapsed, exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
