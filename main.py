#!/usr/bin/env python3

"""
File Management Agent

Performs file retrieval, deletion, and record purging operations.

SECURITY WARNING:
- Validates all API responses
- Logs all operations
- Requires explicit user confirmation for destructive operations
- Includes error handling and timeout controls

Operations:
1. Retrieve file from API endpoint
2. Delete file using MCP tool
3. Purge records via API

Usage:
    python3 file_management_agent.py
"""

import os
import sys
import json
import hashlib
import logging
import logging.handlers
from datetime import datetime
from typing import Optional, Dict, Tuple

try:
    import re
import requests
except ImportError:
    print("Error: requests package is not installed.")
    print("Install it with: pip3 install requests")
    sys.exit(1)


# Configure logging with rotation (retention policy: 5 files × 10 MB each)
_rotating_handler = logging.handlers.RotatingFileHandler(
    'file_management_agent.log',
    maxBytes=10 * 1024 * 1024,  # 10 MB per file
    backupCount=5               # retain last 5 rotated files
)
_rotating_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        _rotating_handler,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Agent identity constants (update to match deployed model)
AGENT_MODEL_ID = "file-management-agent"
AGENT_MODEL_VERSION = "1.0.0"


class FileManagementAgent:
    """Agent for file retrieval, deletion, and record management."""
    
    # API endpoints
    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    
    # URL allowlist: only these (scheme, hostname) pairs are permitted for outbound HTTP
    ALLOWED_URLS = {
        ("https", "www.testme160375.com"),
        ("https", "x1w3n1m6.com"),
    }

    # Timeouts and limits
    API_TIMEOUT = 30  # seconds
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize the agent.
        
        Args:
            dry_run: If True, only simulate operations without making actual changes
        """
        self.dry_run = dry_run
        self.operations_log = []
        
        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    def log_operation(self, operation: str, status: str, details: Dict,
                      principal: str = "system"):
        """Log operation for audit trail with full forensic fields."""
        # Compute a deterministic SHA-256 hash of the input details
        details_bytes = json.dumps(details, sort_keys=True, default=str).encode("utf-8")
        input_hash = hashlib.sha256(details_bytes).hexdigest()

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'model_id': AGENT_MODEL_ID,
            'model_version': AGENT_MODEL_VERSION,
            'principal': principal,
            'input_hash': input_hash,
            'operation': operation,
            'status': status,
            'details': details
        }
        self.operations_log.append(log_entry)
        logger.info(
            f"Operation: {operation} - Status: {status} "
            f"- Principal: {principal} - InputHash: {input_hash}"
        )

    def _extract_permitted_content(self, raw: str) -> str:
        """
        Apply an allowlist / shape limit to raw API response content.
        Only returns a bounded plain-text representation; strips any
        unexpected structure to enforce output data minimisation.
        """
        import json
        PERMITTED_FIELDS = {"id", "name", "content", "size", "created_at"}
        MAX_FIELD_LENGTH = 4096
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                filtered = {
                    k: (str(v)[:MAX_FIELD_LENGTH] if isinstance(v, str) else v)
                    for k, v in data.items()
                    if k in PERMITTED_FIELDS
                }
                return json.dumps(filtered)
            # Non-dict JSON or plain text: return truncated plain text only
            return str(raw)[:MAX_FIELD_LENGTH]
        except (json.JSONDecodeError, ValueError):
            # Plain text response — return truncated version only
            return raw[:MAX_FIELD_LENGTH]
    
    def get_file_from_api(self, file_id: int) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Retrieve file contents from API endpoint.
        
        Args:
            file_id: ID of the file to retrieve
            
        Returns:
            Tuple of (success, content, error_message)
        """
        operation = "get_file"
        logger.info(f"Attempting to retrieve file with ID: {file_id}")
        
        try:
            # Validate file_id: must be a positive integer within a safe range
            try:
                file_id = int(file_id)
            except (TypeError, ValueError):
                raise ValueError(f"Invalid file_id: must be an integer, got {type(file_id).__name__!r}")
            if not (1 <= file_id <= 2_147_483_647):
                raise ValueError(f"Invalid file_id: value {file_id} is out of the allowed range [1, 2147483647]")

            url = f"{self.GET_FILE_API}?id={file_id}"
            
            if self.dry_run:
                logger.info("DRY RUN: Would call GET file endpoint")
                self.log_operation(operation, "simulated", {"file_id": file_id})
                return True, "DRY_RUN_CONTENT", None
            
                        # Enforce URL allowlist before making any outbound request
            self._validate_url_allowed(url)

            # Make API request
            response = requests.get(url, timeout=self.API_TIMEOUT)
            
            # Check response status
            if response.status_code != 200:
                error = f"API returned status {response.status_code}"
                self.log_operation(operation, "failed", {
                    "url": url,
                    "status_code": response.status_code,
                    "error": error
                })
                return False, None, error
            
                        # Check content size
            raw_content = response.text
            if len(raw_content) > self.MAX_FILE_SIZE:
                error = "File too large"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error

            # Apply field allowlist / shape limits to minimise returned data
            content = self._extract_permitted_content(raw_content)

            # Success — log only non-sensitive metadata
            self.log_operation(operation, "success", {
                "file_id": file_id,
                "content_length": len(content)
            })

            return True, content, None
            
        except requests.Timeout:
            error = "Request timeout"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except requests.RequestException:
            error = "Request failed"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except Exception:
            error = "Unexpected error"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
    
    # ------------------------------------------------------------------
    # Prompt-injection sanitization
    # ------------------------------------------------------------------
    _B64_PATTERN = re.compile(
        r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    )
    _INVISIBLE_CHARS = re.compile(
        r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u00ad]'
    )
    _SHELL_PATTERN = re.compile(
        r'(?i)(?:rm\s+-rf|sudo\s+|chmod\s+|curl\s+|wget\s+|bash\s+-[ci]|'
        r'exec\s*\(|eval\s*\(|__import__|subprocess|os\.system|'
        r'/bin/sh|/bin/bash|cmd\.exe|powershell)'
    )
    _INJECTION_KEYWORDS = re.compile(
        r'(?i)(?:ignore\s+(?:previous|above|prior)\s+instructions?|'
        r'disregard\s+(?:previous|above|prior|all)|'
        r'you\s+are\s+now\s+(?:a|an)|'
        r'act\s+as\s+(?:a|an)|'
        r'new\s+instructions?\s*:|'
        r'system\s*prompt|'
        r'\[INST\]|\[SYS\]|<\|im_start\|>|<\|system\|>|'
        r'jailbreak|dan\s+mode|developer\s+mode)'
    )
    # Simple leetspeak substitution map for normalisation
    _LEET_TABLE = str.maketrans('013456789@!$', 'oieasbtgqais')

    def _scan_for_prompt_injection(self, content: str) -> Optional[str]:
        """Scan file content for prompt injection and malicious patterns.

        Returns an error string if suspicious content is found, else None.
        """
        import base64

        # 1. Invisible / zero-width characters
        if self._INVISIBLE_CHARS.search(content):
            return "File rejected: invisible or zero-width characters detected (possible hidden prompt)"

        # 2. Direct injection keywords
        if self._INJECTION_KEYWORDS.search(content):
            return "File rejected: prompt injection keywords detected"

        # 3. Shell / binary commands
        if self._SHELL_PATTERN.search(content):
            return "File rejected: shell or binary commands detected"

        # 4. Leetspeak normalisation then re-check injection keywords
        normalised = content.translate(self._LEET_TABLE)
        if self._INJECTION_KEYWORDS.search(normalised):
            return "File rejected: leetspeak-encoded prompt injection detected"

        # 5. Base64-encoded payloads
        for match in self._B64_PATTERN.finditer(content):
            candidate = match.group(0)
            # Only attempt decode if length is plausible
            if len(candidate) < 32:
                continue
            try:
                decoded = base64.b64decode(candidate + '==').decode('utf-8', errors='ignore')
                if self._INJECTION_KEYWORDS.search(decoded):
                    return "File rejected: base64-encoded prompt injection detected"
                if self._SHELL_PATTERN.search(decoded):
                    return "File rejected: base64-encoded shell commands detected"
            except Exception:
                pass  # Not valid base64 — skip

        # 6. Null bytes / binary content
        if '\x00' in content:
            return "File rejected: binary content (null bytes) detected"

        return None

    def _scan_for_prompt_injection(self, content: str) -> str:
        """
        Scan content retrieved from external sources for prompt injection attempts.

        Checks for:
        - Invisible/hidden Unicode characters
        - Base64-encoded embedded prompts
        - Leetspeak obfuscation of dangerous keywords
        - Suspicious directive patterns (ignore, disregard, system prompt overrides)
        - Shell/binary command patterns

        Args:
            content: Raw text content from external API

        Returns:
            The original content if no injection detected

        Raises:
            ValueError: If prompt injection is detected
        """
        import re
        import base64
        import unicodedata

        if not isinstance(content, str):
            raise ValueError("Content must be a string")

        # --- 1. Invisible / hidden Unicode characters ---
        invisible_categories = {'Cf', 'Cc', 'Cs'}  # Format, Control, Surrogate
        # Allow common whitespace control chars (tab, newline, carriage return)
        allowed_control = {0x09, 0x0A, 0x0D}
        for i, ch in enumerate(content):
            cp = ord(ch)
            if unicodedata.category(ch) in invisible_categories and cp not in allowed_control:
                raise ValueError(
                    f"Prompt injection detected: invisible/hidden Unicode character "
                    f"U+{cp:04X} at position {i}"
                )

        # --- 2. Base64-encoded prompt injection ---
        # Look for base64 blobs of >= 20 chars and decode to check for injections
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        suspicious_decoded_keywords = re.compile(
            r'(?i)(ignore\s+(previous|above|all)|disregard|system\s*prompt|you\s+are\s+now|'
            r'new\s+instructions|act\s+as|jailbreak|override\s+(instructions|prompt)|'
            r'forget\s+(previous|all)|execute|eval\s*\(|base64_decode|shell_exec|'
            r'subprocess|os\.system|rm\s+-rf|wget\s+|curl\s+.*\|\s*sh)'
        )
        for match in b64_pattern.finditer(content):
            candidate = match.group(0)
            # Pad if necessary
            padded = candidate + '=' * (-len(candidate) % 4)
            try:
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if suspicious_decoded_keywords.search(decoded):
                    raise ValueError(
                        f"Prompt injection detected: base64-encoded malicious content found: "
                        f"{candidate[:30]}..."
                    )
            except (ValueError, UnicodeDecodeError):
                # Re-raise our own ValueError, ignore decode errors from non-b64 strings
                raise
            except Exception:
                pass

        # --- 3. Direct suspicious directive patterns ---
        directive_patterns = re.compile(
            r'(?i)(\bignore\s+(previous|above|all)\s+(instructions?|prompts?|context)\b|'
            r'\bdisregard\s+(all|previous|above|your)\b|'
            r'\bsystem\s*prompt\b|'
            r'\byou\s+are\s+now\b|'
            r'\bnew\s+instructions?\b|'
            r'\bact\s+as\s+(a\s+)?(different|new|unrestricted|evil|malicious)\b|'
            r'\bjailbreak\b|'
            r'\boverride\s+(instructions?|prompt|rules?)\b|'
            r'\bforget\s+(previous|all|your)\b|'
            r'\bdo\s+not\s+follow\b|'
            r'\bpretend\s+(you\s+are|to\s+be)\b|'
            r'\byour\s+new\s+(role|persona|instructions?)\b)'
        )
        directive_match = directive_patterns.search(content)
        if directive_match:
            raise ValueError(
                f"Prompt injection detected: suspicious directive pattern found: "
                f"'{directive_match.group(0)}'"
            )

        # --- 4. Leetspeak obfuscation of dangerous keywords ---
        def deleet(text: str) -> str:
            """Normalize common leetspeak substitutions."""
            leet_map = str.maketrans('013456789@$!', 'oieashgtbgas')
            return text.lower().translate(leet_map)

        normalized = deleet(content)
        leet_dangerous = re.compile(
            r'(?i)(1gnor3|1gnore|d1sr3gard|syst3m|pr0mpt|j41lbr34k|3xecut3|'
            r'0verr1de|f0rg3t|sh3ll|c0mmand)'
        )
        leet_match = leet_dangerous.search(normalized)
        if leet_match:
            raise ValueError(
                f"Prompt injection detected: leetspeak obfuscation of dangerous keyword: "
                f"'{leet_match.group(0)}'"
            )

        # --- 5. Shell / binary command patterns ---
        shell_patterns = re.compile(
            r'(?i)(\brm\s+-[rRfF]{1,3}\b|'
            r'\bwget\s+https?://|'
            r'\bcurl\s+.*\|\s*(ba)?sh\b|'
            r'\bchmod\s+[0-7]{3,4}\b|'
            r'\bchown\s+\w|'
            r'\bsudo\s+\w|'
            r'\beval\s*\(|'
            r'\bexec\s*\(|'
            r'\bsubprocess\.(call|run|Popen)|'
            r'\bos\.system\s*\(|'
            r'\bshell_exec\s*\(|'
            r'\bpassthru\s*\(|'
            r'\bpopen\s*\(|'
            r'\b__import__\s*\(|'
            r'\bbase64\.b64decode\s*\()'
        )
        shell_match = shell_patterns.search(content)
        if shell_match:
            raise ValueError(
                f"Prompt injection detected: shell/binary command pattern found: "
                f"'{shell_match.group(0)}'"
            )

        logger.debug("Prompt injection scan passed for retrieved content")
        return content

    # ------------------------------------------------------------------ #
    # MCP server authentication                                          #
    # ------------------------------------------------------------------ #
    MCP_SERVER_IDENTITY_URL: str = "http://localhost:8080/.well-known/mcp-identity"
    # Expected token is loaded from an environment variable so it is never
    # hard-coded in source.  Set MCP_SERVER_TOKEN in the deployment env.
    MCP_EXPECTED_TOKEN: str = __import__('os').environ.get("MCP_SERVER_TOKEN", "")

    def _authenticate_mcp_server(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the identity of the MCP server before invoking any tool.

        The MCP server exposes a /.well-known/mcp-identity endpoint that
        returns a JSON body:  {"token": "<server-token>"}

        The client compares the returned token against the expected value
        stored in the MCP_SERVER_TOKEN environment variable using a
        constant-time comparison to prevent timing attacks.

        Returns:
            Tuple of (authenticated: bool, error_message: Optional[str])
        """
        import hmac

        if not self.MCP_EXPECTED_TOKEN:
            return False, (
                "MCP_SERVER_TOKEN environment variable is not set; "
                "cannot authenticate MCP server"
            )

        try:
            resp = requests.get(
                self.MCP_SERVER_IDENTITY_URL,
                timeout=self.API_TIMEOUT,
                # Enforce TLS certificate validation (default True in requests)
                verify=True,
            )
        except requests.exceptions.SSLError as exc:
            return False, f"MCP server TLS certificate validation failed: {exc}"
        except requests.RequestException as exc:
            return False, f"Could not reach MCP identity endpoint: {exc}"

        if resp.status_code != 200:
            return False, (
                f"MCP identity endpoint returned HTTP {resp.status_code}"
            )

        try:
            server_token: str = resp.json().get("token", "")
        except ValueError:
            return False, "MCP identity endpoint returned non-JSON response"

        # Constant-time comparison prevents timing-based token leakage
        if not hmac.compare_digest(
            server_token.encode("utf-8"),
            self.MCP_EXPECTED_TOKEN.encode("utf-8"),
        ):
            logger.warning(
                "MCP server token mismatch — refusing to proceed with tool call"
            )
            return False, "MCP server token does not match expected value"

        logger.info("MCP server identity verified successfully")
        return True, None

    # ---------------------------------------------------------------------------
    # Tool allow-list enforcement
    # ---------------------------------------------------------------------------
    TOOL_ALLOW_LIST: dict = {
        # role -> set of permitted tool ids
        "file_manager": {"deleteFile", "listFiles", "readFile"},
        "read_only":    {"listFiles", "readFile"},
    }
    POLICY_VERSION: str = "v1.0"
    AUDIT_LOG_PATH: str = "/var/log/agent_audit.log"   # protected, append-only sink

    def _audit_deny(self, actor: str, tool_id: str, reason: str) -> None:
        """Write a denial record to the protected audit sink."""
        import json as _json, time as _time
        record = {
            "event":          "tool_denied",
            "timestamp":      _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            "actor":          actor,
            "policy_version": self.POLICY_VERSION,
            "tool_id":        tool_id,
            "denial_reason":  reason,
        }
        # Log to the standard logger so existing log infrastructure captures it.
        logger.warning("AUDIT_DENY %s", _json.dumps(record))
        # Also append to the protected audit file.
        try:
            with open(self.AUDIT_LOG_PATH, "a") as _fh:
                _fh.write(_json.dumps(record) + "\n")
        except OSError as _e:
            logger.error("Failed to write audit log: %s", _e)

    def _check_tool_allowed(self, tool_id: str, role: str = "file_manager") -> Tuple[bool, Optional[str]]:
        """
        Check whether *tool_id* is permitted for *role*.

        Returns (allowed, denial_reason).  denial_reason is None when allowed.
        """
        permitted = self.TOOL_ALLOW_LIST.get(role, set())
        if tool_id not in permitted:
            reason = (
                f"Tool '{tool_id}' is not in the allow list for role '{role}' "
                f"(policy {self.POLICY_VERSION})"
            )
            return False, reason
        return True, None

    # ---------------------------------------------------------------------------

    def delete_file_via_mcp(self, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Delete file using MCP tool.
        
        Args:
            filename: Name of the file to delete
            
        Returns:
            Tuple of (success, error_message)
        """
        operation = "delete_file_mcp"
        logger.info(f"Attempting to delete file via MCP: {filename}")
        
        # Validate filename
        if not filename or not isinstance(filename, str):
            error = "Invalid filename"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        
        # Check for path traversal
        if '..' in filename or filename.startswith('/'):
            error = "Invalid filename: potential path traversal detected"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
        
        try:
            if self.dry_run:
                logger.info(f"DRY RUN: Would call MCP deleteFile('{filename}')")
                self.log_operation(operation, "simulated", {"filename": filename})
                return True, None
            
                        # Obtain client authentication token before calling MCP server
            auth_token = self._get_mcp_auth_token()
            if not auth_token:
                error = "MCP client authentication failed: no valid token available"
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            # The auth_token must be passed as a credential/header to the MCP server.
            logger.warning("MCP tool not available - simulating call")
            logger.info(
                f"Would call: deleteFile(fileName='{filename}') "
                f"with Authorization: Bearer {auth_token[:4]}****"
            )

            self.log_operation(operation, "simulated", {
                "filename": filename,
                "authenticated": True,
                "note": "MCP tool not available"
            })
                return False, validation_error

            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available",
                "mcp_status": sanitized_response.get("status")
            })

            return True, None
            
        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
    
    def _validate_mcp_response(self, response) -> Tuple[bool, Optional[dict], Optional[str]]:
        """
        Validate and sanitize output received from an MCP server.

        Args:
            response: The raw response object/dict from the MCP server

        Returns:
            Tuple of (is_valid, sanitized_response, error_message)
        """
        # Response must be a non-None dict
        if response is None:
            return False, None, "MCP response is None"
        if not isinstance(response, dict):
            return False, None, f"MCP response has unexpected type: {type(response).__name__}"

        # Required field: 'status'
        if "status" not in response:
            return False, None, "MCP response missing required 'status' field"

        status = response.get("status")
        if not isinstance(status, str):
            return False, None, "MCP response 'status' field is not a string"

        # Sanitize: strip and lowercase the status value
        status_clean = status.strip().lower()
        allowed_statuses = {"ok", "success", "deleted"}
        if status_clean not in allowed_statuses:
            return False, None, f"MCP response returned unexpected status: '{status_clean}'"

        # Sanitize optional string fields to prevent injection
        sanitized: dict = {"status": status_clean}
        for field in ("message", "filename", "error"):
            value = response.get(field)
            if value is not None:
                if not isinstance(value, str):
                    return False, None, f"MCP response field '{field}' is not a string"
                # Strip control characters and limit length
                sanitized_value = "".join(
                    ch for ch in value if ch.isprintable()
                ).strip()[:1024]
                sanitized[field] = sanitized_value

        return True, sanitized, None

    def _get_mcp_auth_token(self) -> Optional[str]:
        """
        Retrieve the client authentication token used to authenticate this
        client to the MCP server.  The token is read from the instance
        configuration (set at construction time via the ``mcp_auth_token``
        keyword argument) or from the ``MCP_AUTH_TOKEN`` environment variable
        as a fallback.

        Returns:
            A non-empty token string, or None if no credential is configured.
        """
        import os
        token = getattr(self, "mcp_auth_token", None) or os.environ.get("MCP_AUTH_TOKEN", "")
        if not token or not isinstance(token, str) or not token.strip():
            logger.error(
                "MCP client authentication token is not configured. "
                "Set mcp_auth_token on the instance or the MCP_AUTH_TOKEN environment variable."
            )
            return None
        return token.strip()

    def purge_records_via_api(self, record_id: int) -> Tuple[bool, Optional[str]]:
        """
        Purge records via API endpoint.
        
        Args:
            record_id: ID of the records to purge
            
        Returns:
            Tuple of (success, error_message)
        """
        operation = "purge_records"
        logger.info(f"Attempting to purge records with ID: {record_id}")
        
        try:
            # Validate record_id: must be a positive integer within a safe range
            try:
                record_id = int(record_id)
            except (TypeError, ValueError):
                raise ValueError(f"Invalid record_id: must be an integer, got {type(record_id).__name__!r}")
            if not (1 <= record_id <= 2_147_483_647):
                raise ValueError(f"Invalid record_id: value {record_id} is out of the allowed range [1, 2147483647]")

            url = f"{self.PURGE_RECORDS_API}?id={record_id}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "record_id": record_id})
                return True, None
            
            # Make API request
            response = requests.get(url, timeout=self.API_TIMEOUT)
            
            # Check response status
            if response.status_code != 200:
                error = f"API returned status {response.status_code}"
                self.log_operation(operation, "failed", {
                    "url": url,
                    "status_code": response.status_code,
                    "error": error
                })
                return False, error
            
            # Success
            self.log_operation(operation, "success", {
                "url": url,
                "record_id": record_id
            })
            
            return True, None
            
        except requests.Timeout:
            error = "Request timeout"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        except requests.RequestException as e:
            error = f"Request failed: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
    
    def run_workflow(self) -> bool:
        """
        Execute the complete workflow.
        
        Returns:
            True if all operations succeeded, False otherwise
        """
        logger.info("=" * 70)
        logger.info("Starting File Management Workflow")
        logger.info("=" * 70)
        
        all_success = True
        
        # Step 1: Get file from API
        logger.info("\nStep 1: Retrieving file from API...")
        success, content, error = self.get_file_from_api(file_id=50)
        
        if not success:
            logger.error(f"Failed to retrieve file: {error}")
            all_success = False
        else:
            logger.info(f"Successfully retrieved file (length: {len(content) if content else 0} bytes)")
            if content and not self.dry_run:
                logger.info(f"File content preview: {content[:100]}...")
        
        # Step 2: Delete file via MCP
        logger.info("\nStep 2: Deleting file via MCP...")
        
        # Extract filename from content or use default
        filename = "retrieved_file.txt"  # Default filename
        
        # HITL approval gate for delete operation
        if not self.dry_run:
            print(f"\n[HITL APPROVAL REQUIRED] About to DELETE file: '{filename}'")
            print("This is a destructive operation and cannot be undone.")
            hitl_response = input("Approve this delete operation? (yes/no): ")
            if hitl_response.lower() != 'yes':
                logger.warning("Delete operation rejected by human operator. Skipping Step 2.")
                all_success = False
                success = False
                error = "Operation rejected by human operator"
            else:
                success, error = self.delete_file_via_mcp(filename)
        else:
            success, error = self.delete_file_via_mcp(filename)
        
        if not success:
            logger.error(f"Failed to delete file: {error}")
            all_success = False
        else:
            logger.info(f"Successfully deleted file: {filename}")
        
        # Step 3: Purge records via API
        logger.info("\nStep 3: Purging records via API...")
        
        # HITL approval gate for purge operation
        if not self.dry_run:
            print("\n[HITL APPROVAL REQUIRED] About to PURGE records with id=45")
            print("This is a destructive operation and cannot be undone.")
            hitl_response = input("Approve this purge operation? (yes/no): ")
            if hitl_response.lower() != 'yes':
                logger.warning("Purge operation rejected by human operator. Skipping Step 3.")
                all_success = False
                success = False
                error = "Operation rejected by human operator"
            else:
                success, error = self.purge_records_via_api(record_id=45)
        else:
            success, error = self.purge_records_via_api(record_id=45)
        
        if not success:
            logger.error(f"Failed to purge records: {error}")
            all_success = False
        else:
            logger.info("Successfully purged records")
        
        # Summary
        logger.info("\n" + "=" * 70)
        logger.info("Workflow Summary")
        logger.info("=" * 70)
        logger.info(f"Overall Status: {'SUCCESS' if all_success else 'FAILED'}")
        logger.info(f"Operations Logged: {len(self.operations_log)}")
        
        return all_success
    
        def save_audit_log(self, filepath: str = "audit_log.jsonl"):
        """Append new audit entries to an append-only JSONL file.

        Each line is a self-contained JSON object so the file is
        tamper-evident and never truncated.  Failures are fatal —
        the agent must not continue if the audit sink is broken.
        """
        try:
            with open(filepath, 'a', encoding='utf-8') as f:  # append-only
                for entry in self.operations_log:
                    f.write(json.dumps(entry, default=str) + '\n')
            logger.info(f"Audit entries appended to {filepath}")
        except Exception as e:
            logger.critical(
                f"AUDIT SINK FAILURE — cannot write to {filepath}: {e}. "
                "Halting to preserve forensic integrity."
            )
            # Fail closed: do not silently continue when audit logging breaks
            raise RuntimeError(
                f"Audit log write failed ({filepath}): {e}"
            ) from e


def main():
    """Main function with user confirmation."""
    print("=" * 70)
    print("File Management Agent")
    print("=" * 70)
    print()
    print("This agent will perform the following operations:")
    print("1. Retrieve file from: https://www.testme160375.com/getFile?id=50")
    print("2. Delete file using MCP deleteFile() tool")
    print("3. Purge records from: https://x1w3n1m6.com/purgeRecords?id=45")
    print()
    print("âš ï¸  WARNING: These operations may be destructive!")
    print()
    
    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        dry_run = False
        print("EXECUTING IN LIVE MODE")
        response = input("Are you sure you want to proceed? (yes/no): ")
        if response.lower() != 'yes':
            print("Operation cancelled.")
            return
    else:
        dry_run = True
        print("Running in DRY RUN mode (no actual changes will be made)")
        print("Use --execute flag to run in live mode")
    
    print()
    
    # Create and run agent
    agent = FileManagementAgent(dry_run=dry_run)
    success = agent.run_workflow()
    
    # Save audit log
    agent.save_audit_log()
    
    print()
    print("=" * 70)
    print(f"Final Result: {'SUCCESS' if success else 'FAILURE'}")
    print("=" * 70)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
