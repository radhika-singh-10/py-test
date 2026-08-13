"""Scheduling Agent class with explicit model invocation."""

import asyncio
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server, generate_client_auth_token

MCP_SERVER_AUTH_TOKENS = {
    "Google Calendar": os.environ.get("MCP_GOOGLE_CALENDAR_AUTH_TOKEN", ""),
    "Email": os.environ.get("MCP_EMAIL_AUTH_TOKEN", ""),
    "Slack": os.environ.get("MCP_SLACK_AUTH_TOKEN", ""),
}

MCP_SERVER_EXPECTED_CERTS = {
    "Google Calendar": os.environ.get("MCP_GOOGLE_CALENDAR_CERT_FINGERPRINT", ""),
    "Email": os.environ.get("MCP_EMAIL_CERT_FINGERPRINT", ""),
    "Slack": os.environ.get("MCP_SLACK_CERT_FINGERPRINT", ""),
}

# ---------------------------------------------------------------------------
# Logging & Retention Configuration
# Policy: All high-risk AI system lifecycle events must be retained for a
# minimum of 6 months (180 days).
# ---------------------------------------------------------------------------
LOG_RETENTION_DAYS = 180  # Minimum six-month retention period
LOG_DIR = os.environ.get("AGENT_LOG_DIR", "/var/log/ai-agents")
LOG_FILE = os.path.join(LOG_DIR, "scheduling_agent_events.log")

os.makedirs(LOG_DIR, exist_ok=True)

_logger = logging.getLogger("scheduling_agent.lifecycle")
_logger.setLevel(logging.INFO)

# TimedRotatingFileHandler keeps logs for at least LOG_RETENTION_DAYS
_file_handler = logging.handlers.TimedRotatingFileHandler(
    LOG_FILE,
    when="D",
    interval=1,
    backupCount=LOG_RETENTION_DAYS,  # Retain 180 daily log files minimum
    utc=True,
)
_file_handler.setFormatter(
    logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
)
_logger.addHandler(_file_handler)


def _log_lifecycle_event(event_type: str, agent_id: str, details: dict[str, Any]) -> None:
    """Record a structured lifecycle event with retention-policy metadata."""
    event_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "agent_id": agent_id,
        "retention_days": LOG_RETENTION_DAYS,
        **details,
    }
    _logger.info("%s", event_record)



MAX_USER_MESSAGE_LENGTH = 500
MODEL_CALL_TIMEOUT_SECONDS = 30


def sanitize_user_input(raw_input: str) -> str:
    """Sanitize untrusted user input before interpolation into LLM prompts.

    - Strips control characters and potential prompt injection patterns.
    - Truncates to a safe maximum length.
    """
    if not raw_input:
        return ""
    # Remove control characters except newline and space
    sanitized = re.sub(r'[\x00-\x09\x0b-\x1f\x7f]', '', raw_input)
    # Collapse multiple newlines to limit prompt manipulation
    sanitized = re.sub(r'\n{3,}', '\n\n', sanitized)
    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()
    # Truncate to maximum allowed length
    sanitized = sanitized[:MAX_USER_MESSAGE_LENGTH]
    return sanitized


def _sanitize_input(value: str, max_length: int = 500) -> str:
    """Sanitize and validate input before passing to the LLM prompt.

    - Strips leading/trailing whitespace
    - Removes control characters (except newline and tab)
    - Removes common prompt-injection patterns (e.g., role overrides)
    - Truncates to max_length
    """
    if not isinstance(value, str):
        return ""
    # Remove control characters except \n and \t
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    # Strip attempts to inject system/assistant role overrides
    value = re.sub(
        r'(?i)(\[/?\s*(?:system|assistant|user)\s*\]|<\|?\s*(?:im_start|im_end|system|assistant)\s*\|?>)',
        '',
        value,
    )
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    return value


_ALLOWED_MCP_KEYS = {"status", "message", "event_id", "message_id", "channel", "error"}


def _sanitize_string(value: str) -> str:
    """Sanitize a string value from MCP output."""
    # Strip control characters except newline/tab
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    # HTML-escape to prevent injection if rendered in a web context
    value = html.escape(value, quote=True)
    # Truncate excessively long strings
    max_len = 2048
    if len(value) > max_len:
        value = value[:max_len] + "...[truncated]"
    return value


def _sanitize_value(value: Any) -> Any:
    """Recursively sanitize a value from MCP output."""
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value[:100]]
    if isinstance(value, dict):
        return {_sanitize_string(str(k)): _sanitize_value(v) for k, v in value.items()}
    # Unrecognized types are converted to sanitized strings
    return _sanitize_string(str(value))


def _validate_mcp_result(result: Any) -> dict[str, Any]:
    """Validate and sanitize a single MCP server result."""
    if result is None:
        return {"status": "error", "message": "No response from MCP server"}
    if isinstance(result, Exception):
        return {"status": "error", "message": _sanitize_string(str(result))}
    if not isinstance(result, dict):
        return {"status": "unknown", "message": _sanitize_string(str(result))}
    # Filter to allowed keys and sanitize values
    sanitized: dict[str, Any] = {}
    for key, value in result.items():
        sanitized_key = str(key)
        if sanitized_key in _ALLOWED_MCP_KEYS:
            sanitized[sanitized_key] = _sanitize_value(value)
    # Ensure a status field exists
    if "status" not in sanitized:
        sanitized["status"] = "unknown"
    return sanitized

logger = logging.getLogger(__name__)


def sanitize_input(value: str, max_length: int = 500) -> str:
    """Sanitize user input by removing control characters, dangerous patterns, and limiting length."""
    if not value:
        return value
    # Remove control characters except newline and tab
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    # Remove potential injection patterns (e.g., template injections, script tags)
    sanitized = re.sub(r'<[^>]*>', '', sanitized)
    sanitized = re.sub(r'\{\{.*?\}\}', '', sanitized)
    sanitized = re.sub(r'\$\{.*?\}', '', sanitized)
    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()
    # Enforce maximum length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    return sanitized


class SchedulingAgent(PolicyProbeAgentFramework):
        AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1@sha256:a3f2c8b91d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    COVERED_DOMAIN = "financial_services"
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
        "cryptographic_caller_binding": None,
    }
    SYSTEM_PROMPT = "You are an AI-powered automated scheduling assistant. Coordinate calendar events and notify the relevant teams."

        async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        sanitized_message = sanitize_user_input(user_message)
        sanitized_reference = sanitize_user_input(meeting_reference)
        return await asyncio.wait_for(
            self.call_bedrock_model(
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            f"Meeting reference: {sanitized_reference}\n"
                            f"Scheduling request: {sanitized_message or 'Loan coordination meeting requested.'}\n\n"
                            "Draft a scheduling confirmation."
                        ),
                    },
                ],
                temperature=0.2,
                max_tokens=180,
            ),
            timeout=MODEL_CALL_TIMEOUT_SECONDS,
        ) -> str:
        sanitized_message = _sanitize_input(user_message, max_length=500)
        sanitized_reference = _sanitize_input(meeting_reference, max_length=50)

        if not sanitized_reference:
            sanitized_reference = "UNKNOWN"

        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {sanitized_reference}\n"
                        f"Scheduling request: {sanitized_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )

        def verify_caller_binding(self, context: dict[str, Any]) -> str:
        """Verify cryptographic user-to-agent binding before processing any request.

        Requires context to contain:
          - 'auth_token': a cryptographic signature (HMAC-SHA256 hex digest)
            binding the user_id, session_id, and timestamp.
          - 'user_id': authenticated user identifier.
          - 'session_id': unique session identifier.
          - 'timestamp': request timestamp (epoch seconds).
          - 'signing_key': shared secret used for HMAC verification.

        Raises ValueError if verification fails.
        Returns the verified user_id.
        """
        auth_token = context.get("auth_token")
        user_id = context.get("user_id")
        session_id = context.get("session_id")
        timestamp = context.get("timestamp")
        signing_key = context.get("signing_key")

        if not all([auth_token, user_id, session_id, timestamp, signing_key]):
            raise ValueError(
                "Cryptographic caller binding failed: missing required authentication "
                "fields (auth_token, user_id, session_id, timestamp, signing_key)."
            )

        # Reject requests older than 5 minutes to prevent replay attacks
        try:
            request_time = float(timestamp)
        except (TypeError, ValueError):
            raise ValueError("Cryptographic caller binding failed: invalid timestamp.")

        if abs(time.time() - request_time) > 300:
            raise ValueError(
                "Cryptographic caller binding failed: request timestamp is stale "
                "(possible replay attack)."
            )

        # Recompute expected HMAC-SHA256 signature over the binding payload
        binding_payload = f"{user_id}:{session_id}:{timestamp}:{self.AGENT_ID}"
        expected_token = hmac.new(
            signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key,
            binding_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_token, auth_token):
            raise ValueError(
                "Cryptographic caller binding failed: HMAC signature mismatch. "
                "The request is not authentically bound to the claimed user/session."
            )

        return user_id

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        # Enforce cryptographic user-to-agent binding before processing
        verified_user_id = self.verify_caller_binding(context)

        user_message = context.get("user_message", "")
        user_message = sanitize_input(raw_user_message, max_length=500)
        meeting_reference = sanitize_input(
            extract_reference_number(user_message, prefix="MEET"), max_length=50
        )
        raw_        llm_request = {
            "model_id": self.BEDROCK_MODEL_ID,
            "agent": self.AGENT_NAME,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        "Scheduling request: Loan coordination meeting requested.\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            "temperature": 0.2,
            "max_tokens": 180,
        }
        logger.info("LLM request: %s", llm_request)
        model_output = await self.call_agent_model(user_message, meeting_reference)
        logger.info("LLM response: %s", {"agent": self.AGENT_NAME, "model_id": self.BEDROCK_MODEL_ID, "output": model_output})
        model_output = _sanitize_model_output(raw_model_output)

        # Define MCP call parameters for logging and execution
        google_calendar_params = {
            "title": f"Borrower meeting {meeting_reference}",
            "description": user_message or "Loan coordination meeting requested.",
            "start": "2026-04-01T10:00:00-07:00",
            "end": "2026-04-01T10:30:00-07:00",
        }
        email_params = {
            "to": ["borrower@acme.example", "underwriting@acme.example"],
            "subject": f"Meeting scheduled for {meeting_reference}",
            "body": "The Scheduling Agent created a calendar event for this request.",
        }
        slack_params = {
            "channel": "#loan-ops",
            "text": f"Scheduling Agent created meeting {meeting_reference}.",
        }

        # Log MCP requests before making calls
        logger.info(
            "MCP request to Google Calendar: server=%s, tool=%s, params=%s",
            "Google Calendar", "create_event", google_calendar_params,
        )
        logger.info(
            "MCP request to Email: server=%s, tool=%s, params=%s",
            "Email", "send_email", email_params,
        )
        logger.info(
            "MCP request to Slack: server=%s, tool=%s, params=%s",
            "Slack", "post_message", slack_params,
        )

                mcp_raw_results = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
            return_exceptions=True,
        )

        # Validate and sanitize all MCP server outputs before use
        mcp_activity = [_validate_mcp_result(result) for result in mcp_raw_results],
                "Google Calendar",
                "create_event",
                google_calendar_params,
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                email_params,
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                slack_params,
            ),
        )

        # Log MCP responses after calls complete
        logger.info(
            "MCP response from Google Calendar: server=%s, tool=%s, response=%s",
            "Google Calendar", "create_event", mcp_activity[0],
        )
        logger.info(
            "MCP response from Email: server=%s, tool=%s, response=%s",
            "Email", "send_email", mcp_activity[1],
        )
        logger.info(
            "MCP response from Slack: server=%s, tool=%s, response=%s",
            "Slack", "post_message", mcp_activity[2],
        )

        generated_at = datetime.now(timezone.utc).isoformat()

        synthetic_label = (
            "[SYNTHETIC CONTENT] This output was generated by an AI system and is not human-authored."
        )

        response = (
            f"{synthetic_label}\n\n"
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}\n\n"
            f"--- Provenance ---\n"
            f"Model: {self.BEDROCK_MODEL_ID}\n"
            f"Generated at: {generated_at}\n"
            f"Content origin: AI-generated by {self.AGENT_NAME} v{self.VERSION}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
            "provenance": {
                "is_ai_generated": True,
                "synthetic_content_label": "AI-generated content",
                "model_identifier": self.BEDROCK_MODEL_ID,
                "agent_id": self.AGENT_ID,
                "agent_version": self.VERSION,
                "generated_at": generated_at,
                "content_origin": f"Generated by {self.AGENT_NAME} using {self.BEDROCK_MODEL_ID}",
            },
        }


scheduling_agent = SchedulingAgent()
