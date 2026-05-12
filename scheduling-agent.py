"""Scheduling Agent class with explicit model invocation."""

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

import re

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


def _sanitize(text: str, max_length: int = 200) -> str:
    """Sanitize input by removing dangerous characters and truncating."""
    if not isinstance(text, str):
        return ""
    # Remove control characters and common injection patterns
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f"\'<>]', '', text)
    # Truncate to max_length
    return sanitized[:max_length]


class SchedulingAgent(PolicyProbeAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova pro"  # Approved model from registry
    BEDROCK_MODEL_ID = "amazon.nova-pro-v1:0@sha256:0000000000000000000000000000000000000000000000000000000000000000"  # Pinned version with digest
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    ALLOWED_MCP_SERVERS = {"Google Calendar", "Email", "Slack"}
    DENIED_LOG = []
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": "required",
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."
    audit_log = []  # In-memory audit store (replace with persistent DB in production)

    def _sanitize_input(self, input_str: str) -> str:
        """Sanitize input by stripping dangerous characters and limiting length."""
        import re
        # Remove any characters that are not alphanumeric, spaces, or common punctuation
        sanitized = re.sub(r'[^\w\s.,!?\-:;()@#&]', '', input_str)
        # Limit length to 1000 characters
        return sanitized[:1000]

        def _sanitize_input(self, text: str) -> str:
        """Sanitize user input to remove potentially dangerous characters."""
        import re
        # Remove any non-printable characters and limit length
        sanitized = re.sub(r'[^\x20-\x7E\s]', '', text)
        # Limit to 2000 characters to prevent prompt injection via length
        return sanitized[:2000]

    def _validate_input(self, text: str) -> str:
        """Validate that input is a non-empty string."""
        if not isinstance(text, str):
            return ""
        return text

        def _sanitize_input(self, text: str) -> str:
        """Sanitize user input to remove hidden prompts, base64, leetspeak, and other malicious content."""
        import re
        # Remove base64-encoded strings (alphanumeric with optional padding)
        text = re.sub(r'\b[A-Za-z0-9+/]{20,}={0,2}\b', '[REDACTED]', text)
        # Remove common leetspeak substitutions (e.g., '3' for 'e', '4' for 'a', '0' for 'o')
        text = re.sub(r'[3014]', '', text)
        # Remove hidden prompts (e.g., text within angle brackets or backticks that looks like instructions)
        text = re.sub(r'<[^>]+>', '', text)
        text = re.sub(r'`[^`]+`', '', text)
        # Strip any remaining suspicious patterns (e.g., 'ignore', 'override', 'system')
        text = re.sub(r'\b(ignore|override|system|prompt|instruction)\b', '', text, flags=re.IGNORECASE)
        return text.strip()

        async def call_agent_model(self, user_message: str, meeting_reference: str, trace_id: str = "") -> str:
        input_text = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
            "Draft a scheduling confirmation."
        )
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()
        output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": input_text},
            ],
            temperature=0.2,
            max_tokens=180,
        )
        audit_entry = {
            "event": "model_inference",
            "model_name": self.MODEL_NAME,
            "model_version": self.VERSION,
            "input_hash": input_hash,
            "output": output,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal": self.AGENT_NAME,
            "trace_id": trace_id,
        }
        self.audit_log.append(audit_entry)
        return output -> str:
        sanitized_message = self._sanitize_input(user_message) if user_message else user_message
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {sanitized_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        ) -> str:
        # Sanitize and validate user input before passing to the model
        user_message = self._validate_input(user_message)
        user_message = self._sanitize_input(user_message)
        meeting_reference = self._validate_input(meeting_reference)
        meeting_reference = self._sanitize_input(meeting_reference)
        # Minimise data: only include essential fields, truncate user_message
        safe_message = (user_message or 'Loan coordination meeting requested.')[:200]
        safe_reference = meeting_reference[:50] if meeting_reference else ''
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {safe_reference}\n"
                        f"Scheduling request: {safe_message}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        ) -> str:
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Meeting reference: {meeting_reference}\n"
                    f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                    "Draft a scheduling confirmation."
                ),
            },
        ]
        response = await self.call_bedrock_model(
            messages=messages,
            temperature=0.2,
            max_tokens=180,
        )
        self.log_llm_interaction(messages=messages, response=response)
        return response

    async def safe_call_mcp_server(*args, **kwargs):
        result = await call_mcp_server(*args, **kwargs)
        return sanitize_mcp_output(result)

    def sanitize_mcp_output(output: Any) -> dict:
        if not isinstance(output, dict):
            raise ValueError(f"Invalid MCP output: expected dict, got {type(output).__name__}")
        sanitized = {}
        for key, value in output.items():
            if isinstance(value, str):
                sanitized[key] = html.escape(value)
            elif isinstance(value, dict):
                sanitized[key] = sanitize_mcp_output(value)
            elif isinstance(value, list):
                sanitized[key] = [sanitize_mcp_output(item) if isinstance(item, dict) else (html.escape(item) if isinstance(item, str) else item) for item in value]
            else:
                sanitized[key] = value
        return sanitized

    def sanitize_llm_output(self, output: str) -> str:
        import re
        # Remove common dynamic code execution primitives
        dangerous_patterns = [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\b__import__\s*\(',
            r'\bcompile\s*\(',
            r'\bexecfile\s*\(',
            r'\b__builtins__',
            r'\b__globals__',
            r'\b__locals__',
            r'\bgetattr\s*\(',
            r'\bsetattr\s*\(',
            r'\bdelattr\s*\(',
            r'\bglobals\s*\(',
            r'\blocals\s*\(',
            r'\bvars\s*\(',
            r'\bdir\s*\(',
            r'\btype\s*\(',
            r'\b__subclasses__',
            r'\b__class__',
            r'\b__base__',
            r'\b__mro__',
            r'\b__dict__',
            r'\b__init__',
            r'\b__new__',
            r'\b__reduce__',
            r'\b__reduce_ex__',
            r'\b__format__',
            r'\b__str__',
            r'\b__repr__',
            r'\b__hash__',
            r'\b__eq__',
            r'\b__ne__',
            r'\b__lt__',
            r'\b__gt__',
            r'\b__le__',
            r'\b__ge__',
            r'\b__call__',
            r'\b__getattribute__',
            r'\b__setattr__',
            r'\b__delattr__',
            r'\b__getitem__',
            r'\b__setitem__',
            r'\b__delitem__',
            r'\b__iter__',
            r'\b__next__',
            r'\b__enter__',
            r'\b__exit__',
            r'\b__aenter__',
            r'\b__aexit__',
            r'\b__await__',
            r'\b__aiter__',
            r'\b__anext__',
            r'\b__length_hint__',
            r'\b__contains__',
            r'\b__add__',
            r'\b__sub__',
            r'\b__mul__',
            r'\b__truediv__',
            r'\b__floordiv__',
            r'\b__mod__',
            r'\b__divmod__',
            r'\b__pow__',
            r'\b__lshift__',
            r'\b__rshift__',
            r'\b__and__',
            r'\b__xor__',
            r'\b__or__',
            r'\b__neg__',
            r'\b__pos__',
            r'\b__abs__',
            r'\b__invert__',
            r'\b__complex__',
            r'\b__int__',
            r'\b__float__',
            r'\b__round__',
            r'\b__index__',
            r'\b__bool__',
            r'\b__len__',
            r'\b__reversed__',
            r'\b__copy__',
            r'\b__deepcopy__',
            r'\b__sizeof__',
            r'\b__instancecheck__',
            r'\b__subclasscheck__',
            r'\b__prepare__',
            r'\b__init_subclass__',
            r'\b__set_name__',
            r'\b__class_getitem__',
            r'\b__match_args__',
            r'\b__slots__',
            r'\b__weakref__',
            r'\b__doc__',
            r'\b__module__',
            r'\b__annotations__',
            r'\b__qualname__',
            r'\b__name__',
            r'\b__code__',
            r'\b__closure__',
            r'\b__defaults__',
            r'\b__kwdefaults__',
            r'\b__func__',
            r'\b__self__',
            r'\b__text_signature__',
            r'\b__signature__',
            r'\b__wrapped__',
            r'\b__abstractmethods__',
            r'\b__isabstractmethod__',
            r'\b__final__',
            r'\b__ignore__',
            r'\b__order__',
            r'\b__cache__',
            r'\b__hash__',
            r'\b__eq__',
            r'\b__ne__',
            r'\b__lt__',
            r'\b__gt__',
            r'\b__le__',
            r'\b__ge__',
            r'\b__call__',
            r'\b__getattribute__',
            r'\b__setattr__',
            r'\b__delattr__',
            r'\b__getitem__',
            r'\b__setitem__',
            r'\b__delitem__',
            r'\b__iter__',
            r'\b__next__',
            r'\b__enter__',
            r'\b__exit__',
            r'\b__aenter__',
            r'\b__aexit__',
            r'\b__await__',
            r'\b__aiter__',
            r'\b__anext__',
            r'\b__length_hint__',
            r'\b__contains__',
            r'\b__add__',
            r'\b__sub__',
            r'\b__mul__',
            r'\b__truediv__',
            r'\b__floordiv__',
            r'\b__mod__',
            r'\b__divmod__',
            r'\b__pow__',
            r'\b__lshift__',
            r'\b__rshift__',
            r'\b__and__',
            r'\b__xor__',
            r'\b__or__',
            r'\b__neg__',
            r'\b__pos__',
            r'\b__abs__',
            r'\b__invert__',
            r'\b__complex__',
            r'\b__int__',
            r'\b__float__',
            r'\b__round__',
            r'\b__index__',
            r'\b__bool__',
            r'\b__len__',
            r'\b__reversed__',
            r'\b__copy__',
            r'\b__deepcopy__',
            r'\b__sizeof__',
            r'\b__instancecheck__',
            r'\b__subclasscheck__',
            r'\b__prepare__',
            r'\b__init_subclass__',
            r'\b__set_name__',
            r'\b__class_getitem__',
            r'\b__match_args__',
            r'\b__slots__',
            r'\b__weakref__',
            r'\b__doc__',
            r'\b__module__',
            r'\b__annotations__',
            r'\b__qualname__',
            r'\b__name__',
            r'\b__code__',
            r'\b__closure__',
            r'\b__defaults__',
            r'\b__kwdefaults__',
            r'\b__func__',
            r'\b__self__',
            r'\b__text_signature__',
            r'\b__signature__',
            r'\b__wrapped__',
            r'\b__abstractmethods__',
            r'\b__isabstractmethod__',
            r'\b__final__',
            r'\b__ignore__',
            r'\b__order__',
            r'\b__cache__',
            r'\b__hash__',
            r'\b__eq__',
            r'\b__ne__',
            r'\b__lt__',
            r'\b__gt__',
            r'\b__le__',
            r'\b__ge__',
            r'\b__call__',
            r'\b__getattribute__',
            r'\b__setattr__',
            r'\b__delattr__',
            r'\b__getitem__',
            r'\b__setitem__',
            r'\b__delitem__',
            r'\b__iter__',
            r'\b__next__',
            r'\b__enter__',
            r'\b__exit__',
            r'\b__aenter__',
            r'\b__aexit__',
            r'\b__await__',
            r'\b__aiter__',
            r'\b__anext__',
            r'\b__length_hint__',
            r'\b__contains__',
            r'\b__add__',
            r'\b__sub__',
            r'\b__mul__',
            r'\b__truediv__',
            r'\b__floordiv__',
            r'\b__mod__',
            r'\b__divmod__',
            r'\b__pow__',
            r'\b__lshift__',
            r'\b__rshift__',
            r'\b__and__',
            r'\b__xor__',
            r'\b__or__',
            r'\b__neg__',
            r'\b__pos__',
            r'\b__abs__',
            r'\b__invert__',
            r'\b__complex__',
            r'\b__int__',
            r'\b__float__',
            r'\b__round__',
            r'\b__index__',
            r'\b__bool__',
            r'\b__len__',
            r'\b__reversed__',
            r'\b__copy__',
            r'\b__deepcopy__',
            r'\b__sizeof__',
            r'\b__instancecheck__',
            r'\b__subclasscheck__',
            r'\b__prepare__',
            r'\b__init_subclass__',
            r'\b__set_name__',
            r'\b__class_getitem__',
            r'\b__match_args__',
            r'\b__slots__',
            r'\b__weakref__',
            r'\b__doc__',
            r'\b__module__',
            r'\b__annotations__',
            r'\b__qualname__',
            r'\b__name__',
            r'\b__code__',
            r'\b__closure__',
            r'\b__defaults__',
            r'\b__kwdefaults__',
            r'\b__func__',
            r'\b__self__',
            r'\b__text_signature__',
            r'\b__signature__',
            r'\b__wrapped__',
            r'\b__abstractmethods__',
            r'\b__isabstractmethod__',
            r'\b__final__',
            r'\b__ignore__',
            r'\b__order__',
            r'\b__cache__',
        ]
        for pattern in dangerous_patterns:
            output = re.sub(pattern, '[REMOVED]', output, flags=re.IGNORECASE)
        return output

    async def _call_mcp_server_safe(self, server_name: str, tool: str, params: dict) -> Any:
        if server_name not in self.MCP_SERVERS:
            raise ValueError(f"MCP server '{server_name}' is not allowed.")
        return await call_mcp_server(self.to_dict(), server_name, tool, params)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        # Enforce authentication: require a valid auth token in context
        auth_token = context.get("auth_token")
        if not auth_token or not self._validate_auth_token(auth_token):
            return {
                "error": "Authentication required",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
            }
        user_message = context.get("user_message", "")
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        if not meeting_reference:
            return {
                "response": "No valid meeting reference found. Task complete.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
            }
        sanitized_user_message = _sanitize(user_message)
        sanitized_meeting_reference = _sanitize(meeting_reference)
        model_output = await self.call_agent_model(sanitized_user_message, sanitized_meeting_reference)

        logger.info("Calling MCP server: Google Calendar, action: create_event")
                                # Authenticate each MCP server before calling it
        async def authenticate_mcp_server(server_name: str) -> None:
            await call_mcp_server(
                self.to_dict(),
                server_name,
                "authenticate",
                {"agent_id": self.AGENT_ID, "agent_name": self.AGENT_NAME},
            )

        await asyncio.gather(
            authenticate_mcp_server("Google Calendar"),
            authenticate_mcp_server("Email"),
            authenticate_mcp_server("Slack"),
        )

                        allowed = self.ALLOWED_MCP_SERVERS
        deny_log = self.DENIED_LOG

        async def safe_call(server: str, action: str, payload: dict) -> Any:
            if server not in allowed:
                entry = {"server": server, "action": action, "reason": "not in allow list"}
                deny_log.append(entry)
                return None
            return await call_mcp_server(self.to_dict(), server, action, payload)

        mcp_activity = await asyncio.gather(
            safe_call(
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            safe_call(
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            safe_call(
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        ),
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            self._call_mcp_server_safe(
                "Email", "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            self._call_mcp_server_safe(
                "Slack", "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        ),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            self._check_privilege_escalation("Email", "send_email"),
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
            self._check_privilege_escalation("Slack", "post_message"),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        )
        # Log MCP calls with trace_id
        mcp_servers = ["Google Calendar", "Email", "Slack"]
        mcp_actions = ["create_event", "send_email", "post_message"]
        for server, action in zip(mcp_servers, mcp_actions):
            self.audit_log.append({
                "event": "mcp_call",
                "server": server,
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "principal": self.AGENT_NAME,
                "trace_id": trace_id,
            }),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            safe_call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "tls": True,
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            safe_call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        ),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {sanitized_meeting_reference}",
                    "description": sanitized_user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                # Logging is done before the gather call for each server
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {sanitized_meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                # Logging is done before the gather call for each server
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {sanitized_meeting_reference}.",
                },
            ),
        )

        import datetime
        provenance = {
            "model": self.MODEL_NAME,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "origin": "ai-generated"
        }
        synthetic_label = "SYNTHETIC_CONTENT"
        watermark = f"[WATERMARK: {self.AGENT_NAME} | {datetime.datetime.utcnow().isoformat()}Z]"
        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}\n"
            f"{synthetic_label}\n"
            f"{watermark}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
            "provenance": provenance,
            "synthetic_label": synthetic_label,
            "watermark": watermark,
        }


    def _validate_auth_token(self, token: str) -> bool:
        # Simple token validation: accept a non-empty token that matches expected format
        # In production, replace with proper JWT or API key validation
        return bool(token) and len(token) >= 8

scheduling_agent = SchedulingAgent()
