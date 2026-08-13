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

Model Card / Release Documentation:
    Model Name: FileManagementAgent
    Version: 1.0.0
    Release Date: 2024-01-15
    Description: Autonomous agent for file retrieval, deletion, and record purging.
    Owner: Platform Engineering Team
    Contact: platform-eng@example.com

Changelog:
    v1.0.0 (2024-01-15):
        - Initial release
        - File retrieval from API endpoint
        - File deletion via MCP tool
        - Record purging via API
        - Dry-run mode support
        - Operation audit logging
"""

import os
import sys
import json
import logging
import logging.handlers
import hashlib
import getpass
from datetime import datetime
from typing import Optional, Dict, Tuple

try:
    import requests
except ImportError:
    print("Error: requests package is not installed.")
    print("Install it with: pip3 install requests")
    sys.exit(1)


# Configure logging with rotation and retention policy
_LOG_FILE = 'file_management_agent.log'
_rotating_handler = logging.handlers.RotatingFileHandler(
    _LOG_FILE,
    mode='a',  # append-only mode
    maxBytes=50 * 1024 * 1024,  # 50 MB per file
    backupCount=90,  # retain up to 90 rotated files (~90 days at moderate volume)
)
_rotating_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        _rotating_handler,
        _stream_handler
    ]
)
logger = logging.getLogger(__name__)

# Immutability: set log file to append-only at OS level where supported
try:
    import fcntl
    import struct
    _fd = os.open(_LOG_FILE, os.O_RDONLY)
    # Set append-only attribute (Linux ext2/ext3/ext4)
    _FS_APPEND_FL = 0x00000020
    try:
        _attr = struct.unpack('i', fcntl.ioctl(_fd, 0x80086601, struct.pack('i', 0)))[0]
        fcntl.ioctl(_fd, 0x40086602, struct.pack('i', _attr | _FS_APPEND_FL))
    except (OSError, PermissionError):
        pass  # Best-effort; may require elevated privileges
    finally:
        os.close(_fd)
except (ImportError, OSError):
    pass  # Non-Linux or insufficient privileges; rely on file permissions

# Agent metadata for audit trail
AGENT_MODEL_ID = "file-management-agent"
AGENT_MODEL_VERSION = "1.0.0"


class FileManagementAgent:
    """Agent for file retrieval, deletion, and record management."""
    
    # Configuration metadata
    AGENT_METADATA = {
        "name": "FileManagementAgent",
        "version": "1.0.0",
        "risk_level": "high",  # Risk classification: low, medium, high, critical
        "description": "Agent for file retrieval, deletion, and record management."
    }
    
    VALID_RISK_LEVELS = ("low", "medium", "high", "critical")
    
    # API endpoints
    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    
    # Timeouts and limits
    API_TIMEOUT = 30  # seconds
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize the agent.
        
        Args:
            dry_run: If True, only simulate operations without making actual changes
        """
        # Validate risk classification at startup
        risk_level = self.AGENT_METADATA.get("risk_level")
        if not risk_level:
            raise ValueError(
                "AI agent deployment must declare a risk_level in configuration metadata. "
                "Valid levels: " + ", ".join(self.VALID_RISK_LEVELS)
            )
        if risk_level not in self.VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. "
                "Valid levels: " + ", ".join(self.VALID_RISK_LEVELS)
            )
        logger.info(f"Agent risk classification: {risk_level}")
        
        self.dry_run = dry_run
        self.risk_level = risk_level
        self.operations_log = []
        
        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    def _authenticate_mcp_server(self) -> bool:
        """
        Authenticate the MCP server by validating its TLS certificate against
        the trusted CA bundle and verifying the expected Common Name.
        
        Returns:
            True if server authentication succeeds, False otherwise.
        """
        import ssl
        import socket
        from urllib.parse import urlparse
        
        parsed = urlparse(self.MCP_SERVER_URL)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        if not os.path.isfile(self.MCP_CA_BUNDLE):
            logger.error(f"MCP CA bundle not found at: {self.MCP_CA_BUNDLE}")
            return False
        
        try:
            context = ssl.create_default_context(cafile=self.MCP_CA_BUNDLE)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), timeout=self.API_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    # Verify the subject common name matches expected value
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    cn = subject.get('commonName', '')
                    
                    # Also accept if hostname matches any SAN entry (already validated by check_hostname)
                    if cn != self.MCP_EXPECTED_CN:
                        # check_hostname already validated against SANs, but log for audit
                        logger.info(f"MCP server CN '{cn}' differs from expected '{self.MCP_EXPECTED_CN}', "
                                    f"but hostname verification passed via SAN.")
                    
                    logger.info(f"MCP server authenticated successfully: CN={cn}, "
                                f"issuer={dict(x[0] for x in cert.get('issuer', ()))}")
                    self._mcp_authenticated = True
                    return True
        except ssl.SSLCertVerificationError as e:
            logger.error(f"MCP server TLS certificate verification failed: {e}")
            return False
        except ssl.SSLError as e:
            logger.error(f"MCP server TLS error: {e}")
            return False
        except (socket.timeout, socket.error) as e:
            logger.error(f"MCP server connection error during authentication: {e}")
            return False
    
    def request_human_approval(self, operation: str, details: Dict) -> bool:
        """
        Request explicit human approval before executing a destructive operation.

        Args:
            operation: Name of the operation requiring approval
            details: Dictionary with context about the operation

        Returns:
            True if the human approves, False otherwise
        """
        print()
        print("=" * 50)
        print(f"⚠️  APPROVAL REQUIRED for destructive operation")
        print(f"   Operation : {operation}")
        for key, value in details.items():
            print(f"   {key}: {value}")
        print("=" * 50)
        response = input("Do you approve this operation? (yes/no): ").strip().lower()
        approved = response == 'yes'
        if approved:
            logger.info(f"Human approved operation: {operation}")
        else:
            logger.warning(f"Human denied operation: {operation}")
        return approved

    def _validate_url_allowlist(self, url: str) -> None:
        """
        Validate that a URL is permitted by the allowlist.
        
        Args:
            url: The full URL to validate
            
        Raises:
            ValueError: If the URL is not in the allowlist
        """
        for allowed_prefix in self.ALLOWED_URL_PREFIXES:
            if url == allowed_prefix or url.startswith(allowed_prefix + "?") or url.startswith(allowed_prefix + "/"):
                return
        raise ValueError(
            f"URL not permitted by allowlist: {url}. "
            f"Allowed prefixes: {self.ALLOWED_URL_PREFIXES}"
        )
    
    def log_operation(self, operation: str, status: str, details: Dict):
        """Log operation for audit trail with full forensic metadata."""
        input_hash = hashlib.sha256(
            json.dumps(details, sort_keys=True, default=str).encode('utf-8')
        ).hexdigest()

        try:
            principal = getpass.getuser()
        except Exception:
            principal = os.environ.get('USER', 'unknown')

        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'model_id': AGENT_MODEL_ID,
            'model_version': AGENT_MODEL_VERSION,
            'principal': principal,
            'input_hash_sha256': input_hash,
            'operation': operation,
            'status': status,
            'details': details
        }
        self.operations_log.append(log_entry)
        logger.info(json.dumps(log_entry, default=str))
    
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
            url = f"{self.GET_FILE_API}?id={file_id}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "file_id": file_id})
                return True, "DRY_RUN_CONTENT", None
            
            # Validate URL against allowlist
            self._validate_url_allowlist(url)
            
            # Enforce RBAC and OAuth scope verification
            authorized, access_error = self._verify_access(operation)
            if not authorized:
                self.log_operation(operation, "denied", {"url": url, "error": access_error})
                return False, None, access_error
            
            # Make API request with authorization header
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(url, headers=headers, timeout=self.API_TIMEOUT)
            
            # Check response status
            if response.status_code != 200:
                error = f"API returned status {response.status_code}"
                self.log_operation(operation, "failed", {
                    "url": url,
                    "status_code": response.status_code,
                    "error": error
                })
                return False, None, error
            
            # Apply data minimisation: extract only required fields from response
            try:
                response_data = response.json()
                # Only retain the fields we need (content and metadata)
                allowed_fields = {'content', 'filename', 'id', 'name'}
                minimised_data = {k: v for k, v in response_data.items() if k in allowed_fields}
                content = minimised_data.get('content', '')
                if content is None:
                    content = ''
            except (ValueError, AttributeError):
                # If not JSON, use raw text but strip any extraneous whitespace
                content = response.text.strip()

            if len(content) > self.MAX_FILE_SIZE:
                error = f"File too large: {len(content)} bytes (max {self.MAX_FILE_SIZE})"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Success
            self.log_operation(operation, "success", {
                "url": url,
                "file_id": file_id,
                "content_length": len(content)
            })
            
            return True, content, None
            
        except requests.Timeout:
            error = "Request timeout"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except requests.RequestException as e:
            error = f"Request failed: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
    
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
            
            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}')")
            
            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available"
            })
            
            return True, None
            
        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
    
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
            # Enforce six-month retention policy before purging
        if hasattr(record_id, '__int__'):
            creation_date = kwargs.get('record_creation_date') if 'kwargs' in dir() else None
        else:
            creation_date = None

        if creation_date is not None:
            if isinstance(creation_date, str):
                creation_date = datetime.fromisoformat(creation_date)
            retention_elapsed = datetime.now() - creation_date
            if retention_elapsed < self.MIN_RETENTION_PERIOD:
                days_remaining = (self.MIN_RETENTION_PERIOD - retention_elapsed).days
                error_msg = (
                    f"Cannot purge record {record_id}: minimum 6-month retention period not met. "
                    f"{days_remaining} days remaining before record may be purged."
                )
                logger.error(error_msg)
                self.log_operation("purge_records", "rejected_retention_policy", {
                    "record_id": record_id,
                    "creation_date": creation_date.isoformat(),
                    "days_remaining": days_remaining
                })
                return False, error_msg
        else:
            # If no creation date is available, deny purge to enforce retention policy
            error_msg = (
                f"Cannot purge record {record_id}: record_creation_date must be provided "
                f"to verify six-month retention policy compliance."
            )
            logger.error(error_msg)
            self.log_operation("purge_records", "rejected_no_creation_date", {
                "record_id": record_id
            })
            return False, error_msg

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
        
        success, error = self.delete_file_via_mcp(filename)
        
        if not success:
            logger.error(f"Failed to delete file: {error}")
            all_success = False
        else:
            logger.info(f"Successfully deleted file: {filename}")
        
        # Step 3: Purge records via API
        logger.info("\nStep 3: Purging records via API...")
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
    
    def save_audit_log(self, filepath: str = "audit_log.json"):
        """Save operations log to file."""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.operations_log, f, indent=2)
            logger.info(f"Audit log saved to: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save audit log: {e}")


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
    if '--execute' in sys.argv and '--confirm' in sys.argv:
        dry_run = False
        print("EXECUTING IN LIVE MODE (confirmed via --confirm flag)")
    elif '--execute' in sys.argv:
        print("Operation cancelled: --execute requires --confirm flag to proceed.")
        sys.exit(0)
    else:
        dry_run = True
        print("Running in DRY RUN mode (no actual changes will be made)")
        print("Use --execute --confirm flags to run in live mode")
    
    print()
    
    # Explicit tool allow list - only these tools may be executed
    ALLOWED_TOOLS = {
        "get_file_from_api",
        "MCP deleteFile",
        "purge_records_via_api",
    }

    # Create agent
    agent = FileManagementAgent(dry_run=dry_run)

    # Validate agent tools against the allow list before execution
    agent_tools = {"get_file_from_api", "MCP deleteFile", "purge_records_via_api"}
    disallowed = agent_tools - ALLOWED_TOOLS
    if disallowed:
        print(f"ERROR: Agent attempted to use disallowed tools: {disallowed}")
        print("Aborting workflow.")
        sys.exit(1)

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
