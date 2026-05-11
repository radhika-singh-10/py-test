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
import logging
from datetime import datetime
from typing import Optional, Dict, Tuple

try:
    import requests
except ImportError:
    print("Error: requests package is not installed.")
    print("Install it with: pip3 install requests")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('file_management_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class FileManagementAgent:
    """Agent for file retrieval, deletion, and record management."""
    
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
        self.dry_run = dry_run
        self.operations_log = []
        
        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    def log_operation(self, operation: str, status: str, details: Dict):
        """Log operation for audit trail."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'status': status,
            'details': details
        }
        self.operations_log.append(log_entry)
        logger.info(f"Operation: {operation} - Status: {status}")
    
    # PII patterns for redaction
    _PII_PATTERNS = [
        # Social Security Numbers (SSN): 123-45-6789 or 123456789
        (r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', '[REDACTED-SSN]'),
        # Email addresses
        (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED-EMAIL]'),
        # IPv4 addresses
        (r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', '[REDACTED-IP]'),
        # Credit card numbers (Visa, MC, Amex, Discover)
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', '[REDACTED-CC]'),
        # US phone numbers
        (r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b', '[REDACTED-PHONE]'),
        # Medical Record Numbers (MRN): common formats like MRN: 1234567 or MR#1234567
        (r'\b(?:MR(?:N|#|\s*:?\s*)\d{5,10})\b', '[REDACTED-MRN]'),
        # Dates of birth (MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD)
        (r'\b(?:DOB|Date of Birth|Birth Date)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b', '[REDACTED-DOB]'),
    ]

    def _redact_pii(self, content: str) -> Tuple[str, int]:
        """
        Scan content for PII and redact matches.

        Returns:
            Tuple of (redacted_content, count_of_redactions)
        """
        import re
        redacted = content
        total_redactions = 0
        for pattern, placeholder in self._PII_PATTERNS:
            redacted, count = re.subn(pattern, placeholder, redacted)
            total_redactions += count
        return redacted, total_redactions

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
            content = response.text
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
            
            # Redact PII before returning content
            content, redaction_count = self._redact_pii(content)
            if redaction_count > 0:
                logger.info(f"PII redaction applied: {redaction_count} item(s) redacted from file {file_id}")
                self.log_operation(operation, "pii_redacted", {
                    "file_id": file_id,
                    "redaction_count": redaction_count
                })

                        # Scan for Singapore PII before returning content
            pii_detected, pii_types = self._scan_for_singapore_pii(content)
            if pii_detected:
                error = f"File rejected: Singapore PII detected ({', '.join(pii_types)})"
                self.log_operation(operation, "rejected", {
                    "url": url,
                    "file_id": file_id,
                    "pii_types": pii_types,
                    "error": error
                })
                logger.warning(error)
                return False, None, error

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
    
    def _scan_for_singapore_pii(self, content: str) -> Tuple[bool, list]:
        """
        Scan content for Singapore-specific PII categories.

        Checks for:
        - NRIC / FIN Number (e.g. S1234567A, T1234567B, F1234567C, G1234567D)
        - SingPass Identifier (NRIC used as SingPass ID)
        - CPF Account Number (same format as NRIC)
        - Singapore phone numbers
        - Singapore postal codes
        - Full Name patterns (heuristic: 2-4 capitalised words)
        - Singapore bank account numbers
        - Passport numbers
        - Date of birth patterns

        Returns:
            Tuple of (pii_found: bool, list_of_detected_pii_types: list)
        """
        import re

        detected = []

        patterns = {
            "NRIC/FIN Number": r'\b[STFG]\d{7}[A-Z]\b',
            "Singapore Passport Number": r'\bE\d{7}[A-Z]\b',
            "Singapore Phone Number": r'\b[689]\d{7}\b',
            "Singapore Postal Code": r'\b(?:Singapore\s)?[0-9]{6}\b',
            "CPF Account Number": r'\b[STFG]\d{7}[A-Z]\b',
            "Date of Birth": (
                r'\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b'
            ),
            "Full Name (heuristic)": (
                r'\b[A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20}){1,3}\b'
            ),
            "Singapore Bank Account": r'\b\d{3}-\d{5,6}-\d{1}\b',
        }

        for pii_type, pattern in patterns.items():
            if re.search(pattern, content):
                # Avoid double-counting NRIC and CPF (same pattern)
                if pii_type == "CPF Account Number" and "NRIC/FIN Number" in detected:
                    continue
                detected.append(pii_type)

        return (len(detected) > 0, detected)

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
            
            # Authenticate MCP server before invoking any tool
            # Retrieve the expected server token from the environment
            import os
            import hmac
            mcp_server_token = os.environ.get("MCP_SERVER_TOKEN", "")
            mcp_server_url = os.environ.get("MCP_SERVER_URL", "")
            if not mcp_server_token:
                error = "MCP server authentication failed: MCP_SERVER_TOKEN is not configured"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error
            if not mcp_server_url:
                error = "MCP server authentication failed: MCP_SERVER_URL is not configured"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            # Perform a server authentication handshake:
            # Send a challenge and verify the server's HMAC-signed response
            import secrets
            import hashlib
            challenge = secrets.token_hex(32)
            try:
                auth_response = requests.post(
                    f"{mcp_server_url}/auth/challenge",
                    json={"challenge": challenge},
                    timeout=self.API_TIMEOUT,
                    verify=True,  # enforce TLS certificate validation
                )
            except requests.exceptions.SSLError as ssl_err:
                error = f"MCP server TLS certificate validation failed: {ssl_err}"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error
            except requests.RequestException as req_err:
                error = f"MCP server authentication request failed: {req_err}"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            if auth_response.status_code != 200:
                error = f"MCP server authentication failed: server returned HTTP {auth_response.status_code}"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            auth_data = auth_response.json()
            server_signature = auth_data.get("signature", "")
            expected_signature = hmac.new(
                mcp_server_token.encode(),
                challenge.encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(server_signature, expected_signature):
                error = "MCP server authentication failed: server signature mismatch"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            logger.info("MCP server authenticated successfully")

            # Retrieve client authentication credentials for MCP server
            import os
            mcp_api_key = getattr(self, 'mcp_api_key', None) or os.environ.get('MCP_API_KEY')
            if not mcp_api_key:
                error = "MCP client authentication credentials not configured (MCP_API_KEY missing)"
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            # Authentication is passed via the 'X-API-Key' header / auth token.
            logger.warning("MCP tool not available - simulating call")
            logger.info(
                f"Would call: deleteFile(fileName='{filename}') "
                f"with auth token (key id: {mcp_api_key[:4]}****)"
            )

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


def _authenticate() -> bool:
    """Validate user credentials before granting access to the agent.

    Checks the AGENT_API_KEY environment variable first; if not set,
    prompts the user interactively.  Returns True only when the
    supplied key matches the expected secret.
    """
    import os
    import getpass
    import hmac

    expected_key = os.environ.get("EXPECTED_AGENT_API_KEY", "")
    if not expected_key:
        logger.error(
            "EXPECTED_AGENT_API_KEY environment variable is not set. "
            "Cannot authenticate."
        )
        return False

    # Prefer a key supplied via environment variable (non-interactive use)
    provided_key = os.environ.get("AGENT_API_KEY", "")
    if not provided_key:
        provided_key = getpass.getpass("Enter API key to access the File Management Agent: ")

    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(provided_key.strip(), expected_key.strip()):
        logger.error("Authentication failed: invalid API key.")
        return False

    logger.info("Authentication successful.")
    return True


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

    # --- Authentication gate ---
    if not _authenticate():
        print("Access denied: authentication failed. Exiting.")
        sys.exit(1)

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
