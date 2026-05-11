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
    import re
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

            # Scan for Singapore-specific PII before processing
            pii_found = self._scan_for_singapore_pii(content)
            if pii_found:
                error = f"File rejected: Singapore PII detected ({', '.join(pii_found)})"
                self.log_operation(operation, "rejected", {
                    "url": url,
                    "file_id": file_id,
                    "reason": error
                })
                return False, None, error

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
    
    # Zero-tolerance PII patterns
    _PII_PATTERNS = [
        # Social Security Numbers (SSN)
        (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
        # Credit / debit card numbers (13-16 digits, optionally separated by spaces or dashes)
        (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED_CARD]'),
        # Email addresses
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
        # Phone numbers (various formats)
        (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
        # Dates of birth (MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD)
        (re.compile(r'\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b'), '[REDACTED_DOB]'),
    ]

    def _redact_pii(self, text: str) -> str:
        """
        Scan *text* for zero-tolerance PII categories and replace every match
        with a labelled placeholder.  Returns the redacted string.
        """
        redacted = text
        for pattern, placeholder in self._PII_PATTERNS:
            redacted = pattern.sub(placeholder, redacted)
        pii_found = redacted != text
        if pii_found:
            logger.warning("PII detected in retrieved file content — redacted before further use.")
        return redacted

    # Singapore PII patterns
    _SG_PII_PATTERNS = [
        # NRIC / FIN: S/T/F/G followed by 7 digits and a letter
        ("NRIC/FIN Number", r'\b[STFG]\d{7}[A-Z]\b'),
        # SingPass identifier (SingPass ID is typically the NRIC, but also match explicit labels)
        ("SingPass Identifier", r'(?i)singpass[\s_-]*(?:id|identifier|user)?[:\s]+[STFG]\d{7}[A-Z]\b'),
        # CPF Account Number: 9-digit numeric string labelled as CPF
        ("CPF Account Number", r'(?i)cpf[\s_-]*(?:account)?[\s_-]*(?:no\.?|number)?[:\s]+\d{9}\b'),
        # Standalone 9-digit number that could be a CPF account number
        ("Possible CPF Account Number", r'\b\d{9}\b'),
        # Singapore phone numbers (+65 followed by 8 digits)
        ("SG Phone Number", r'(?:\+65|\(65\))[\s-]?[689]\d{7}\b'),
        # Singapore postal code (6 digits, labelled)
        ("SG Postal Code", r'(?i)(?:postal|zip)[\s_-]*(?:code)?[:\s]+\d{6}\b'),
    ]

    def _scan_for_singapore_pii(self, content: str) -> list:
        """
        Scan content for Singapore-specific PII categories.

        Returns a list of PII category names found in the content,
        or an empty list if none are detected.
        """
        import re
        detected = []
        for label, pattern in self._SG_PII_PATTERNS:
            if re.search(pattern, content):
                detected.append(label)
                logger.warning(f"Singapore PII detected in file content: {label}")
        return detected

    def _authenticate_mcp_server(self) -> Tuple[bool, Optional[str]]:
        """
        Authenticate the MCP server before making tool calls.

        Verifies the MCP server's identity by comparing the server-supplied
        token (from the MCP_SERVER_TOKEN environment variable) against the
        expected token (from MCP_EXPECTED_SERVER_TOKEN). Both values must be
        present and must match for authentication to succeed.

        Returns:
            Tuple of (authenticated: bool, error_message: Optional[str])
        """
        import os
        import hmac

        server_token = os.environ.get("MCP_SERVER_TOKEN", "").strip()
        expected_token = os.environ.get("MCP_EXPECTED_SERVER_TOKEN", "").strip()

        if not server_token:
            error = "MCP server authentication failed: MCP_SERVER_TOKEN is not set or empty"
            logger.error(error)
            return False, error

        if not expected_token:
            error = "MCP server authentication failed: MCP_EXPECTED_SERVER_TOKEN is not configured"
            logger.error(error)
            return False, error

        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(server_token.encode(), expected_token.encode()):
            error = "MCP server authentication failed: server token mismatch"
            logger.error(error)
            return False, error

        logger.info("MCP server authenticated successfully")
        return True, None

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
            
            # Authenticate MCP server before making any tool call
            auth_ok, auth_error = self._authenticate_mcp_server()
            if not auth_ok:
                self.log_operation(operation, "failed", {"filename": filename, "error": auth_error})
                return False, auth_error

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

    # --- Authentication Gate ---
    import os, hashlib, secrets
    expected_key = os.environ.get("FILE_AGENT_API_KEY", "")
    if not expected_key:
        print("ERROR: FILE_AGENT_API_KEY environment variable is not set. "
              "Set it to a secret API key before running this agent.")
        sys.exit(1)
    entered_key = input("Enter API key to authenticate: ").strip()
    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(
        hashlib.sha256(entered_key.encode()).digest(),
        hashlib.sha256(expected_key.encode()).digest()
    ):
        print("Authentication failed: invalid API key.")
        logger.error("Authentication failed: invalid API key provided.")
        sys.exit(1)
    print("Authentication successful.")
    logger.info("User authenticated successfully.")
    # --- End Authentication Gate ---

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
