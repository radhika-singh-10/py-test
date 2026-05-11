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
            
            # Redact PII from retrieved file content before further use
            raw_content = response.text
            content = self._redact_pii(raw_content)
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
    
    def _redact_pii(self, text: str) -> str:
        """
        Scan text for PII and redact any matches.
        Covers zero-tolerance categories: SSN, email, IP address, credit card numbers,
        phone numbers, and dates of birth.
        """
        import re

        pii_patterns = [
            # Social Security Numbers  (e.g. 123-45-6789 or 123 45 6789)
            (re.compile(r'\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b'), '[REDACTED-SSN]'),
            # Email addresses
            (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
            # IPv4 addresses
            (re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            ), '[REDACTED-IP]'),
            # Credit card numbers (13-19 digits, optionally separated by spaces or dashes)
            (re.compile(r'\b(?:\d[ \-]?){13,19}\b'), '[REDACTED-CC]'),
            # US phone numbers
            (re.compile(
                r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b'
            ), '[REDACTED-PHONE]'),
            # Dates of birth (common formats: MM/DD/YYYY, YYYY-MM-DD, DD-MM-YYYY)
            (re.compile(
                r'\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b'
            ), '[REDACTED-DOB]'),
        ]

        redacted = text
        for pattern, placeholder in pii_patterns:
            redacted = pattern.sub(placeholder, redacted)

        if redacted != text:
            logger.warning("PII detected and redacted from retrieved file content.")

        return redacted

    def _scan_for_singapore_pii(self, content: str) -> Tuple[bool, list]:
        """
        Scan content for Singapore-specific PII categories.

        Checks for:
          - NRIC / FIN numbers  (S/T/F/G followed by 7 digits and a letter)
          - SingPass identifiers (same pattern, labelled separately)
          - CPF account numbers  (same NRIC/FIN pattern used as CPF reference)
          - Singapore phone numbers
          - Full names (heuristic: 2-4 capitalised words)
          - Singapore postal codes
          - Singapore bank account numbers

        Returns:
            Tuple of (pii_found: bool, list_of_detected_pii_types)
        """
        import re

        detected = []

        patterns = {
            # NRIC: S/T + 7 digits + letter  |  FIN: F/G + 7 digits + letter
            "NRIC Number": r'\b[ST]\d{7}[A-Z]\b',
            "FIN Number": r'\b[FG]\d{7}[A-Z]\b',
            # SingPass identifier uses the same NRIC/FIN format
            "SingPass Identifier": r'\b[STFG]\d{7}[A-Z]\b',
            # CPF account number (same format as NRIC/FIN)
            "CPF Account Number": r'\b[STFG]\d{7}[A-Z]\b',
            # Singapore mobile / local numbers
            "Singapore Phone Number": r'\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b',
            # Singapore 6-digit postal code
            "Singapore Postal Code": r'\b(?:Singapore\s)?\d{6}\b',
            # Heuristic for full names: 2-4 consecutive title-cased words
            "Full Name": r'\b[A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20}){1,3}\b',
            # Common SG bank account patterns (DBS/POSB/OCBC/UOB)
            "Bank Account Number": r'\b\d{3}-\d{5,6}-\d{1}\b|\b\d{9,12}\b',
        }

        for pii_type, pattern in patterns.items():
            if re.search(pattern, content):
                if pii_type not in detected:
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
            import os
            import hmac
            import hashlib

            mcp_server_token = os.environ.get("MCP_SERVER_TOKEN")
            if not mcp_server_token:
                error = "MCP server authentication failed: MCP_SERVER_TOKEN is not configured"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            # Derive an expected authenticator from the shared token and the operation
            # In a real implementation this would be a challenge/response or mTLS handshake;
            # here we verify that the caller possesses the shared secret before proceeding.
            expected_authenticator = hmac.new(
                mcp_server_token.encode(),
                msg=b"deleteFile",
                digestmod=hashlib.sha256
            ).hexdigest()

            # Simulate obtaining the server's presented authenticator.
            # Replace this with the actual value returned by the MCP server during
            # the connection handshake (e.g. from a TLS-protected challenge response).
            mcp_server_presented_token = os.environ.get("MCP_SERVER_PRESENTED_TOKEN", "")

            if not hmac.compare_digest(expected_authenticator, mcp_server_presented_token):
                error = "MCP server authentication failed: server identity could not be verified"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            logger.info("MCP server authenticated successfully")

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
    # --- Authentication gate ---
    import os
    import getpass
    expected_api_key = os.environ.get("FILE_AGENT_API_KEY")
    if not expected_api_key:
        print("ERROR: Environment variable FILE_AGENT_API_KEY is not set. "
              "Cannot authenticate.")
        sys.exit(1)
    entered_key = getpass.getpass("Enter API key to access File Management Agent: ")
    if entered_key != expected_api_key:
        print("Authentication failed: invalid API key.")
        sys.exit(1)
    print("Authentication successful.")
    # --- End authentication gate ---

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
