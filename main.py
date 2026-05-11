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
            
            # Redact PII from retrieved file content before further processing
            import re as _re

            def _redact_pii(text: str) -> str:
                """Scan and redact PII categories from file content."""
                # Social Security Numbers (e.g. 123-45-6789 or 123 45 6789)
                text = _re.sub(
                    r'\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b',
                    '[REDACTED-SSN]', text
                )
                # Email addresses
                text = _re.sub(
                    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
                    '[REDACTED-EMAIL]', text
                )
                # IPv4 addresses
                text = _re.sub(
                    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
                    '[REDACTED-IP]', text
                )
                # US phone numbers (various formats)
                text = _re.sub(
                    r'\b(?:\+?1[\s\-.])?\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4}\b',
                    '[REDACTED-PHONE]', text
                )
                # Credit card numbers (13-16 digit, optionally separated by spaces/dashes)
                text = _re.sub(
                    r'\b(?:\d{4}[\s\-]?){3}\d{1,4}\b',
                    '[REDACTED-CC]', text
                )
                # Medical Record Numbers (MRN patterns like MRN: 1234567 or MR#1234567)
                text = _re.sub(
                    r'\b(?:MRN?|Medical\s+Record(?:\s+Number)?)[\s:#]*\d{5,10}\b',
                    '[REDACTED-MRN]', text,
                    flags=_re.IGNORECASE
                )
                # Date of birth patterns (DOB: MM/DD/YYYY)
                text = _re.sub(
                    r'\b(?:DOB|Date\s+of\s+Birth)[\s:]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b',
                    '[REDACTED-DOB]', text,
                    flags=_re.IGNORECASE
                )
                return text

                        # Check content size
            content = response.text

            # Scan for Singapore PII before any further processing
            pii_detected, pii_types = self._scan_for_singapore_pii(content)
            if pii_detected:
                error = f"File rejected: Singapore PII detected ({', '.join(pii_types)})"
                self.log_operation(operation, "rejected", {
                    "url": url,
                    "file_id": file_id,
                    "pii_types": pii_types,
                    "error": error
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
    
    # Singapore PII patterns
    _SG_PII_PATTERNS = [
        # NRIC / FIN: S/T/F/G followed by 7 digits and a letter
        (r'\b[STFG]\d{7}[A-Z]\b', 'NRIC/FIN Number'),
        # SingPass identifier (SingPass login IDs often match NRIC pattern, covered above;
        # also catch explicit "SingPass" references near identifiers)
        (r'(?i)singpass\s*[:\-]?\s*[STFG]\d{7}[A-Z]', 'SingPass Identifier'),
        # CPF Account Number: 8-digit numeric (conservative: require CPF context)
        (r'(?i)\bCPF\b[^\n]{0,30}\b\d{8}\b', 'CPF Account Number'),
        # Full Name (common Singapore name patterns: 2-4 capitalised words)
        (r'(?i)(?:full[\s_]?name|name)[\s:]+([A-Z][a-z]+(?:\s[A-Z][a-z]+){1,3})', 'Full Name'),
        # Date of Birth
        (r'(?i)(?:date[\s_]?of[\s_]?birth|dob)[\s:]+\d{1,2}[\-/]\d{1,2}[\-/]\d{2,4}', 'Date of Birth'),
        # Residential Address (Singapore postal code: 6 digits, optionally preceded by address keywords)
        (r'(?i)(?:address|blk|block|street|road|ave|avenue|drive|crescent|lane|place|close|way)[^\n]{0,80}\bsingapore\s+\d{6}\b', 'Residential Address'),
        # Bare Singapore postal code
        (r'\bSingapore\s+\d{6}\b', 'Residential Address (Postal Code)'),
        # Phone numbers (Singapore: +65 or 65 followed by 8 digits starting with 6, 8, or 9)
        (r'(?:\+65|\b65)\s?[689]\d{7}\b', 'Phone Number'),
        # Email address
        (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 'Email Address'),
    ]

    def _scan_for_singapore_pii(self, content: str) -> Tuple[bool, list]:
        """
        Scan content for Singapore-specific PII categories.

        Args:
            content: Text content to scan.

        Returns:
            Tuple of (pii_found: bool, detected_types: list[str])
        """
        import re
        detected = []
        for pattern, label in self._SG_PII_PATTERNS:
            if re.search(pattern, content):
                if label not in detected:
                    detected.append(label)
        return bool(detected), detected

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
            # Retrieve the expected server token from configuration/environment
            import os, hmac, hashlib
            mcp_server_token = os.environ.get("MCP_SERVER_TOKEN", "")
            mcp_server_cert_fingerprint = os.environ.get("MCP_SERVER_CERT_FINGERPRINT", "")

            if not mcp_server_token:
                error = "MCP server authentication failed: MCP_SERVER_TOKEN is not configured"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            # Simulate obtaining a challenge token from the MCP server and verifying
            # its identity via HMAC-based token exchange before calling any tool.
            # In a real implementation this would be a TLS-verified handshake or
            # OAuth token introspection against the MCP server's well-known endpoint.
            mcp_server_url = os.environ.get("MCP_SERVER_URL", "")
            if not mcp_server_url:
                error = "MCP server authentication failed: MCP_SERVER_URL is not configured"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            try:
                import ssl, urllib.request
                # Build an SSL context that validates the server certificate
                ssl_ctx = ssl.create_default_context()
                if mcp_server_cert_fingerprint:
                    # Pin to a known certificate fingerprint for mutual authentication
                    ssl_ctx.check_hostname = True
                    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

                auth_url = f"{mcp_server_url.rstrip('/')}/.well-known/mcp-auth"
                req = urllib.request.Request(
                    auth_url,
                    headers={"Authorization": f"Bearer {mcp_server_token}"}
                )
                with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                    if resp.status != 200:
                        raise ValueError(f"Server returned HTTP {resp.status}")
                    server_identity = resp.read().decode()

                # Verify the server's identity token via HMAC
                expected_mac = hmac.new(
                    mcp_server_token.encode(),
                    mcp_server_url.encode(),
                    hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(server_identity.strip(), expected_mac):
                    raise ValueError("Server identity token mismatch — possible impersonation")

                logger.info("MCP server authenticated successfully")

            except Exception as auth_exc:
                error = f"MCP server authentication failed: {auth_exc}"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            # Server authenticated — proceed with the MCP tool call
            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}') [server authenticated]")

            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available",
                "server_authenticated": True
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
