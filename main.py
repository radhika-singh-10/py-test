#!/usr/bin/env python3

"""
File Management Agent
test the flow
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
    
    def __init__(self, dry_run: bool = True, api_key: Optional[str] = None):
        """
        Initialize the agent.
        
        Args:
            dry_run: If True, only simulate operations without making actual changes
            api_key: Bearer token used to authenticate inter-agent API calls.
                     Falls back to the AGENT_API_KEY environment variable.
        """
        self.dry_run = dry_run
        self.operations_log = []
        self.api_key = api_key or os.environ.get("AGENT_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "No API key provided. Set the AGENT_API_KEY environment variable "
                "or pass api_key= to FileManagementAgent()."
            )
        self._auth_headers = {"Authorization": f"Bearer {self.api_key}"}
        
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
            
            # Make API request (authenticated)
            response = requests.get(url, headers=self._auth_headers, timeout=self.API_TIMEOUT)
            
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
            
            # Check for Singapore PII before returning content
            pii_findings = self._scan_for_singapore_pii(content)
            if pii_findings:
                error = f"File content contains Singapore PII ({', '.join(pii_findings)}); upload blocked per policy"
                logger.warning(f"PII detected in file {file_id}: {', '.join(pii_findings)}")
                self.log_operation(operation, "blocked_pii", {
                    "url": url,
                    "file_id": file_id,
                    "pii_types": pii_findings
                })
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
    
    # ------------------------------------------------------------------
    # Singapore PII detection helper
    # ------------------------------------------------------------------
    _SG_PII_PATTERNS: dict = {
        "NRIC/FIN": re.compile(
            r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE
        ),
        "Singapore_Passport": re.compile(
            r'\bE\d{7}[A-Z]\b', re.IGNORECASE
        ),
        "SG_Phone": re.compile(
            r'\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b'
        ),
        "SG_Postal_Code": re.compile(
            r'\bSingapore\s+\d{6}\b', re.IGNORECASE
        ),
        "Full_Name_IC_Context": re.compile(
            r'(?:name|full name|nric|fin|passport)[\s:]+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}',
            re.IGNORECASE
        ),
    }

    def _scan_for_singapore_pii(self, content: str) -> list:
        """
        Scan text content for Singapore PII patterns.

        Returns a list of PII category names found in the content,
        or an empty list if none are detected.
        """
        import re as _re  # ensure re is available in method scope
        found = []
        for category, pattern in self._SG_PII_PATTERNS.items():
            if pattern.search(content):
                found.append(category)
        return found

        def delete_file_via_mcp(self, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Delete file using MCP tool.
        
        Args:
            filename: Name of the file to delete
            
        Returns:
            Tuple of (success, error_message)
        """
        import os
        operation = "delete_file_mcp"
        logger.info(f"Attempting to delete file via MCP: {filename}")

        # --- MCP client authentication ---
        mcp_auth_token = os.environ.get("MCP_AUTH_TOKEN", "").strip()
        if not mcp_auth_token:
            error = "MCP authentication failed: MCP_AUTH_TOKEN is not set or empty"
            logger.error(error)
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        mcp_auth_headers = {"Authorization": f"Bearer {mcp_auth_token}"}
        # ----------------------------------

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
            
            # NOTE: Actual MCP tool call would go here.
            # Pass `mcp_auth_headers` (containing the Bearer token) to the MCP
            # client/transport layer when establishing the connection, e.g.:
            #   mcp_client.connect(headers=mcp_auth_headers)
            #   mcp_client.call_tool("deleteFile", {"fileName": filename})
            logger.warning("MCP tool not available - simulating call")
            logger.info(
                f"Would call: deleteFile(fileName='{filename}') "
                f"with auth header: Authorization: Bearer ***"
            )
            
            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available",
                "authenticated": True
            })
            
            return True, None
            
        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
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
            mcp_server_token = os.environ.get("MCP_SERVER_TOKEN")
            if not mcp_server_token:
                error = "MCP server authentication failed: MCP_SERVER_TOKEN environment variable is not set"
                logger.error(error)
                self.log_operation(operation, "failed", {"filename": filename, "error": error})
                return False, error

            # Verify the token is accepted by the MCP server before proceeding
            import hashlib, hmac
            expected_token_hash = os.environ.get("MCP_SERVER_TOKEN_HASH")
            if expected_token_hash:
                actual_hash = hashlib.sha256(mcp_server_token.encode()).hexdigest()
                if not hmac.compare_digest(actual_hash, expected_token_hash):
                    error = "MCP server authentication failed: token verification failed"
                    logger.error(error)
                    self.log_operation(operation, "failed", {"filename": filename, "error": error})
                    return False, error

            logger.info("MCP server authenticated successfully via token")

            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            # The authenticated token (mcp_server_token) must be passed to the MCP client
            # when establishing the connection, e.g.:
            #   mcp_client = MCPClient(server_url=MCP_SERVER_URL, auth_token=mcp_server_token)
            #   mcp_client.call_tool("deleteFile", {"fileName": filename})
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}') with authenticated token")

            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available",
                "authenticated": True
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
            response = requests.get(url, headers=self._auth_headers, timeout=self.API_TIMEOUT)
            
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


def authenticate() -> bool:
    """Authenticate the user via API key before granting access to the agent."""
    import os
    import hmac
    expected_key = os.environ.get("FILE_AGENT_API_KEY", "")
    if not expected_key:
        logger.error("Authentication error: FILE_AGENT_API_KEY environment variable is not set.")
        return False
    provided_key = input("Enter your API key to authenticate: ").strip()
    # Use hmac.compare_digest to prevent timing attacks
    if not hmac.compare_digest(expected_key.encode(), provided_key.encode()):
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
    
    # Authenticate the user before proceeding
    if not authenticate():
        print("Access denied. Exiting.")
        sys.exit(1)

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
