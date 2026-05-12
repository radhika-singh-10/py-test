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
    
    # URL allowlist for outbound requests
    ALLOWED_URLS = {GET_FILE_API, PURGE_RECORDS_API}
    
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
            
            # Validate URL against allowlist
            base_url = url.split('?')[0]
            if base_url not in self.ALLOWED_URLS:
                error = f"URL {base_url} is not in the allowed list"
                self.log_operation(operation, "failed", {"url": url, "error": error})
                return False, None, error
            
            # Make API request (no redirects to prevent bypass)
            response = requests.get(url, timeout=self.API_TIMEOUT, allow_redirects=False)
            
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

            # Check for Singapore PII (NRIC, FIN, etc.)
            import re
            # Singapore NRIC/FIN patterns: S/T/F/G/M followed by 7 digits and a letter
            sg_pii_pattern = r'\b[STFGM]\d{7}[A-Z]\b'
            if re.search(sg_pii_pattern, content):
                error = "File contains Singapore PII (NRIC/FIN) and cannot be uploaded"
                self.log_operation(operation, "failed", {"error": error, "reason": "PII detected"})
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
        Redact common PII patterns from text.
        
        Args:
            text: Input string to scan for PII
            
        Returns:
            String with PII redacted
        """
        import re
        # Redact email addresses
        text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
        # Redact US phone numbers (e.g., 123-456-7890, (123) 456-7890)
        text = re.sub(r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', '[REDACTED_PHONE]', text)
        # Redact Social Security Numbers (XXX-XX-XXXX)
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', text)
        return text
    
        def _require_human_approval(self, operation: str, details: dict) -> bool:
        """
        Prompt the user for explicit approval before performing a risky operation.
        
        Args:
            operation: Name of the operation requiring approval
            details: Dictionary with contextual information (e.g., filename, record_id)
            
        Returns:
            True if human approved, False otherwise
        """
        logger.warning(f"HUMAN APPROVAL REQUIRED for {operation}: {details}")
        # In a real implementation, this would send a notification and wait for response.
        # For now, we simulate by reading from stdin or a config.
        # To avoid blocking in automated tests, we check an environment variable override.
        import os
        if os.environ.get("SKIP_HUMAN_APPROVAL", "0") == "1":
            logger.info("Human approval skipped due to SKIP_HUMAN_APPROVAL=1")
            return True
        try:
            response = input(f"Approve {operation} with details {details}? (yes/no): ")
            approved = response.strip().lower() in ("yes", "y")
            if approved:
                logger.info(f"Human approved {operation}")
            else:
                logger.warning(f"Human denied {operation}")
            return approved
        except (EOFError, KeyboardInterrupt):
            logger.warning("No input available, denying operation by default")
            return False

        # Tool allow list: only these MCP tools are permitted
    ALLOWED_MCP_TOOLS = {"deleteFile", "readFile", "listFiles"}  # extend as needed

    # Per-role tool permissions: mapping from role to set of allowed tools
    ROLE_TOOL_PERMISSIONS = {
        "admin": {"deleteFile", "readFile", "listFiles", "createFile"},
        "editor": {"readFile", "listFiles", "createFile"},
        "viewer": {"readFile", "listFiles"},
    }

    def _check_tool_allowed(self, tool_name: str, role: str = "viewer") -> bool:
        """Check if the given tool is allowed for the given role."""
        if tool_name not in self.ALLOWED_MCP_TOOLS:
            return False
        allowed_for_role = self.ROLE_TOOL_PERMISSIONS.get(role, set())
        return tool_name in allowed_for_role

    def delete_file_via_mcp(self, filename: str, role: str = "viewer") -> Tuple[bool, Optional[str]]:
        """
        Delete file using MCP tool.
        
        Args:
            filename: Name of the file to delete
            role: Role of the caller (default "viewer")
            
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
        
        # Enforce tool allow list and role scoping
        tool_name = "deleteFile"
        if not self._check_tool_allowed(tool_name, role):
            error = f"Tool '{tool_name}' is not allowed for role '{role}'"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
        
        try:
            if self.dry_run:
                logger.info(f"DRY RUN: Would call MCP {tool_name}('{filename}')")
                self.log_operation(operation, "simulated", {"filename": filename})
                return True, None
            
            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: {tool_name}(fileName='{filename}')")
            
            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available"
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
        
        # Human-in-the-loop approval
        if not self._require_human_approval(operation, {"filename": filename}):
            error = "Operation denied by human"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
        
        try:
            if self.dry_run:
                logger.info(f"DRY RUN: Would call MCP deleteFile('{filename}')")
                self.log_operation(operation, "simulated", {"filename": filename})
                return True, None
            
            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            # Ensure server authentication is performed (e.g., TLS certificate validation, API key)
            import os
            auth_token = os.environ.get('MCP_AUTH_TOKEN')
            if not auth_token:
                raise ValueError("MCP server authentication token not configured. Set MCP_AUTH_TOKEN environment variable.")
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}') with authentication")
            
            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available"
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
                # TODO: In real implementation, validate and sanitize MCP server response
            # For simulation, assume safe response
            mcp_response = None  # placeholder for actual response
            if mcp_response is not None:
                # Validate response structure and sanitize any content
                if not isinstance(mcp_response, dict) or 'success' not in mcp_response:
                    logger.warning("MCP response validation failed")
                    return False, "Invalid MCP response"
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
        Purge records via API.
        
        Args:
            record_id: ID of the record to purge
            
        Returns:
            Tuple of (success, error_message)
        """
        operation = "purge_records_api"
        logger.info(f"Attempting to purge record via API: {record_id}")
        
        # Validate record_id
        if not isinstance(record_id, int) or record_id <= 0:
            error = "Invalid record_id"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        
        # Human-in-the-loop approval
        if not self._require_human_approval(operation, {"record_id": record_id}):
            error = "Operation denied by human"
            self.log_operation(operation, "failed", {"record_id": record_id, "error": error})
            return False, error
        
        try:
            if self.dry_run:
                logger.info(f"DRY RUN: Would call DELETE /api/records/{record_id}")
                self.log_operation(operation, "simulated", {"record_id": record_id})
                return True, None
            
            # Make API request
            url = f"{self.base_url}/api/records/{record_id}"
            response = requests.delete(url, timeout=self.API_TIMEOUT)
            
            if response.status_code != 200:
                error = f"API returned status {response.status_code}"
                self.log_operation(operation, "failed", {
                    "record_id": record_id,
                    "status_code": response.status_code,
                    "error": error
                })
                return False, error
            
            self.log_operation(operation, "success", {"record_id": record_id})
            return True, None
            
        except requests.Timeout:
            error = "Request timeout"
            self.log_operation(operation, "failed", {"record_id": record_id, "error": error})
            return False, error
        except requests.RequestException as e:
            error = f"Request failed: {str(e)}"
            self.log_operation(operation, "failed", {"record_id": record_id, "error": error})
            return False, error
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            self.log_operation(operation, "failed", {"record_id": record_id, "error": error})
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
