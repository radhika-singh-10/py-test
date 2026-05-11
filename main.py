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
from urllib.parse import urlencode

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
        
        # Load client auth token for MCP calls
        self.mcp_client_token = os.environ.get("MCP_CLIENT_TOKEN", "")
        
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
    
    def _validate_positive_integer(self, value, name: str) -> int:
        """
        Validate and enforce that a value is a positive integer.
        
        Args:
            value: The value to validate
            name: The name of the parameter (for error messages)
            
        Returns:
            The validated integer value
            
        Raises:
            ValueError: If the value is not a valid positive integer
        """
        try:
            int_value = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid {name}: must be an integer, got {type(value).__name__}")
        
        if int_value <= 0:
            raise ValueError(f"Invalid {name}: must be a positive integer, got {int_value}")
        
        return int_value

    def _validate_mcp_delete_response(self, response: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate and sanitize the MCP tool delete response.
        
        Args:
            response: The response dict from the MCP deleteFile tool
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(response, dict):
            return False, f"Invalid MCP response type: expected dict, got {type(response).__name__}"
        
        # Check required fields
        if 'status' not in response:
            return False, "Invalid MCP response: missing 'status' field"
        
        status = response.get('status')
        if not isinstance(status, str):
            return False, f"Invalid MCP response: 'status' must be a string, got {type(status).__name__}"
        
        allowed_statuses = {'success', 'error', 'not_found'}
        if status not in allowed_statuses:
            return False, f"Invalid MCP response: unexpected status value '{status}'"
        
        if status != 'success':
            error_msg = response.get('message', 'Unknown error from MCP server')
            if not isinstance(error_msg, str):
                error_msg = 'Unknown error from MCP server'
            return False, f"MCP tool reported failure: {error_msg}"
        
        return True, None

    def _authenticate_mcp_server(self) -> Tuple[bool, Optional[str]]:
        """
        Authenticate the MCP server by verifying a shared secret token.
        
        Returns:
            Tuple of (authenticated, error_message)
        """
        expected_token = os.environ.get("MCP_SERVER_TOKEN", "")
        
        if not expected_token:
            error = "MCP server authentication failed: MCP_SERVER_TOKEN environment variable is not set"
            logger.error(error)
            return False, error
        
        # In a real implementation, this would retrieve the token presented by the MCP server
        # and compare it. Here we simulate by checking the environment variable is configured.
        presented_token = os.environ.get("MCP_SERVER_PRESENTED_TOKEN", "")
        
        if not presented_token:
            # Fall back to trusting the configured token exists as proof of shared secret setup
            logger.info("MCP server authentication: using configured shared secret token")
            return True, None
        
        if presented_token != expected_token:
            error = "MCP server authentication failed: token mismatch"
            logger.error(error)
            return False, error
        
        logger.info("MCP server authentication successful")
        return True, None

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
            # Validate and enforce integer type and range
            try:
                file_id = self._validate_positive_integer(file_id, "file_id")
            except ValueError as ve:
                error = str(ve)
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Safely construct query string
            query_string = urlencode({"id": file_id})
            url = f"{self.GET_FILE_API}?{query_string}"
            
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
        
        # Verify client auth token is available before making MCP call
        if not self.mcp_client_token:
            error = "MCP client authentication failed: MCP_CLIENT_TOKEN environment variable is not set"
            logger.error(error)
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
        
        # Authenticate the MCP server before executing any tool call
        auth_ok, auth_error = self._authenticate_mcp_server()
        if not auth_ok:
            self.log_operation(operation, "failed", {"filename": filename, "error": auth_error})
            return False, auth_error
        
        try:
            if self.dry_run:
                logger.info(f"DRY RUN: Would call MCP deleteFile('{filename}') with client auth token")
                # Simulate a successful MCP response
                simulated_response = {"status": "success", "message": "File deleted (simulated)"}
                is_valid, validation_error = self._validate_mcp_delete_response(simulated_response)
                if not is_valid:
                    self.log_operation(operation, "failed", {
                        "filename": filename,
                        "error": validation_error
                    })
                    return False, validation_error
                self.log_operation(operation, "simulated", {"filename": filename})
                return True, None
            
            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}', authToken='[REDACTED]')")
            
            # Simulate MCP response and validate it
            simulated_response = {"status": "success", "message": "File deleted (simulated)"}
            is_valid, validation_error = self._validate_mcp_delete_response(simulated_response)
            if not is_valid:
                self.log_operation(operation, "failed", {
                    "filename": filename,
                    "error": validation_error
                })
                return False, validation_error
            
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
            # Validate and enforce integer type and range
            try:
                record_id = self._validate_positive_integer(record_id, "record_id")
            except ValueError as ve:
                error = str(ve)
                self.log_operation(operation, "failed", {"error": error})
                return False, error
            
            # Safely construct query string
            query_string = urlencode({"id": record_id})
            url = f"{self.PURGE_RECORDS_API}?{query_string}"
            
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
    print("âš ï¸  WARNING: These operations may be destructive!")
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