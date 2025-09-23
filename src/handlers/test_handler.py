"""
Test mode handler for data quality testing and validation.
Handles S3 data testing, test case execution, and result injection.
"""

import os
import time
import logging
from typing import Dict, List, Any, Optional

from src.handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)


class TestModeHandler(BaseHandler):
    """Handler for test mode with data quality testing and validation"""
    
    def __init__(self, config_file="ingestion-generic.yaml"):
        """Initialize test handler"""
        super().__init__(config_file)
        logger.debug("🧪 TestModeHandler initialized")
    
    def run_test_mode(self, mode_config):
        """Data quality testing and validation with multi-server coordination"""
        logger.info("🧪 Running test mode")
        
        try:
            # Add server coordination to prevent conflicts
            server_id = os.environ.get('SERVER_ID', 'default')
            logger.info(f"🖥️ Running on server: {server_id}")
            
            # Check if another server is currently running operations
            if self._is_another_server_running():
                logger.warning("⚠️ Another server is currently running operations")
                logger.warning("💡 Waiting for other server to complete...")
                time.sleep(30)  # Wait 30 seconds before proceeding
                
                # Check again
                if self._is_another_server_running():
                    logger.error("❌ Multiple servers detected. Aborting to prevent conflicts.")
                    logger.error("💡 Run operations on only one server at a time.")
                    return False
            
            # Mark this server as active
            self._mark_server_active(server_id)
            
            try:
                # Test mode should always run quality tests against S3 data
                # This retrieves existing test cases from OpenMetadata and executes them against S3
                logger.info("📊 Executing existing test cases against S3 data...")
                success = self.run_quality_tests()
                
                if success:
                    logger.info("✅ Test mode completed successfully")
                else:
                    logger.error("❌ Test mode failed during quality test execution")
                    
                return success
            finally:
                # Always clear the server active marker
                self._clear_server_active(server_id)
            
        except Exception as e:
            logger.error(f"❌ Test mode failed: {e}")
            return False

    def _is_another_server_running(self):
        """Check if another server is currently running operations"""
        try:
            # For now, disable the multi-server check since we're running on a single instance
            # This prevents false positives when the OpenMetadata API is simply responsive
            # TODO: Implement proper distributed lock mechanism if running on multiple servers
            return False
        except Exception:
            # If we can't check, assume no other server is running
            return False

    def _mark_server_active(self, server_id):
        """Mark this server as active"""
        # TODO: Implement server coordination logic
        logger.debug(f"Marking server {server_id} as active")
        pass

    def _clear_server_active(self, server_id):
        """Clear the server active marker"""
        # TODO: Implement server coordination logic
        logger.debug(f"Clearing active marker for server {server_id}")
        pass

    def run_quality_tests(self):
        """Execute quality tests against S3 data"""
        logger.info("🔍 Starting S3 data quality testing...")
        
        try:
            # Step 1: Verify connection (always required)
            logger.info("\n[1/6] Verifying OpenMetadata connection...")
            if not self.verify_connection():
                return False
            
            # Step 2: Load contracts to understand what to test
            logger.info("\n[2/6] Loading contracts to identify test targets...")
            contracts = self.load_contracts()
            if not contracts:
                logger.error("No contracts found for testing!")
                return False
            
            logger.info(f"📊 Found {len(contracts)} contracts to test")
            
            # Step 3: Retrieve existing test cases from OpenMetadata
            logger.info("\n[3/6] Retrieving existing test cases from OpenMetadata...")
            test_cases = self.get_existing_test_cases(contracts)
            
            if not test_cases:
                logger.warning("⚠️ No test cases found in OpenMetadata")
                return True  # Not an error - just no tests to run
            
            logger.info(f"📋 Found {len(test_cases)} test cases to execute")
            
            # Step 4: Execute tests against S3 data
            logger.info("\n[4/6] Executing test cases against S3 data...")
            test_results = self.execute_s3_tests(test_cases, contracts)
            
            # Step 5: Inject test results back to OpenMetadata
            logger.info("\n[5/6] Injecting test results to OpenMetadata...")
            injection_success = self.inject_all_test_results(test_results)
            
            # Step 6: Handle failures and create incidents
            logger.info("\n[6/6] Processing test failures and creating incidents...")
            incident_success = self.process_test_failures(test_results)
            
            # Summary
            passed_tests = sum(1 for result in test_results.values() if result.get('status') == 'Success')
            failed_tests = len(test_results) - passed_tests
            
            logger.info(f"\n📊 Test Execution Summary:")
            logger.info(f"   ✅ Passed: {passed_tests}")
            logger.info(f"   ❌ Failed: {failed_tests}")
            logger.info(f"   📝 Results injected: {'✅' if injection_success else '❌'}")
            logger.info(f"   🚨 Incidents created: {'✅' if incident_success else '❌'}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Quality tests failed: {e}")
            return False

    def get_existing_test_cases(self, contracts):
        """Retrieve existing test cases from OpenMetadata"""
        # TODO: Extract from original class
        logger.debug("Retrieving existing test cases...")
        return {}

    def execute_s3_tests(self, test_cases, contracts):
        """Execute test cases against S3 data"""
        # TODO: Extract from original class
        logger.debug("Executing S3 tests...")
        return {}

    def inject_all_test_results(self, test_results):
        """Inject all test results back to OpenMetadata"""
        # TODO: Extract from original class
        logger.debug("Injecting test results...")
        return True

    def process_test_failures(self, test_results):
        """Process test failures and create incidents"""
        # TODO: Extract from original class
        logger.debug("Processing test failures...")
        return True

    def inject_test_result_via_sdk(self, test_case_fqn, status="Success", result_message="Test passed successfully"):
        """Inject test result using OpenMetadata SDK"""
        # TODO: Extract from original class
        logger.debug(f"Injecting test result via SDK: {test_case_fqn} - {status}")
        pass

    def inject_test_result_via_api(self, test_case_fqn, status="Success", result_message="Test passed successfully"):
        """Inject test result using OpenMetadata API"""
        # TODO: Extract from original class
        logger.debug(f"Injecting test result via API: {test_case_fqn} - {status}")
        pass

    def save_test_failure_as_incident(self, execution_result, test_case_name, error_message=None):
        """Save test failure as incident in OpenMetadata"""
        # TODO: Extract from original class
        logger.debug(f"Saving test failure as incident: {test_case_name}")
        pass

    def create_incident_via_api(self, title, description, test_case_name):
        """Create incident via OpenMetadata API"""
        # TODO: Extract from original class
        logger.debug(f"Creating incident via API: {title}")
        pass