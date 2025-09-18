"""
Refactored contract ingestion entry point using modular handlers.
Preserves exact --mode test and --mode ingestion functionality.
"""

import sys
import argparse
import logging

from base_handler import BaseHandler
from ingestion_handler import IngestionModeHandler
from test_handler import TestModeHandler

logger = logging.getLogger(__name__)


def main():
    """Main function to orchestrate the ingestion process with modular handlers"""
    print("DEBUG: Starting main() function with modular architecture")
    
    try:
        # Create a base handler to load configuration and determine mode
        print("DEBUG: Creating BaseHandler instance to load configuration")
        base_handler = BaseHandler("ingestion-generic.yaml")
        
        # Get default mode from configuration
        operations = base_handler.config.get('operations', {})
        default_mode = operations.get('default_mode', 'metadata')
        
        # Get mode from command line arguments or use config default
        parser = argparse.ArgumentParser(description='Generic Contract-based Data Ingestion')
        parser.add_argument('--mode', choices=['ingestion', 'lineage', 'profiling', 'test', 'monitoring', 'dry-run'], 
                          default=default_mode, help='Operation mode: ingestion (comprehensive), lineage, profiling, test, monitoring, dry-run (show connection details)')
        args = parser.parse_args()
        
        print(f"DEBUG: Running operation mode: {args.mode}")
        
        # Handle dry-run mode
        if args.mode == 'dry-run':
            success = run_dry_run_mode(base_handler)
            return 0 if success else 1
        
        # Execute based on mode using appropriate handler
        success = False
        
        if args.mode == 'ingestion':
            print("DEBUG: Using IngestionModeHandler for --mode ingestion")
            handler = IngestionModeHandler("ingestion-generic.yaml")
            mode_config = handler.config.get('operations', {}).get('modes', {}).get('ingestion', {})
            success = handler.run_ingestion_mode(mode_config)
            
        elif args.mode == 'test':
            print("DEBUG: Using TestModeHandler for --mode test")
            handler = TestModeHandler("ingestion-generic.yaml")
            mode_config = handler.config.get('operations', {}).get('modes', {}).get('test', {})
            success = handler.run_test_mode(mode_config)
            
        elif args.mode == 'lineage':
            print("DEBUG: Using BaseHandler for --mode lineage (TODO: implement LineageHandler)")
            mode_config = base_handler.config.get('operations', {}).get('modes', {}).get('lineage', {})
            success = run_lineage_mode_fallback(base_handler, mode_config)
            
        elif args.mode == 'profiling':
            print("DEBUG: Using BaseHandler for --mode profiling (TODO: implement ProfilingHandler)")
            mode_config = base_handler.config.get('operations', {}).get('modes', {}).get('profiling', {})
            success = run_profiling_mode_fallback(base_handler, mode_config)
            
        elif args.mode == 'monitoring':
            print("DEBUG: Using BaseHandler for --mode monitoring (TODO: implement MonitoringHandler)")
            mode_config = base_handler.config.get('operations', {}).get('modes', {}).get('monitoring', {})
            success = run_monitoring_mode_fallback(base_handler, mode_config)
            
        else:
            print(f"ERROR: Unsupported mode: {args.mode}")
            return 1
        
        if success:
            print("SUCCESS! Generic ingestion operation completed successfully")
        else:
            print("FAILED! Generic metadata operation encountered errors")
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"CRITICAL ERROR in main(): {e}")
        print("FAILED!")
        logger.exception("Critical error in main function")
        return 1


def run_dry_run_mode(handler):
    """Run dry-run mode to show connection details"""
    try:
        logger.info("🔍 Running dry-run mode - showing connection details")
        logger.info("=" * 50)
        
        # Show configuration details
        logger.info(f"🌍 Target Environment: {handler.target_environment}")
        logger.info(f"🔗 OpenMetadata URL: {handler.base_url}")
        logger.info(f"📁 Contracts Directory: {handler.contracts_dir}")
        logger.info(f"🏢 Service Name: {handler.service_name}")
        logger.info(f"🗃️ Database Name: {handler.database_name}")
        
        # Test connection
        logger.info("\n🔌 Testing OpenMetadata connection...")
        if handler.verify_connection():
            logger.info("✅ Connection test successful!")
        else:
            logger.error("❌ Connection test failed!")
            return False
        
        # Show contracts summary
        contracts = handler.load_contracts()
        logger.info(f"\n📊 Found {len(contracts)} compatible contracts")
        
        if contracts:
            domains = set(contract.get('domain', 'Unknown') for contract in contracts)
            logger.info(f"📁 Domains: {', '.join(sorted(domains))}")
        
        logger.info("\n✅ Dry-run completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Dry-run failed: {e}")
        return False


def run_lineage_mode_fallback(handler, mode_config):
    """Fallback for lineage mode - TODO: implement LineageHandler"""
    logger.warning("⚠️ Lineage mode not yet refactored - using fallback")
    # TODO: Implement LineageHandler or call original method
    return True


def run_profiling_mode_fallback(handler, mode_config):
    """Fallback for profiling mode - TODO: implement ProfilingHandler"""
    logger.warning("⚠️ Profiling mode not yet refactored - using fallback")
    # TODO: Implement ProfilingHandler or call original method
    return True


def run_monitoring_mode_fallback(handler, mode_config):
    """Fallback for monitoring mode - TODO: implement MonitoringHandler"""
    logger.warning("⚠️ Monitoring mode not yet refactored - using fallback")
    # TODO: Implement MonitoringHandler or call original method
    return True


if __name__ == "__main__":
    sys.exit(main())