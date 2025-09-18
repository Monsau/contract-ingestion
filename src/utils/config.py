"""
Utility functions for logging setup and configuration management.
"""

import logging
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


def setup_logging(config: dict = None):
    """Setup logging based on configuration"""
    log_config = config.get('logging', {}) if config else {}
    
    level = getattr(logging, log_config.get('level', 'INFO').upper())
    format_str = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    logging.basicConfig(level=level, format=format_str, force=True)
    
    # Suppress verbose third-party logging
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    # Configure SDK logging if specified
    if log_config.get('sdk_logging'):
        logger_sdk = logging.getLogger('SDK')
        logger_sdk.setLevel(level)
    else:
        logger_sdk = logging.getLogger('SDK')
        logger_sdk.setLevel(logging.WARNING)


def load_configuration(config_file_name="ingestion-generic.yaml"):
    """Load YAML configuration file with validation"""
    logger = logging.getLogger(__name__)
    
    try:
        config_path = Path(config_file_name)
        
        if not config_path.exists():
            logger.error(f"❌ Configuration file '{config_file_name}' not found")
            raise FileNotFoundError(f"Configuration file '{config_file_name}' not found")
        
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            
        if not config:
            logger.error(f"❌ Configuration file '{config_file_name}' is empty or invalid")
            raise ValueError(f"Configuration file '{config_file_name}' is empty or invalid")
            
        logger.debug(f"✅ Configuration loaded from {config_file_name}")
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"❌ Error parsing YAML configuration: {e}")
        raise
    except Exception as e:
        logger.error(f"❌ Error loading configuration: {e}")
        raise


def camel_case_to_readable(camel_str: str) -> str:
    """Convert camelCase to readable format"""
    import re
    # Insert space before uppercase letters that follow lowercase letters
    readable = re.sub(r'([a-z])([A-Z])', r'\1 \2', camel_str)
    # Capitalize first letter
    return readable.capitalize()


def extract_table_name_from_s3_location(s3_location: str) -> Optional[str]:
    """Extract table name from S3 location"""
    if not s3_location or not s3_location.startswith('s3://'):
        return None
    
    # Extract table name from S3 path
    # Example: s3://bucket/path/to/table_name/ -> table_name
    path_parts = s3_location.replace('s3://', '').split('/')
    # Get the last non-empty part as table name
    table_name = next((part for part in reversed(path_parts) if part), None)
    return table_name