#!/usr/bin/env python3
"""
Test actual team creation in OpenMetadata.
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.handlers.base_handler import BaseHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_actual_team_creation():
    """Test creating one team in OpenMetadata"""
    logger.info("🧪 Testing actual team creation in OpenMetadata...")
    
    try:
        handler = BaseHandler("ingestion-generic.yaml")
        
        # Test creating one simple team
        test_team_data = {
            "name": "test_credentials_team",
            "displayName": "Test Credentials Team",
            "description": "Test team for credentials domain data assets",
            "teamType": "Department"
        }
        
        logger.info(f"🔧 Attempting to create team: {test_team_data['displayName']}")
        
        result = handler.client.create_team(test_team_data)
        
        if result:
            logger.info(f"✅ Successfully created team: {result}")
            
            # Try to get the team back
            try:
                retrieved = handler.client.get_team_by_name(test_team_data['name'])
                logger.info(f"✅ Successfully retrieved team: {retrieved.get('displayName', 'Unknown')}")
            except Exception as e:
                logger.warning(f"⚠️ Could not retrieve team: {e}")
                
        else:
            logger.error("❌ Team creation returned None/False")
            
    except Exception as e:
        logger.error(f"❌ Team creation failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_actual_team_creation()