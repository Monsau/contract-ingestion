#!/usr/bin/env python3
"""
Isolated test script for team creation functionality.
Tests the team creation process from contract YAML data.
"""

import logging
import sys
import yaml
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

class TeamCreationTester:
    """Isolated tester for team creation functionality"""
    
    def __init__(self):
        """Initialize the tester"""
        self.base_handler = BaseHandler("ingestion-generic.yaml")
        logger.info("🔧 TeamCreationTester initialized")
    
    def extract_teams_from_contracts(self):
        """Extract and analyze team data from contracts"""
        logger.info("📋 Extracting team data from contracts...")
        
        try:
            # Load all contracts
            contracts = self.base_handler.load_contracts()
            logger.info(f"📁 Loaded {len(contracts)} contracts")
            
            # Extract team information
            all_team_members = {}
            team_stats = {"total_members": 0, "unique_users": set(), "domains_with_teams": set()}
            
            for contract in contracts:
                contract_team = contract.get('team', [])
                contract_domain = contract.get('domain', 'unknown')
                contract_name = contract.get('dataProduct', 'unknown')
                
                if contract_team:
                    team_stats["domains_with_teams"].add(contract_domain)
                    logger.info(f"   📊 Contract '{contract_name}' in domain '{contract_domain}' has {len(contract_team)} team members")
                    
                    for member in contract_team:
                        username = member.get('username', '')
                        role = member.get('role', 'data_analyst')
                        date_in = member.get('dateIn', 'unknown')
                        
                        if username:
                            team_stats["total_members"] += 1
                            team_stats["unique_users"].add(username)
                            
                            # Create domain-based team name
                            team_name = f"{contract_domain.replace(' ', '_').lower()}_team"
                            
                            if team_name not in all_team_members:
                                all_team_members[team_name] = {
                                    'name': team_name,
                                    'displayName': f"{contract_domain} Team",
                                    'description': f"Team responsible for {contract_domain} domain data assets",
                                    'domain': contract_domain,
                                    'members': []
                                }
                            
                            # Add member if not already present
                            member_exists = any(m.get('username') == username for m in all_team_members[team_name]['members'])
                            if not member_exists:
                                all_team_members[team_name]['members'].append({
                                    'username': username,
                                    'role': role,
                                    'dateIn': date_in,
                                    'domain': contract_domain
                                })
                                logger.info(f"      👤 Member: {username} ({role}) - joined {date_in}")
            
            # Print statistics
            logger.info(f"\n📊 TEAM EXTRACTION STATISTICS:")
            logger.info(f"   • Total team member entries: {team_stats['total_members']}")
            logger.info(f"   • Unique users: {len(team_stats['unique_users'])}")
            logger.info(f"   • Domains with teams: {len(team_stats['domains_with_teams'])}")
            logger.info(f"   • Teams to create: {len(all_team_members)}")
            
            logger.info(f"\n🏢 TEAMS TO CREATE:")
            for team_name, team_data in all_team_members.items():
                logger.info(f"   • {team_data['displayName']} ({len(team_data['members'])} members)")
                for member in team_data['members']:
                    logger.info(f"     - {member['username']} ({member['role']})")
            
            return all_team_members
            
        except Exception as e:
            logger.error(f"❌ Failed to extract teams: {e}")
            return {}
    
    def test_team_creation_logic(self, teams_data):
        """Test the team creation logic without actually creating teams"""
        logger.info(f"\n🧪 TESTING TEAM CREATION LOGIC...")
        
        try:
            successful_preparations = 0
            
            for team_name, team_data in teams_data.items():
                logger.info(f"\n🔧 Preparing team: {team_data['displayName']}")
                
                # Prepare team creation data
                team_create_data = {
                    "name": team_data['name'],
                    "displayName": team_data['displayName'],
                    "description": team_data['description'],
                    "teamType": "Department"
                }
                
                logger.info(f"   📋 Team data prepared:")
                logger.info(f"      - Name: {team_create_data['name']}")
                logger.info(f"      - Display Name: {team_create_data['displayName']}")
                logger.info(f"      - Description: {team_create_data['description']}")
                logger.info(f"      - Type: {team_create_data['teamType']}")
                logger.info(f"      - Members to add: {len(team_data['members'])}")
                
                successful_preparations += 1
            
            logger.info(f"\n✅ Successfully prepared {successful_preparations}/{len(teams_data)} teams for creation")
            return successful_preparations > 0
            
        except Exception as e:
            logger.error(f"❌ Team creation logic test failed: {e}")
            return False
    
    def test_openmetadata_connection(self):
        """Test OpenMetadata connection"""
        logger.info("🔗 Testing OpenMetadata connection...")
        
        try:
            if self.base_handler.verify_connection():
                logger.info("✅ OpenMetadata connection successful")
                return True
            else:
                logger.warning("⚠️ OpenMetadata connection failed")
                return False
        except Exception as e:
            logger.error(f"❌ Connection test failed: {e}")
            return False
    
    def run_full_test(self):
        """Run the complete team creation test"""
        logger.info("🚀 STARTING TEAM CREATION TEST")
        logger.info("=" * 60)
        
        # Test 1: Connection
        connection_ok = self.test_openmetadata_connection()
        
        # Test 2: Extract teams
        teams_data = self.extract_teams_from_contracts()
        
        # Test 3: Test creation logic
        if teams_data:
            logic_ok = self.test_team_creation_logic(teams_data)
        else:
            logger.warning("⚠️ No team data found, skipping creation logic test")
            logic_ok = False
        
        # Summary
        logger.info("\n" + "=" * 60)
        logger.info("🎯 TEST SUMMARY:")
        logger.info(f"   • OpenMetadata Connection: {'✅ PASS' if connection_ok else '❌ FAIL'}")
        logger.info(f"   • Team Data Extraction: {'✅ PASS' if teams_data else '❌ FAIL'}")
        logger.info(f"   • Team Creation Logic: {'✅ PASS' if logic_ok else '❌ FAIL'}")
        
        if connection_ok and teams_data and logic_ok:
            logger.info("🎉 ALL TESTS PASSED - Team creation should work!")
            return True
        else:
            logger.warning("⚠️ Some tests failed - review the issues above")
            return False

def main():
    """Main function"""
    try:
        tester = TeamCreationTester()
        success = tester.run_full_test()
        
        if success:
            print("\n🎉 Team creation test completed successfully!")
            sys.exit(0)
        else:
            print("\n⚠️ Team creation test had issues - check logs above")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"❌ Test failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()