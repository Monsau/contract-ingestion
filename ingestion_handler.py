"""
Ingestion mode handler for full data ingestion and metadata creation.
Handles comprehensive domain-aware ingestion process.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from base_handler import BaseHandler

logger = logging.getLogger(__name__)


class IngestionModeHandler(BaseHandler):
    """Handler for full ingestion mode with comprehensive metadata creation"""
    
    def __init__(self, config_file="ingestion-generic.yaml"):
        """Initialize ingestion handler"""
        super().__init__(config_file)
        logger.debug("🔄 IngestionModeHandler initialized")
    
    def run_ingestion_mode(self, mode_config):
        """Full data ingestion and metadata creation for all domains"""
        logger.info("🔄 Running full ingestion mode")
        includes = mode_config.get('includes', [])
        
        logger.info("🎯 STARTING FULL DOMAIN-AWARE INGESTION")
        logger.info("=" * 60)
        logger.info(f"Processing ALL domains from contracts directory...")
        logger.info(f"Included components: {', '.join(includes) if includes else 'ALL'}")
        
        try:
            # Step 1: Verify connection (always required)
            logger.info("\n[1/11] Verifying OpenMetadata connection...")
            if not self.verify_connection():
                return False
            
            # Step 2: Load ALL contracts from ALL domains
            logger.info("\n[2/11] Loading contracts from ALL domains...")
            contracts = self.load_contracts()
            if not contracts:
                logger.error("No contracts found in any domain!")
                return False
            
            # Log all domains being processed
            domains_found = set()
            for contract in contracts:
                domain = contract.get('domain', 'Unknown')
                domains_found.add(domain)
            
            logger.info(f"📁 Found {len(contracts)} contracts across {len(domains_found)} domains:")
            for domain in sorted(domains_found):
                domain_contracts = [c for c in contracts if c.get('domain') == domain]
                logger.info(f"   • {domain}: {len(domain_contracts)} contracts")
            
            # Step 3: Create comprehensive roles, users, and teams (if included)
            if not includes or 'teams' in includes or 'users' in includes:
                logger.info("\n[3/11] Creating comprehensive roles for user assignment...")
                created_roles = self.create_comprehensive_roles(contracts)
                
                logger.info("\n[3b/11] Creating comprehensive users with detailed profiles...")
                created_users = self.create_comprehensive_users(contracts)
                self.created_users = created_users  # Store users for later access
                
                logger.info("\n[3c/11] Creating teams with ownership relationships and domain assignment...")
                created_teams = self.create_comprehensive_teams(created_users)
                self.created_teams = created_teams  # Store teams for later access
                
                # Also create domain-aware team assignments for contracts
                logger.info("\n[3d/11] Assigning teams to contracts based on domain patterns...")
                self.assign_teams_to_contracts(contracts, created_teams)
            else:
                logger.info("\n[3/11] Skipping roles, teams and users (not included)")
                created_users, created_teams = [], []
            
            # Step 4: Create tags (if included)
            if not includes or 'tags' in includes:
                logger.info("\n[4/11] Creating tag categories and tags...")
                self.create_tag_categories_and_tags()
            else:
                logger.info("\n[4/11] Skipping tags (not included)")
            
            # Step 5: Create domains (if included)
            if not includes or 'domains' in includes:
                logger.info("\n[5/11] Creating root domains for each folder...")
                created_root_domains = self.create_root_domains_with_ownership(contracts)
                if not created_root_domains:
                    return False
                
                logger.info("\n[6/11] Creating subdomains for ALL contract domains...")
                created_subdomains = self.create_subdomains_for_multiple_roots(created_root_domains, contracts)
            else:
                logger.info("\n[5-6/11] Skipping domains (not included)")
                created_root_domains = {}
                created_subdomains = {}
            
            # Step 7: Create comprehensive database service (if included)
            if not includes or 'services' in includes:
                logger.info("\n[7/11] Creating database service with comprehensive metadata and team ownership...")
                service_fqn = self.create_comprehensive_database_service(created_teams)
                if not service_fqn:
                    # Fallback to basic service creation if comprehensive fails
                    logger.warning("Comprehensive service creation failed, trying basic approach...")
                    service_fqn = self.create_database_service_with_ownership()
                if not service_fqn:
                    return False
            else:
                logger.info("\n[7/11] Skipping services (not included)")
                service_fqn = None
            
            # Step 8: Create databases for each root domain (if included)
            created_databases = {}
            if not includes or 'databases' in includes:
                logger.info("\n[8/11] Creating databases for each root domain...")
                if service_fqn:
                    # Get unique root domains from contracts
                    root_domains = set()
                    root_domain_mapping = {}  # Map subdomain to root domain
                    
                    for contract in contracts:
                        root_domain = contract.get('_root_domain_folder', 'unknown')
                        subdomain = contract.get('domain', 'unknown')
                        root_domains.add(root_domain)
                        root_domain_mapping[subdomain] = root_domain
                    
                    # Create database for each root domain
                    for root_domain in root_domains:
                        database_fqn = self.create_database_with_comprehensive_metadata(
                            service_fqn, root_domain, created_teams, contracts, created_root_domains
                        )
                        if database_fqn:
                            created_databases[root_domain] = database_fqn
                            logger.info(f"✅ Created database for root domain '{root_domain}': {database_fqn}")
                        else:
                            logger.error(f"❌ Failed to create database for root domain '{root_domain}'")
                            return False
            else:
                logger.info("\n[8/11] Skipping databases (not included)")
            
            # Step 9: Create schemas and tables (if included)
            if not includes or 'schemas' in includes or 'tables' in includes:
                logger.info("\n[9/11] Creating schemas and tables for ALL contracts...")
                success = self.create_schemas_and_tables_with_ownership(contracts, created_databases, created_subdomains)
                if not success:
                    logger.error("❌ Failed to create schemas and tables")
                    return False
            else:
                logger.info("\n[9/11] Skipping schemas and tables (not included)")
            
            # Step 10: Create test cases (if included) 
            if not includes or 'tests' in includes:
                logger.info("\n[10/11] Creating comprehensive test cases with team ownership...")
                success = self.create_comprehensive_test_cases(contracts, created_databases, created_teams)
                if not success:
                    logger.warning("⚠️ Some test cases may have failed, but continuing...")
            else:
                logger.info("\n[10/11] Skipping test cases (not included)")
            
            # Step 11: Create data products (if included)
            if not includes or 'data_products' in includes:
                logger.info("\n[11/11] Creating data products with comprehensive metadata...")
                success = self.create_comprehensive_data_products(contracts, created_databases, created_teams)
                if not success:
                    logger.warning("⚠️ Some data products may have failed, but continuing...")
            else:
                logger.info("\n[11/11] Skipping data products (not included)")
            
            logger.info("\n" + "=" * 60)
            logger.info("✅ FULL INGESTION COMPLETED SUCCESSFULLY!")
            logger.info("🎯 All domains processed with comprehensive metadata")
            return True
            
        except Exception as e:
            logger.error(f"❌ Ingestion mode failed: {e}")
            return False

    # Placeholder methods - these need to be extracted from the original class
    def create_comprehensive_roles(self, contracts):
        """Create comprehensive roles for user assignment"""
        # TODO: Extract from original class
        logger.debug("Creating comprehensive roles...")
        return {}

    def create_comprehensive_users(self, contracts):
        """Create comprehensive users with detailed profiles"""
        # TODO: Extract from original class
        logger.debug("Creating comprehensive users...")
        return {}

    def create_comprehensive_teams(self, created_users):
        """Create teams with ownership relationships and domain assignment"""
        # TODO: Extract from original class
        logger.debug("Creating comprehensive teams...")
        return {}

    def assign_teams_to_contracts(self, contracts, created_teams):
        """Assign teams to contracts based on domain patterns"""
        # TODO: Extract from original class
        logger.debug("Assigning teams to contracts...")
        pass

    def create_tag_categories_and_tags(self):
        """Create tag categories and tags"""
        # TODO: Extract from original class
        logger.debug("Creating tag categories and tags...")
        pass

    def create_root_domains_with_ownership(self, contracts):
        """Create root domains for each folder"""
        # TODO: Extract from original class
        logger.debug("Creating root domains with ownership...")
        return {}

    def create_subdomains_for_multiple_roots(self, created_root_domains, contracts):
        """Create subdomains for ALL contract domains"""
        # TODO: Extract from original class
        logger.debug("Creating subdomains for multiple roots...")
        return {}

    def create_comprehensive_database_service(self, created_teams):
        """Create database service with comprehensive metadata and team ownership"""
        # TODO: Extract from original class
        logger.debug("Creating comprehensive database service...")
        return None

    def create_database_service_with_ownership(self):
        """Fallback basic service creation"""
        # TODO: Extract from original class
        logger.debug("Creating database service with ownership...")
        return None

    def create_database_with_comprehensive_metadata(self, service_fqn, root_domain_name, created_teams, contracts, created_root_domains=None):
        """Create database with comprehensive metadata"""
        # TODO: Extract from original class
        logger.debug("Creating database with comprehensive metadata...")
        return None

    def create_schemas_and_tables_with_ownership(self, contracts, created_databases, created_subdomains):
        """Create schemas and tables for ALL contracts"""
        # TODO: Extract from original class
        logger.debug("Creating schemas and tables with ownership...")
        return True

    def create_comprehensive_test_cases(self, contracts, created_databases, created_teams):
        """Create comprehensive test cases with team ownership"""
        # TODO: Extract from original class
        logger.debug("Creating comprehensive test cases...")
        return True

    def create_comprehensive_data_products(self, contracts, created_databases, created_teams):
        """Create data products with comprehensive metadata"""
        # TODO: Extract from original class
        logger.debug("Creating comprehensive data products...")
        return True