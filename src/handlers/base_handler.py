"""
Base handler for contract ingestion with shared functionality across all modes.
Contains configuration loading, OpenMetadata client setup, and utility methods.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from src.client.omd_client import OMDClient
from src.utils.config import setup_logging, load_configuration, camel_case_to_readable
from src.utils.sdk import init_sdk_client, setup_cloud_credentials

logger = logging.getLogger(__name__)


class BaseHandler:
    """Base handler with shared functionality for all ingestion modes"""
    
    def __init__(self, config_file="ingestion-generic.yaml"):
        """Initialize base handler with configuration and OpenMetadata client"""
        # Load configuration from YAML file first
        self.config = load_configuration(config_file)
        
        # Setup logging based on configuration
        setup_logging(self.config)
        
        # Get target environment FIRST to determine which config to use
        source_config = self.config.get('source', {})
        self.target_environment = os.getenv('TARGET_ENVIRONMENT', source_config.get('target_environment', 'production'))
        
        # Get environment-specific configuration for OpenMetadata
        env_config = self.config.get('environments', {}).get(self.target_environment.lower(), {})
        env_om_config = env_config.get('openmetadata', {})
        
        # OpenMetadata connection - use environment-specific config if available, otherwise base config
        om_config = self.config.get('openmetadata', {})
        # Override base config with environment-specific values
        host = env_om_config.get('host', om_config.get('host', 'localhost'))
        port = env_om_config.get('port', om_config.get('port', 8585))
        protocol = env_om_config.get('protocol', om_config.get('protocol', 'http'))
        self.base_url = f"{protocol}://{host}:{port}"
        
        # JWT token from environment variable (secure) - prefer environment-specific token
        jwt_token_env = env_om_config.get('jwt_token', om_config.get('jwt_token', '${OPENMETADATA_JWT_TOKEN}'))
        if jwt_token_env.startswith('${') and jwt_token_env.endswith('}'):
            env_var = jwt_token_env[2:-1]
            self.jwt_token = os.environ.get(env_var)
            if not self.jwt_token:
                logger.error(f"JWT token environment variable {env_var} not set!")
                raise ValueError(f"JWT token environment variable {env_var} not set!")
        else:
            self.jwt_token = jwt_token_env

        logger.debug(f"🌍 Using {self.target_environment} environment -> {self.base_url}")
        self.client = OMDClient(self.base_url, self.jwt_token)
        
        # Initialize SDK client for test result injection
        self.sdk_client = init_sdk_client(self.base_url, self.jwt_token)
        
        # Source configuration
        self.contracts_dir = Path(source_config.get('contracts_directory', 'contracts'))
        
        # Domain structure from configuration
        domain_config = self.config.get('domain', {})
        self.root_domain_name = domain_config.get('root_name', 'DataManagement')
        self.root_domain_display = domain_config.get('root_display', 'Data Management Domain')
        
        # Service name from configuration
        service_config = self.config.get('service', {})
        self.service_name = service_config.get('name', 'DataLake')
        
        # Database configuration
        db_config = self.config.get('database_structure', {})
        self.database_name = db_config.get('database_name', 'bronze_layer')
        
        # Team and ownership tracking
        self.created_teams = {}
        self.created_users = {}
        self.created_tags = {}
        
        # Load existing teams into created_teams for ownership functionality
        self.load_existing_teams()
        
        # Cloud provider configuration
        setup_cloud_credentials(self.config)

    def verify_connection(self):
        """Verify connection to OpenMetadata server"""
        try:
            version = self.client.get_version()
            if version:
                logger.info(f"✅ Connected to OpenMetadata {version.get('version', 'unknown')}")
                return True
            else:
                logger.error("❌ Failed to get version information from OpenMetadata")
                return False
        except Exception as e:
            logger.error(f"❌ Failed to connect to OpenMetadata: {e}")
            return False

    def load_existing_teams(self):
        """Load existing teams from OpenMetadata to avoid duplicates"""
        try:
            # Note: This method should be implemented to call OpenMetadata API
            # to get existing teams and populate self.created_teams
            # For now, we'll leave it as a placeholder
            logger.debug("Loading existing teams from OpenMetadata...")
            # Implementation needed: fetch teams via API and populate self.created_teams
            pass
        except Exception as e:
            logger.warning(f"⚠️ Error loading existing teams: {e}")

    def get_environment_server(self, contract):
        """
        Get server configuration for environment with fallback logic.
        For DEV environment, try: DEV -> UAT -> PROD
        For other environments, use exact match only.
        """
        servers = contract.get('servers', [])
        
        # If DEV environment, use fallback logic
        if self.target_environment.lower() == 'dev':
            # Try DEV first
            dev_server = next((s for s in servers if s.get('environment', '').lower() == 'dev'), None)
            if dev_server:
                return dev_server
            
            # Fallback to UAT
            uat_server = next((s for s in servers if s.get('environment', '').lower() == 'uat'), None)
            if uat_server:
                logger.debug(f"DEV mode: Using UAT server config for contract {contract.get('info', {}).get('title', 'Unknown')}")
                return uat_server
            
            # Final fallback to PROD
            prod_server = next((s for s in servers if s.get('environment', '').lower() in ['prod', 'production']), None)
            if prod_server:
                logger.debug(f"DEV mode: Using PROD server config for contract {contract.get('info', {}).get('title', 'Unknown')}")
                return prod_server
        else:
            # For other environments, exact match only
            target_server = next((s for s in servers if s.get('environment', '').lower() == self.target_environment.lower()), None)
            if target_server:
                return target_server
        
        return None

    def has_compatible_environment(self, contract):
        """Check if contract has compatible environment configuration"""
        return self.get_environment_server(contract) is not None

    def load_contracts(self):
        """Load all contracts from contracts directory"""
        contracts = []
        
        if not self.contracts_dir.exists():
            logger.error(f"❌ Contracts directory not found: {self.contracts_dir}")
            return contracts
        
        logger.info(f"📁 Loading contracts from: {self.contracts_dir}")
        
        # Walk through all subdirectories to find YAML files
        for yaml_file in self.contracts_dir.rglob("*.yaml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as file:
                    contract = yaml.safe_load(file)
                    
                if contract and isinstance(contract, dict):
                    # Add metadata about the contract file
                    contract['_file_path'] = str(yaml_file)
                    contract['_relative_path'] = str(yaml_file.relative_to(self.contracts_dir))
                    
                    # Extract folder structure - preserve original domain from YAML
                    parts = yaml_file.relative_to(self.contracts_dir).parts
                    if len(parts) >= 2:
                        # Store the root folder (first directory) separately
                        contract['_root_domain_folder'] = parts[0]
                        contract['_subdomain_folder'] = parts[1] if len(parts) > 1 else parts[0]
                        # Don't overwrite the domain field from the YAML - keep the original
                        # contract['domain'] is already set from the YAML file content
                    
                    # Only include contracts with compatible environments
                    if self.has_compatible_environment(contract):
                        contracts.append(contract)
                        logger.debug(f"✅ Loaded contract: {yaml_file.name}")
                    else:
                        logger.debug(f"⏭️ Skipped contract {yaml_file.name} - no compatible environment for {self.target_environment}")
                        
            except Exception as e:
                logger.error(f"❌ Error loading contract {yaml_file}: {e}")
        
        logger.info(f"📊 Loaded {len(contracts)} compatible contracts")
        return contracts

    def extract_table_name_from_location(self, contract):
        """Extract table name from S3 location in contract or generate from contract info"""
        try:
            # Get server info for current environment
            server = self.get_environment_server(contract)
            if server:
                # Get S3 location
                s3_location = server.get('url', '')
                if s3_location:
                    from src.utils.config import extract_table_name_from_s3_location
                    table_name = extract_table_name_from_s3_location(s3_location)
                    if table_name:
                        return table_name
            
            # Fallback: Generate table name from contract info
            logger.debug("No S3 location found, generating table name from contract info")
            
            # Try to get table name from contract info
            info = contract.get('info', {})
            title = info.get('title', '')
            
            if title:
                # Clean and convert title to table name
                table_name = title.lower()
                table_name = table_name.replace(' ', '_')
                table_name = table_name.replace('-', '_')
                table_name = table_name.replace('&', 'and')
                table_name = ''.join(c for c in table_name if c.isalnum() or c == '_')
                return table_name
            
            # Final fallback: use file name
            file_path = contract.get('_file_path', '')
            if file_path:
                from pathlib import Path
                file_name = Path(file_path).stem  # Get filename without extension
                table_name = file_name.lower().replace('-', '_').replace(' ', '_')
                return table_name
            
            # Ultimate fallback
            return "unknown_table"
            
        except Exception as e:
            logger.error(f"Error extracting table name from location: {e}")
            # Return a safe fallback name
            return "error_table"

    def get_team_for_domain_dynamic(self, domain_identifier, context="general"):
        """
        Enhanced dynamic team assignment based on flexible domain patterns.
        
        Args:
            domain_identifier: Domain name, table FQN, or any identifier containing domain info
            context: Context for logging (e.g., "test_case", "data_product", "table")
        
        Returns:
            tuple: (team_info, team_name) or (None, None) if no match
        """
        if not self.created_teams:
            logger.warning(f"No teams available for {context} assignment")
            return None, None
        
        domain_lower = domain_identifier.lower()
        
        # Dynamic domain-team mapping based on actual contract structure
        domain_team_mappings = [
            {
                'patterns': ['electric', 'vehicle', 'inverter', 'enode_general', 'enode_inverter', 'enode_vehicle'],
                'target_team': 'data_engineering',
                'description': 'Electric Vehicles & Inverters Service'
            },
            {
                'patterns': ['energy', 'management', 'trading', 'emsys', 'ppa', 'asset', 'forecast'],
                'target_team': 'platform_engineering', 
                'description': 'Energy Management and Trading'
            }
        ]
        
        # Find matching pattern
        for mapping in domain_team_mappings:
            for pattern in mapping['patterns']:
                if pattern in domain_lower:
                    team_name = mapping['target_team']
                    team_info = self.created_teams.get(team_name)
                    
                    if team_info:
                        logger.debug(f"🎯 Assigned {context} '{domain_identifier}' to team '{team_name}' via pattern '{pattern}'")
                        return team_info, team_name
                    else:
                        logger.warning(f"⚠️ Pattern matched '{pattern}' but team '{team_name}' not found in created teams")
        
        # Fallback to default team if no pattern matches
        default_team = 'data_engineering'
        team_info = self.created_teams.get(default_team)
        
        if team_info:
            logger.debug(f"🔄 Using default team '{default_team}' for {context} '{domain_identifier}'")
            return team_info, default_team
        
        logger.warning(f"⚠️ No team found for {context} '{domain_identifier}' - no assignment made")
        return None, None