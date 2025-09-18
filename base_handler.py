"""
Base handler for contract ingestion with shared functionality across all modes.
Contains configuration loading, OpenMetadata client setup, and utility methods.
"""

import os
import yaml
import logging
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


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

# Try to import OpenMetadata SDK
try:
    from metadata.generated.schema.entity.services.connections.metadata.openMetadataConnection import (
        OpenMetadataConnection,
        AuthProvider
    )
    from metadata.generated.schema.security.client.openMetadataJWTClientConfig import (
        OpenMetadataJWTClientConfig
    )
    from metadata.ingestion.ometa.ometa_api import OpenMetadata
    SDK_AVAILABLE = True
    logger.debug("✅ OpenMetadata SDK available for test result injection")
except ImportError as e:
    SDK_AVAILABLE = False
    logger.debug(f"⚠️ OpenMetadata SDK not available: {e}")


class OMDClient:
    """OpenMetadata 1.8.2 client"""
    
    def __init__(self, base_url: str, jwt_token: str):
        self.base_url = base_url.rstrip('/')
        self.jwt_token = jwt_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {jwt_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
    def _make_request(self, method: str, endpoint: str, data: dict = None, ignore_409=True):
        """Make API request with proper error handling"""
        url = f"{self.base_url}/api{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, timeout=30)
            elif method.upper() == 'PATCH':
                response = self.session.patch(url, json=data, timeout=30)
            else:
                logger.error(f"Unsupported method: {method}")
                return None
                
            if response.status_code in [200, 201]:
                try:
                    return response.json()
                except Exception:
                    return {"status": "success"}
            elif response.status_code == 409 and ignore_409:
                logger.debug(f"Resource already exists: {endpoint}")
                # For existing resources, try to get them
                if method.upper() == 'POST':
                    try:
                        # Try to get existing resource by name
                        resource_name = data.get('name') if data else None
                        if resource_name and '/domains' in endpoint:
                            # Check if this is a subdomain creation (has parent field)
                            if data.get('parent'):
                                # For subdomains, use parent.name format
                                full_domain_name = f"{data.get('parent')}.{resource_name}"
                                get_response = self.session.get(f"{self.base_url}/api/v1/domains/name/{full_domain_name}", timeout=30)
                            else:
                                # For root domains, just use the name
                                get_response = self.session.get(f"{self.base_url}/api/v1/domains/name/{resource_name}", timeout=30)
                            if get_response.status_code == 200:
                                return get_response.json()
                        elif resource_name and '/teams' in endpoint:
                            get_response = self.session.get(f"{self.base_url}/api/v1/teams/name/{resource_name}", timeout=30)
                            if get_response.status_code == 200:
                                return get_response.json()
                        elif resource_name and '/users' in endpoint:
                            # Extract email from user data
                            email = data.get('email')
                            if email:
                                get_response = self.session.get(f"{self.base_url}/api/v1/users/name/{data.get('name')}", timeout=30)
                                if get_response.status_code == 200:
                                    return get_response.json()
                    except Exception:
                        pass
                return {"status": "exists"}
            else:
                logger.error(f"API request failed: {method} {endpoint}")
                logger.error(f"Status: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Request exception: {method} {url} -> {e}")
            return None
    
    def get_version(self):
        return self._make_request('GET', '/v1/system/version')
    
    def create_domain(self, data):
        return self._make_request('POST', '/v1/domains', data)
    
    def get_domain_by_name(self, name):
        return self._make_request('GET', f'/v1/domains/name/{name}')
    
    def create_subdomain(self, data):
        return self._make_request('POST', '/v1/domains', data)
    
    def create_database_service(self, data):
        return self._make_request('POST', '/v1/services/databaseServices', data)
    
    def get_database_service_by_name(self, name):
        return self._make_request('GET', f'/v1/services/databaseServices/name/{name}')
    
    def create_database(self, data):
        return self._make_request('POST', '/v1/databases', data)
    
    def create_database_schema(self, data):
        return self._make_request('POST', '/v1/databaseSchemas', data)
    
    def create_table(self, data):
        return self._make_request('POST', '/v1/tables', data)
    
    def create_test_case(self, data):
        return self._make_request('POST', '/v1/dataQuality/testCases', data)
    
    def create_data_product(self, data):
        return self._make_request('POST', '/v1/dataProducts', data)
        
    def create_tag_category(self, data):
        return self._make_request('POST', '/v1/tags', data)
    
    def create_tag(self, data):
        return self._make_request('POST', '/v1/tags', data)
    
    def create_user(self, data):
        return self._make_request('POST', '/v1/users', data)
    
    def get_user_by_email(self, email):
        return self._make_request('GET', f'/v1/users/email/{email}')
    
    def create_team(self, data):
        return self._make_request('POST', '/v1/teams', data)
    
    def create_role(self, data):
        return self._make_request('POST', '/v1/roles', data)
    
    def get_team_by_name(self, name):
        return self._make_request('GET', f'/v1/teams/name/{name}')
    
    def update_domain_owners(self, domain_id, owners):
        return self._make_request('PATCH', f'/v1/domains/{domain_id}', {'owners': owners})


class BaseHandler:
    """Base handler with shared functionality for all ingestion modes"""
    
    def __init__(self, config_file="ingestion-generic.yaml"):
        """Initialize base handler with configuration and OpenMetadata client"""
        # Load configuration from YAML file first
        self.config = self.load_configuration(config_file)
        
        # Setup logging based on configuration
        self.setup_logging(self.config)
        
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
        self.sdk_client = None
        if SDK_AVAILABLE:
            self.init_sdk_client()
        
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
        self.setup_cloud_credentials()

    def setup_logging(self, config):
        """Setup logging configuration"""
        setup_logging(config)

    def load_configuration(self, config_file_name="ingestion-generic.yaml"):
        """Load YAML configuration file with validation"""
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

    def init_sdk_client(self):
        """Initialize OpenMetadata SDK client for test result injection"""
        try:
            server_config = OpenMetadataConnection(
                hostPort=self.base_url,
                authProvider=AuthProvider.openmetadata,
                securityConfig=OpenMetadataJWTClientConfig(
                    jwtToken=self.jwt_token,
                ),
            )
            self.sdk_client = OpenMetadata(server_config)
            logger.debug("✅ OpenMetadata SDK client initialized successfully")
        except Exception as e:
            logger.warning(f"⚠️ Failed to initialize OpenMetadata SDK client: {e}")
            self.sdk_client = None

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

    def setup_cloud_credentials(self):
        """Setup cloud provider credentials from configuration"""
        try:
            # Cloud provider configuration from YAML
            cloud_config = self.config.get('cloud_providers', {})
            
            # AWS Configuration
            aws_config = cloud_config.get('aws', {})
            if aws_config.get('enabled', False):
                # Set AWS credentials from environment variables or config
                aws_access_key = os.getenv('AWS_ACCESS_KEY_ID', aws_config.get('access_key_id'))
                aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY', aws_config.get('secret_access_key'))
                aws_region = os.getenv('AWS_DEFAULT_REGION', aws_config.get('region', 'us-east-1'))
                
                if aws_access_key and aws_secret_key:
                    os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key
                    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_key
                    os.environ['AWS_DEFAULT_REGION'] = aws_region
                    logger.debug(f"🔐 AWS credentials configured for region: {aws_region}")
                else:
                    logger.warning("⚠️ AWS enabled but credentials not found in environment or config")
            
            # Azure Configuration
            azure_config = cloud_config.get('azure', {})
            if azure_config.get('enabled', False):
                tenant_id = os.getenv('AZURE_TENANT_ID', azure_config.get('tenant_id'))
                client_id = os.getenv('AZURE_CLIENT_ID', azure_config.get('client_id'))
                client_secret = os.getenv('AZURE_CLIENT_SECRET', azure_config.get('client_secret'))
                
                if tenant_id and client_id and client_secret:
                    os.environ['AZURE_TENANT_ID'] = tenant_id
                    os.environ['AZURE_CLIENT_ID'] = client_id
                    os.environ['AZURE_CLIENT_SECRET'] = client_secret
                    logger.debug("🔐 Azure credentials configured")
                else:
                    logger.warning("⚠️ Azure enabled but credentials not found in environment or config")
            
            # GCP Configuration
            gcp_config = cloud_config.get('gcp', {})
            if gcp_config.get('enabled', False):
                credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS', gcp_config.get('credentials_path'))
                project_id = os.getenv('GOOGLE_CLOUD_PROJECT', gcp_config.get('project_id'))
                
                if credentials_path and os.path.exists(credentials_path):
                    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path
                    if project_id:
                        os.environ['GOOGLE_CLOUD_PROJECT'] = project_id
                    logger.debug(f"🔐 GCP credentials configured for project: {project_id}")
                else:
                    logger.warning("⚠️ GCP enabled but credentials file not found")
                    
        except Exception as e:
            logger.warning(f"⚠️ Error setting up cloud credentials: {e}")

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
                    
                    # Extract domain from directory structure
                    parts = yaml_file.relative_to(self.contracts_dir).parts
                    if len(parts) >= 2:
                        contract['domain'] = parts[0]
                        contract['subdomain'] = parts[1] if len(parts) > 1 else parts[0]
                    
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

    def camel_case_to_readable(self, camel_str):
        """Convert camelCase to readable format"""
        import re
        # Insert space before uppercase letters that follow lowercase letters
        readable = re.sub(r'([a-z])([A-Z])', r'\1 \2', camel_str)
        # Capitalize first letter
        return readable.capitalize()

    def extract_table_name_from_location(self, contract):
        """Extract table name from S3 location in contract"""
        try:
            # Get server info for current environment
            server = self.get_environment_server(contract)
            if not server:
                logger.warning(f"No server configuration found for environment {self.target_environment}")
                return None
            
            # Get S3 location
            s3_location = server.get('url', '')
            if not s3_location:
                logger.warning("No S3 location found in server configuration")
                return None
            
            # Extract table name from S3 path
            # Example: s3://bucket/path/to/table_name/ -> table_name
            if s3_location.startswith('s3://'):
                path_parts = s3_location.replace('s3://', '').split('/')
                # Get the last non-empty part as table name
                table_name = next((part for part in reversed(path_parts) if part), None)
                return table_name
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting table name from location: {e}")
            return None

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