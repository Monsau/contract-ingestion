"""
OpenMetadata SDK utilities and initialization.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

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
    
    # Create dummy classes for when SDK is not available
    class OpenMetadata:
        pass
    
    class OpenMetadataConnection:
        pass
    
    class AuthProvider:
        openmetadata = "openmetadata"
    
    class OpenMetadataJWTClientConfig:
        pass


def init_sdk_client(base_url: str, jwt_token: str) -> Optional[OpenMetadata]:
    """Initialize OpenMetadata SDK client for test result injection"""
    if not SDK_AVAILABLE:
        logger.warning("⚠️ OpenMetadata SDK not available")
        return None
        
    try:
        server_config = OpenMetadataConnection(
            hostPort=base_url,
            authProvider=AuthProvider.openmetadata,
            securityConfig=OpenMetadataJWTClientConfig(
                jwtToken=jwt_token,
            ),
        )
        sdk_client = OpenMetadata(server_config)
        logger.debug("✅ OpenMetadata SDK client initialized successfully")
        return sdk_client
    except Exception as e:
        logger.warning(f"⚠️ Failed to initialize OpenMetadata SDK client: {e}")
        return None


def setup_cloud_credentials(config: dict):
    """Setup cloud provider credentials from configuration"""
    try:
        # Cloud provider configuration from YAML
        cloud_config = config.get('cloud_providers', {})
        
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