"""
OpenMetadata client for API interactions.
Provides a clean interface to OpenMetadata REST API.
"""

import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class OMDClient:
    """
    OpenMetadata 1.8.2 client
    """
    
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
    
    def create_test_suite(self, data):
        return self._make_request('POST', '/v1/dataQuality/testSuites', data)
    
    def create_data_product(self, data):
        return self._make_request('POST', '/v1/dataProducts', data)
        
    def create_tag_classification(self, data):
        return self._make_request('POST', '/v1/classifications', data)
    
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
    
    def add_sample_data_to_table(self, table_fqn, sample_data):
        """Add sample data to a table"""
        try:
            # First get the table to understand its structure
            table_response = self._make_request('GET', f'/v1/tables/name/{table_fqn}')
            
            if not table_response:
                self.logger.error(f"Failed to get table info for {table_fqn}")
                return False
                
            table_id = table_response.get('id')
            if not table_id:
                self.logger.error(f"Could not get table ID for {table_fqn}")
                return False
            
            # Extract column names from table info
            columns = [col['name'] for col in table_response.get('columns', [])]
            
            # Format sample data for OpenMetadata - array of arrays format
            formatted_rows = []
            for row in sample_data:
                row_values = [str(row.get(col, '')) for col in columns]
                formatted_rows.append(row_values)
            
            sample_data_payload = {
                "columns": columns,
                "rows": formatted_rows
            }
            
            # Use table ID endpoint
            return self._make_request('PUT', f'/v1/tables/{table_id}/sampleData', sample_data_payload)
            
        except Exception as e:
            self.logger.error(f"Failed to add sample data to table {table_fqn}: {e}")
            return False
    
    def update_table_ownership(self, table_fqn, owners):
        """Update table ownership"""
        try:
            # First get the table to get its ID and current state
            table_response = self._make_request('GET', f'/v1/tables/name/{table_fqn}')
            
            if not table_response:
                logger.error(f"Failed to get table info for {table_fqn}")
                return False
                
            table_id = table_response.get('id')
            if not table_id:
                logger.error(f"Could not get table ID for {table_fqn}")
                return False
            
            # Update the table with new ownership - use PUT with full table object
            table_response['owners'] = owners
            
            # Fix the databaseSchema to be just the FQN string
            if 'databaseSchema' in table_response and isinstance(table_response['databaseSchema'], dict):
                table_response['databaseSchema'] = table_response['databaseSchema'].get('fullyQualifiedName', table_response['databaseSchema'])
            
            # Remove fields that shouldn't be sent in updates
            update_payload = {k: v for k, v in table_response.items() 
                            if k not in ['id', 'href', 'fullyQualifiedName', 'updatedAt', 'updatedBy', 'version', 'database', 'service', 'serviceType', 'deleted', 'processedLineage', 'changeDescription', 'incrementalChangeDescription', 'tier', 'certification']}
            
            # Also clean up nested objects that might contain serviceType
            if 'databaseSchema' in update_payload and isinstance(update_payload['databaseSchema'], dict):
                update_payload['databaseSchema'] = update_payload['databaseSchema'].get('fullyQualifiedName')
            
            result = self._make_request('PUT', f'/v1/tables', update_payload)
            if result:
                logger.info(f"✅ Updated table ownership: {table_fqn}")
                return True
            else:
                logger.warning(f"⚠️ Failed to update table ownership: {table_fqn}")
                return False
            
        except Exception as e:
            logger.error(f"Failed to update table ownership for {table_fqn}: {e}")
            return False
    
    def add_table_retention_policy(self, table_fqn, retention_policy):
        """Add retention policy to table"""
        try:
            # First get the table to get its ID and current state
            table_response = self._make_request('GET', f'/v1/tables/name/{table_fqn}')
            
            if not table_response:
                logger.error(f"Failed to get table info for {table_fqn}")
                return False
                
            table_id = table_response.get('id')
            if not table_id:
                logger.error(f"Could not get table ID for {table_fqn}")
                return False
            
            # Update the table with retention policy - use PUT with full table object
            table_response['retentionPeriod'] = retention_policy
            
            # Fix the databaseSchema to be just the FQN string
            if 'databaseSchema' in table_response and isinstance(table_response['databaseSchema'], dict):
                table_response['databaseSchema'] = table_response['databaseSchema'].get('fullyQualifiedName', table_response['databaseSchema'])
            
            # Remove fields that shouldn't be sent in updates
            update_payload = {k: v for k, v in table_response.items() 
                            if k not in ['id', 'href', 'fullyQualifiedName', 'updatedAt', 'updatedBy', 'version', 'database', 'service', 'serviceType', 'deleted', 'processedLineage', 'changeDescription', 'incrementalChangeDescription', 'tier', 'certification']}
            
            # Also clean up nested objects that might contain serviceType
            if 'databaseSchema' in update_payload and isinstance(update_payload['databaseSchema'], dict):
                update_payload['databaseSchema'] = update_payload['databaseSchema'].get('fullyQualifiedName')
            
            result = self._make_request('PUT', f'/v1/tables', update_payload)
            if result:
                logger.info(f"✅ Added retention policy to table: {table_fqn}")
                return True
            else:
                logger.warning(f"⚠️ Failed to add retention policy to table: {table_fqn}")
                return False
            
        except Exception as e:
            logger.error(f"Failed to add retention policy to table {table_fqn}: {e}")
            return False
    
    def create_glossary(self, data):
        """Create glossary"""
        return self._make_request('POST', '/v1/glossaries', data)
    
    def create_glossary_term(self, data):
        """Create glossary term"""
        return self._make_request('POST', '/v1/glossaryTerms', data)
    
    def get_glossary_by_name(self, name):
        """Get glossary by name"""
        return self._make_request('GET', f'/v1/glossaries/name/{name}')
    
    def update_data_product_glossary_terms(self, data_product_fqn, glossary_terms):
        """Update data product with glossary terms"""
        return self._make_request('PATCH', f'/v1/dataProducts/{data_product_fqn}', {'glossaryTerms': glossary_terms})
    
    def update_table_tier(self, table_fqn, tier):
        """Update table tier"""
        try:
            # First get the table to get its ID and current state
            table_response = self._make_request('GET', f'/v1/tables/name/{table_fqn}')
            
            if not table_response:
                logger.error(f"Failed to get table info for {table_fqn}")
                return False
                
            table_id = table_response.get('id')
            if not table_id:
                logger.error(f"Could not get table ID for {table_fqn}")
                return False
            
            # Update the table with tier - use PUT with full table object
            table_response['tier'] = tier
            
            # Fix the databaseSchema to be just the FQN string
            if 'databaseSchema' in table_response and isinstance(table_response['databaseSchema'], dict):
                table_response['databaseSchema'] = table_response['databaseSchema'].get('fullyQualifiedName', table_response['databaseSchema'])
            
            # Remove fields that shouldn't be sent in updates
            update_payload = {k: v for k, v in table_response.items() 
                            if k not in ['id', 'href', 'fullyQualifiedName', 'updatedAt', 'updatedBy', 'version', 'database', 'service', 'serviceType', 'deleted', 'processedLineage', 'changeDescription', 'incrementalChangeDescription']}
            
            # Also clean up nested objects that might contain serviceType
            if 'databaseSchema' in update_payload and isinstance(update_payload['databaseSchema'], dict):
                update_payload['databaseSchema'] = update_payload['databaseSchema'].get('fullyQualifiedName')
            
            result = self._make_request('PUT', f'/v1/tables', update_payload)
            if result:
                logger.info(f"✅ Updated table tier: {table_fqn} -> {tier}")
                return True
            else:
                logger.warning(f"⚠️ Failed to update table tier: {table_fqn}")
                return False
                
        except Exception as e:
            logger.warning(f"⚠️ Failed to update table tier: {table_fqn} - {e}")
            return False
    
    def update_table_certification(self, table_fqn, certification):
        "Update table certification"
        try:
            # First get the table to get its ID and current state
            table_response = self._make_request('GET', f'/v1/tables/name/{table_fqn}')
            
            if not table_response:
                logger.error(f"Failed to get table info for {table_fqn}")
                return False
                
            table_id = table_response.get('id')
            if not table_id:
                logger.error(f"Could not get table ID for {table_fqn}")
                return False
            
            # Update the table with certification - use PUT with full table object
            table_response['certification'] = certification
            
            # Fix the databaseSchema to be just the FQN string
            if 'databaseSchema' in table_response and isinstance(table_response['databaseSchema'], dict):
                table_response['databaseSchema'] = table_response['databaseSchema'].get('fullyQualifiedName', table_response['databaseSchema'])
            
            # Remove fields that shouldn't be sent in updates
            update_payload = {k: v for k, v in table_response.items() 
                            if k not in ['id', 'href', 'fullyQualifiedName', 'updatedAt', 'updatedBy', 'version', 'database', 'service', 'serviceType', 'deleted', 'processedLineage', 'changeDescription', 'incrementalChangeDescription']}
            
            # Also clean up nested objects that might contain serviceType
            if 'databaseSchema' in update_payload and isinstance(update_payload['databaseSchema'], dict):
                update_payload['databaseSchema'] = update_payload['databaseSchema'].get('fullyQualifiedName')
            
            result = self._make_request('PUT', f'/v1/tables', update_payload)
            if result:
                logger.info(f"✅ Updated table certification: {table_fqn} -> {certification}")
                return True
            else:
                logger.warning(f"⚠️ Failed to update table certification: {table_fqn}")
                return False
                
        except Exception as e:
            logger.warning(f"⚠️ Failed to update table certification: {table_fqn} - {e}")
            return False