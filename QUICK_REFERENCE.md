# 🚀 Quick Reference - Contract Ingestion System

## 🎯 Essential Commands

### Basic Execution
```bash
# Full ingestion (recommended)
python contract_ingestion.py

# Environment-specific
export TARGET_ENVIRONMENT="dev"
python contract_ingestion.py

# Debug mode
export LOG_LEVEL="DEBUG"
python contract_ingestion.py --verbose
```

### Environment Setup
```bash
# Virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Required environment variables
export OPENMETADATA_JWT_TOKEN="your-jwt-token"
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
```

## 🔧 Key Code Snippets

### 1. Manual Domain Creation
```python
from src.handlers.ingestion_handler import IngestionModeHandler

# Initialize handler
handler = IngestionModeHandler('ingestion-generic.yaml')

# Create complete domain hierarchy
contracts = handler.load_contracts()
root_domains = handler.create_root_domains_with_ownership(contracts)
subdomains = handler.create_subdomains_for_multiple_roots(root_domains, contracts)
```

### 2. Table Creation with S3 Data
```python
# Create table with real S3 sample data
def create_enhanced_table(contract, schema_fqn):
    # Get S3 location from contract
    server = handler.get_environment_server(contract)
    s3_location = server.get('url', '') if server else ''
    
    # Fetch real sample data
    sample_data = handler.s3_client.fetch_sample_data(s3_location)
    
    # Create table with metadata
    table_data = {
        "name": table_name,
        "databaseSchema": schema_fqn,
        "columns": build_columns_from_schema(contract['schema']),
        "tags": get_classified_tags(contract.get('tags', [])),
        "domains": [get_domain_reference(domain_name)],
        "retentionPeriod": {"retentionPeriod": f"{retention_days}d"}
    }
    
    result = handler.client.create_table(table_data)
    
    # Add sample data
    if sample_data and result:
        handler.client.add_sample_data(result['fullyQualifiedName'], sample_data)
    
    return result
```

### 3. Test Case Creation
```python
# Create and execute data quality test
def create_data_quality_test(table_fqn, test_suite_fqn):
    test_case_data = {
        "name": f"quality_test_{table_name}",
        "displayName": f"Data Quality Test for {table_name}",
        "entityLink": table_fqn,
        "testSuite": test_suite_fqn,
        "testDefinition": "tableRowCountToEqual",
        "parameterValues": [
            {"name": "minValue", "value": "1"},
            {"name": "maxValue", "value": "1000000"}
        ]
    }
    
    return handler.client.create_test_case(test_case_data)
```

### 4. Tag Classification
```python
# Intelligent tag classification
def classify_tags(tags):
    classified = []
    for tag in tags:
        if tag in ['Bronze', 'Silver', 'Gold']:
            classified.append({"tagFQN": f"Data Quality.{tag}"})
        elif tag in ['Asset', 'Vehicle', 'Inverter']:
            classified.append({"tagFQN": f"Business Domain.{tag}"})
        else:
            classified.append({"tagFQN": f"Certification Level.{tag}"})
    return classified
```

### 5. Team Assignment
```python
# Dynamic team assignment
def get_team_for_domain(domain_name):
    domain_lower = domain_name.lower()
    
    if any(word in domain_lower for word in ['electric', 'vehicle', 'inverter']):
        return get_team_by_pattern('data_engineering')
    elif any(word in domain_lower for word in ['energy', 'management', 'trading']):
        return get_team_by_pattern('platform_engineering')
    else:
        return get_default_team()
```

## 🔍 Debugging Commands

### Connection Testing
```python
# Test OpenMetadata connection
python -c "
import requests
response = requests.get('http://localhost:8585/v1/system/version')
print(f'Status: {response.status_code}')
print(f'Version: {response.json() if response.status_code == 200 else response.text}')
"
```

### S3 Integration Testing
```python
# Test S3 connectivity
python -c "
import boto3
s3 = boto3.client('s3')
try:
    response = s3.list_objects_v2(Bucket='eno-dm-bronze-uat', MaxKeys=5)
    print(f'S3 Access: ✅ Found {len(response.get(\"Contents\", []))} objects')
except Exception as e:
    print(f'S3 Error: ❌ {e}')
"
```

### Team Ownership Fix
```python
# Fix Department team ownership issues
python -c "
from src.client.omd_client import OMDClient
from src.config.config import Config

config = Config.from_yaml('ingestion-generic.yaml')
client = OMDClient(config.api_config)

# List teams with wrong type
teams = client.get_all_teams()
for team in teams['data']:
    if team.get('teamType') == 'Department':
        print(f'Found Department team: {team[\"name\"]} - needs to be Group type')
"
```

## ⚙️ Configuration Quick Setup

### Minimal `ingestion-generic.yaml`
```yaml
openmetadata:
  host: "localhost"
  port: 8585
  protocol: "http"
  jwt_token: "${OPENMETADATA_JWT_TOKEN}"

source:
  contracts_directory: "contracts"
  target_environment: "dev"

teams:
  default_team:
    name: "data_engineering"
    display: "Data Engineering Team"
    description: "Core data engineering team"

cloud:
  provider: "aws"
  aws:
    access_key_id: "${AWS_ACCESS_KEY_ID}"
    secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
```

## 🧪 Test Execution

### Run Specific Test Cases
```python
# Execute single test case
from src.handlers.ingestion_handler import IngestionModeHandler

handler = IngestionModeHandler()
test_result = handler.inject_test_result_via_sdk(
    "test_case_fqn", 
    "Success", 
    "Test passed successfully"
)
```

### Batch Test Execution
```bash
# Run all tests for a specific table
python -c "
from src.handlers.ingestion_handler import IngestionModeHandler
handler = IngestionModeHandler()
handler.create_and_execute_tests_for_table('Datalake.db.schema.table')
"
```

## 📊 Common Patterns

### Contract Structure
```yaml
# Example contract file: enode_vehicle_event.yaml
info:
  title: "Enode Vehicle Events"
  version: "1.0.0"

domain: "Data Contract for Electric Vehicles Events"

servers:
  - environment: "uat"
    url: "s3://eno-dm-bronze-uat/enode/landing/*/*/*/vehicleEvents-*.json"

schema:
  - name: "id"
    type: "string"
    description: "Unique event identifier"
  - name: "timestamp"
    type: "datetime"
    description: "Event timestamp"
  - name: "vehicle_id"
    type: "string"
    description: "Vehicle identifier"

tags: ["Vehicle", "Bronze"]
retention_days: 365
quality_rules:
  - type: "not_null"
    columns: ["id", "vehicle_id"]
  - type: "row_count"
    min_value: 1
```

## 🚨 Emergency Commands

### Clean Restart
```bash
# Reset OpenMetadata entities (USE WITH CAUTION)
python -c "
# This would delete all created entities - implement with extreme caution
print('Manual cleanup required - use OpenMetadata UI to remove test entities')
"
```

### Verify Ingestion Status
```python
# Check ingestion completeness
python -c "
from src.handlers.ingestion_handler import IngestionModeHandler
handler = IngestionModeHandler()

# Verify domain hierarchy
domains = handler.client.get_all_domains()
print(f'Domains: {len(domains.get(\"data\", []))}')

# Verify tables
tables = handler.client.get_all_tables()
print(f'Tables: {len(tables.get(\"data\", []))}')

# Verify data products
products = handler.client.get_all_data_products()
print(f'Data Products: {len(products.get(\"data\", []))}')
"
```

---
*Quick Reference for Generic Contract Ingestion System v1.0*