# Contract Ingestion Refactoring Architecture

## Current State
- Single `GenericContractIngestion` class with **215 methods** and 10,548 lines
- All functionality in one monolithic class
- Mode-based execution: `--mode test`, `--mode ingestion`, etc.

## Target Architecture

### 1. Base Handler (`base_handler.py`)
**Purpose**: Shared functionality across all modes

**Core Responsibilities**:
- Configuration loading and validation
- OpenMetadata client setup and connection
- Cloud credentials setup (AWS, Azure, GCP)
- Contract loading and parsing
- Team/User/Role creation utilities
- Domain and subdomain management
- Utility methods (logging, validation, etc.)

**Key Methods to Extract**:
- `__init__()` - Configuration and client setup
- `load_configuration()`
- `setup_cloud_credentials()`
- `verify_connection()`
- `load_contracts()`
- `create_comprehensive_teams()`, `create_comprehensive_users()`, `create_comprehensive_roles()`
- `create_root_domains_with_ownership()`, `create_subdomains_for_multiple_roots()`
- `load_existing_teams()`, `get_team_for_domain_dynamic()`
- All utility methods (`camel_case_to_readable()`, etc.)

### 2. Ingestion Mode Handler (`ingestion_handler.py`)
**Purpose**: Full data ingestion and metadata creation

**Core Responsibilities**:
- Complete domain-aware ingestion process
- Database service and schema creation
- Table and column metadata creation
- Data lineage and profiling
- Comprehensive metadata enrichment

**Key Methods to Extract**:
- `run_ingestion_mode()` - Main ingestion orchestration
- `create_database_service_with_ownership()`
- `create_database_with_comprehensive_metadata()`
- `create_schemas_and_tables_with_ownership()`
- `create_enhanced_table_from_contract()`
- `ensure_file_schema_exists()`
- `extract_columns_from_schema()`, `map_contract_type_to_openmetadata()`
- All table creation and metadata methods

### 3. Test Mode Handler (`test_handler.py`)
**Purpose**: Data quality testing and validation

**Core Responsibilities**:
- S3 data quality testing
- Test case execution and validation
- Test result injection (SDK and API)
- Incident management for failures
- Server coordination for multi-server testing

**Key Methods to Extract**:
- `run_test_mode()` - Main test orchestration
- `run_quality_tests()` - S3 data testing
- `inject_test_result_via_sdk()`, `inject_test_result_via_api()`
- `save_test_failure_as_incident()`, `create_incident_via_api()`
- Server coordination methods (`_is_another_server_running()`, etc.)
- All testing and validation methods

### 4. Main Entry Point (`contract_ingestion.py`)
**Purpose**: Mode routing and backward compatibility

**Responsibilities**:
- Preserve existing `main()` function and argparse
- Route to appropriate handler based on `--mode` parameter
- Maintain exact same CLI interface
- Ensure no regression in existing functionality

## Implementation Strategy

### Phase 1: Extract BaseHandler
1. Create `base_handler.py` with shared functionality
2. Move configuration, client setup, and utility methods
3. Test basic functionality

### Phase 2: Create IngestionModeHandler  
1. Create `ingestion_handler.py` inheriting from BaseHandler
2. Move `run_ingestion_mode()` and all ingestion-related methods
3. Test `--mode ingestion` functionality

### Phase 3: Create TestModeHandler
1. Create `test_handler.py` inheriting from BaseHandler  
2. Move `run_test_mode()` and all testing-related methods
3. Test `--mode test` functionality

### Phase 4: Update Main Entry Point
1. Modify `contract_ingestion.py` to use new handlers
2. Preserve exact argparse and mode routing logic
3. Comprehensive testing of all modes

### Phase 5: Validation
1. Test both `--mode test` and `--mode ingestion` thoroughly
2. Verify retention system still works perfectly
3. Ensure no functional regression
4. Performance validation

## Key Preservation Requirements
- **MUST** preserve `--mode test` and `--mode ingestion` functionality exactly
- **MUST** maintain working 7-day retention system (P7D periods)
- **MUST** keep all existing CLI arguments and behavior
- **MUST** ensure no performance degradation
- **MUST** maintain all OpenMetadata integrations

## Benefits
- **Maintainability**: Smaller, focused classes instead of 10,548-line monolith
- **Testability**: Isolated mode handlers can be tested independently  
- **Extensibility**: Easy to add new modes or modify existing ones
- **Readability**: Clear separation of concerns and responsibilities
- **Debugging**: Easier to trace issues within specific mode contexts