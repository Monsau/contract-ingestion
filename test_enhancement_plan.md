# Test Generation Enhancement Plan

## Current Status: 68% Accuracy (17/25 quality rules supported)

## Missing Rule Implementations:

### 1. timestampFormat Rule
**Current Gap:** Found in 8 quality rules across contracts
**Implementation needed:**
```python
def create_timestamp_format_test_case(self, test_suite, table_name, column_name, rule, domain):
    """Create test case for timestamp format validation"""
    expected_format = rule.get('parameters', {}).get('expectedFormat', 'YYYY-MM-DDTHH:mm:ssZ')
    
    test_case_data = {
        "name": f"{self.format_name(table_name)}_{self.format_name(column_name)}_timestamp_format",
        "displayName": f"{table_name} - {column_name} Timestamp Format Check",
        "description": f"Validates that {column_name} follows timestamp format: {expected_format}",
        "testDefinition": "columnValueMatchesRegex",
        "entityLink": f"<#E::table::{self.get_column_fqn(table_name, column_name, domain)}>",
        "parameterValues": [
            {
                "name": "regex",
                "value": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
            }
        ]
    }
```

### 2. nonEmpty Rule  
**Current Gap:** Found in version fields
**Implementation needed:**
```python
def create_non_empty_test_case(self, test_suite, table_name, column_name, rule, domain):
    """Create test case for non-empty validation"""
    min_length = rule.get('parameters', {}).get('minLength', 1)
    
    test_case_data = {
        "name": f"{self.format_name(table_name)}_{self.format_name(column_name)}_non_empty",
        "displayName": f"{table_name} - {column_name} Non-Empty Check",
        "description": f"Validates that {column_name} is not empty (min length: {min_length})",
        "testDefinition": "columnValueLengthsToBeBetween",
        "entityLink": f"<#E::table::{self.get_column_fqn(table_name, column_name, domain)}>",
        "parameterValues": [
            {
                "name": "minLength",
                "value": min_length
            },
            {
                "name": "maxLength",
                "value": 1000
            }
        ]
    }
```

### 3. Required Field Tests
**Enhancement:** Automatically create not-null tests for all required fields
```python
# In create_test_cases_from_contracts method, add:
for schema_item in schema_def:
    properties = schema_item.get('properties', [])
    for prop in properties:
        if prop.get('required', False):
            # Create not-null test for required field
            self.create_required_field_test_case(test_suite, table_name, prop['name'], domain)
```

## Expected Improvement:
- **Before:** 68.0% accuracy (17/25 rules)
- **After:** 100% accuracy (25/25 rules) + all required field tests

## Implementation Priority:
1. **High:** timestampFormat (affects 8 quality rules)
2. **Medium:** nonEmpty (affects version fields across contracts)  
3. **Low:** Required field auto-generation (infrastructure enhancement)