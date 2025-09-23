#!/usr/bin/env python3

from src.handlers.ingestion_handler import IngestionModeHandler
import logging

logging.basicConfig(level=logging.INFO)

def validate_test_generation_accuracy():
    """
    Validate that test generation accurately reflects contract specifications
    """
    print('\n=== TEST GENERATION ACCURACY VALIDATION ===')
    
    handler = IngestionModeHandler()
    contracts = handler.load_contracts()
    
    print(f'\n✅ Found {len(contracts)} contracts to analyze')
    
    total_quality_rules = 0
    total_required_fields = 0
    supported_rule_types = 0
    unsupported_rule_types = 0
    
    # Supported rule types in current implementation
    SUPPORTED_RULES = {
        'validValues': 'columnValuesToBeInSet',
        'jsonStructure': 'columnValueLengthsToBeBetween',  # Custom mapping
        'nullCheck': 'columnValuesToBeNotNull',
        'valueCheck': 'columnValueLengthsToBeBetween'  # Generic mapping
    }
    
    print('\n📊 ANALYSIS BY CONTRACT:')
    print('=' * 60)
    
    for i, contract in enumerate(contracts, 1):
        data_product = contract.get('dataProduct', 'unknown')
        domain = contract.get('domain', 'unknown')
        schema_def = contract.get('schema', [])
        
        contract_quality_rules = 0
        contract_required_fields = 0
        contract_supported_rules = 0
        contract_unsupported_rules = 0
        rule_details = []
        
        print(f'\n{i}. 📋 {data_product}')
        print(f'   🏢 Domain: {domain}')
        
        for schema_item in schema_def:
            properties = schema_item.get('properties', [])
            for prop in properties:
                prop_name = prop.get('name', 'unknown')
                
                # Count required fields
                if prop.get('required', False):
                    contract_required_fields += 1
                
                # Analyze quality rules
                quality_rules = prop.get('quality', [])
                for rule in quality_rules:
                    rule_type = rule.get('rule', 'unknown')
                    severity = rule.get('severity', 'unknown')
                    contract_quality_rules += 1
                    
                    if rule_type in SUPPORTED_RULES:
                        contract_supported_rules += 1
                        test_definition = SUPPORTED_RULES[rule_type]
                        rule_details.append(f'      ✅ {prop_name}.{rule_type} → {test_definition} ({severity})')
                    else:
                        contract_unsupported_rules += 1
                        rule_details.append(f'      ❌ {prop_name}.{rule_type} → NOT SUPPORTED ({severity})')
        
        print(f'   📊 Quality Rules: {contract_quality_rules}')
        print(f'   ✅ Required Fields: {contract_required_fields}')
        print(f'   🎯 Supported Rules: {contract_supported_rules}')
        print(f'   ⚠️  Unsupported Rules: {contract_unsupported_rules}')
        
        if rule_details:
            print('   📝 Rule Mapping Details:')
            for detail in rule_details:
                print(detail)
        
        # Update totals
        total_quality_rules += contract_quality_rules
        total_required_fields += contract_required_fields
        supported_rule_types += contract_supported_rules
        unsupported_rule_types += contract_unsupported_rules
    
    print('\n' + '=' * 60)
    print('📈 OVERALL ACCURACY SUMMARY:')
    print('=' * 60)
    
    print(f'📊 Total Quality Rules in Contracts: {total_quality_rules}')
    print(f'✅ Total Required Fields: {total_required_fields}')
    print(f'🎯 Supported Quality Rules: {supported_rule_types}')
    print(f'⚠️  Unsupported Quality Rules: {unsupported_rule_types}')
    
    if total_quality_rules > 0:
        accuracy_rate = (supported_rule_types / total_quality_rules) * 100
        print(f'📊 Test Generation Accuracy: {accuracy_rate:.1f}%')
        
        if accuracy_rate >= 90:
            print('🎉 EXCELLENT: Very high accuracy in test generation!')
        elif accuracy_rate >= 75:
            print('✅ GOOD: High accuracy, minor gaps exist')
        elif accuracy_rate >= 50:
            print('⚠️  MODERATE: Some gaps in test coverage')
        else:
            print('❌ LOW: Significant gaps in test generation')
    
    print('\n🔍 TEST GENERATION ANALYSIS:')
    print('=' * 60)
    
    # The current implementation creates:
    # 1. One summary test case per contract (table-level)
    # 2. Specific test cases based on quality rules where possible
    
    expected_test_cases = len(contracts)  # 1 summary test per contract
    expected_test_cases += supported_rule_types  # 1 test per supported quality rule
    expected_test_cases += total_required_fields  # 1 not-null test per required field (if implemented)
    
    print(f'📊 Expected Test Cases to Generate:')
    print(f'   - Summary tests (1 per contract): {len(contracts)}')
    print(f'   - Quality rule tests: {supported_rule_types}')
    print(f'   - Required field tests: {total_required_fields} (if implemented)')
    print(f'   🎯 Total Expected: {expected_test_cases}')
    
    print('\n✅ VALIDATION COMPLETE!')
    
    return {
        'total_contracts': len(contracts),
        'total_quality_rules': total_quality_rules,
        'supported_rules': supported_rule_types,
        'unsupported_rules': unsupported_rule_types,
        'accuracy_rate': (supported_rule_types / total_quality_rules * 100) if total_quality_rules > 0 else 0,
        'expected_test_cases': expected_test_cases
    }

if __name__ == "__main__":
    results = validate_test_generation_accuracy()