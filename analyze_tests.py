#!/usr/bin/env python3

from src.handlers.ingestion_handler import IngestionModeHandler
import logging

logging.basicConfig(level=logging.INFO)

def analyze_test_generation():
    handler = IngestionModeHandler()
    contracts = handler.load_contracts()
    print('\n=== ANALYZING TEST GENERATION ACCURACY ===')

    for contract in contracts:
        print(f'\n📋 Contract: {contract.get("dataProduct", "unknown")}')
        print(f'   Domain: {contract.get("domain", "unknown")}')
        
        schema_def = contract.get("schema", [])
        total_quality_rules = 0
        required_fields = 0
        quality_rules_by_type = {}
        quality_details = []
        
        for schema_item in schema_def:
            properties = schema_item.get("properties", [])
            for prop in properties:
                prop_name = prop.get("name", "unknown")
                if prop.get("required", False):
                    required_fields += 1
                quality_rules = prop.get("quality", [])
                for rule in quality_rules:
                    rule_type = rule.get("rule", "unknown")
                    quality_rules_by_type[rule_type] = quality_rules_by_type.get(rule_type, 0) + 1
                    total_quality_rules += 1
                    
                    # Store details for analysis
                    quality_details.append({
                        'field': prop_name,
                        'rule_type': rule_type,
                        'severity': rule.get('severity', 'unknown'),
                        'description': rule.get('description', ''),
                        'valid_values': rule.get('validValues', []),
                        'parameters': rule.get('parameters', {})
                    })
        
        print(f'   📊 Total quality rules: {total_quality_rules}')
        print(f'   ✅ Required fields: {required_fields}')
        print(f'   🔍 Quality rules by type: {quality_rules_by_type}')
        
        if quality_details:
            print('   📝 Quality rule details:')
            for detail in quality_details:
                print(f'      - {detail["field"]}: {detail["rule_type"]} ({detail["severity"]})')
                if detail["valid_values"]:
                    print(f'        Valid values: {detail["valid_values"]}')
                if detail["parameters"]:
                    print(f'        Parameters: {detail["parameters"]}')

if __name__ == "__main__":
    analyze_test_generation()