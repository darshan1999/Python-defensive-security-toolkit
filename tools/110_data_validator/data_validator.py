#!/usr/bin/env python3
"""Data Validator - Validates data against schema."""

import sys, json, argparse

def validate_schema(data, schema):
    """Validate data against schema."""
    errors = []
    
    if isinstance(schema, dict):
        if not isinstance(data, dict):
            return ['Data must be a dictionary']
        
        for key, expected_type in schema.items():
            if key not in data:
                errors.append(f'Missing key: {key}')
            elif expected_type == 'str' and not isinstance(data[key], str):
                errors.append(f'{key} must be string')
            elif expected_type == 'int' and not isinstance(data[key], int):
                errors.append(f'{key} must be integer')
            elif expected_type == 'list' and not isinstance(data[key], list):
                errors.append(f'{key} must be list')
    
    return errors

def main():
    p = argparse.ArgumentParser(description="Validate data against schema")
    p.add_argument("data", help="JSON data to validate")
    p.add_argument("--schema", help="Schema JSON file")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        data = json.loads(args.data)
        schema = {}
        
        if args.schema:
            with open(args.schema) as f:
                schema = json.load(f)
        
        errors = validate_schema(data, schema)
        
        result = {'valid': len(errors) == 0, 'errors': errors}
        
        print(f"[+] Validation Result: {'PASS' if result['valid'] else 'FAIL'}")
        if errors:
            for e in errors[:5]:
                print(f"    {e}")
        
        if args.output:
            json.dump(result, open(args.output, 'w'))
        
        return 0 if result['valid'] else 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
