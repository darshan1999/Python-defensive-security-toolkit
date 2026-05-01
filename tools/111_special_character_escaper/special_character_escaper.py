#!/usr/bin/env python3
"""Special Character Escaper - Escapes special characters for various formats."""

import sys, argparse, json

ESCAPE_MAPS = {
    'json': {'"': '\\"', '\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t'},
    'xml': {'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;'},
    'csv': {'"': '""', '\n': '\\n'},
    'shell': {'$': '\\$', '"': '\\"', '\\': '\\\\', '`': '\\`'}
}

def escape(text, fmt='json'):
    """Escape text for specified format."""
    escape_map = ESCAPE_MAPS.get(fmt, {})
    for char, escaped in escape_map.items():
        text = text.replace(char, escaped)
    return text

def main():
    p = argparse.ArgumentParser(description="Escape special characters")
    p.add_argument("text", help="Text to escape")
    p.add_argument("--format", choices=['json', 'xml', 'csv', 'shell'], default='json')
    p.add_argument("--output", help="Output file")
    args = p.parse_args()
    
    try:
        result = escape(args.text, args.format)
        
        print(f"[+] Escaped for {args.format}:")
        print(result)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(result)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
