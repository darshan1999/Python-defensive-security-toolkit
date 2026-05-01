#!/usr/bin/env python3
"""CLI Argument Parser - Standardized command-line argument parsing framework."""

import sys, argparse, json

def parse_cli_args(args):
    """Parse generic CLI arguments."""
    positional = []
    flags = {}
    options = {}
    
    i = 0
    while i < len(args):
        if args[i].startswith('--'):
            key = args[i][2:]
            if i + 1 < len(args) and not args[i+1].startswith('-'):
                options[key] = args[i+1]
                i += 2
            else:
                flags[key] = True
                i += 1
        elif args[i].startswith('-'):
            flags[args[i][1:]] = True
            i += 1
        else:
            positional.append(args[i])
            i += 1
    
    return {'positional': positional, 'flags': flags, 'options': options}

def main():
    p = argparse.ArgumentParser(description="Parse CLI arguments")
    p.add_argument("args", nargs='*', help="Arguments to parse")
    p.add_argument("--output", help="Output JSON")
    parsed = p.parse_args()
    
    try:
        result = parse_cli_args(parsed.args) if parsed.args else parse_cli_args(sys.argv[1:])
        output = json.dumps(result, indent=2)
        
        if parsed.output:
            json.dump(result, open(parsed.output, 'w'), indent=2)
        else:
            print(output)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
