#!/usr/bin/env python3
"""Configuration Manager - Manages tool configurations in JSON/YAML formats."""

import sys, json, argparse, os

class ConfigManager:
    def __init__(self, config_file):
        self.config_file = config_file
        self.config = {}
        self.load()
    
    def load(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    self.config = json.load(f)
            except:
                self.config = {}
        else:
            self.config = {}
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
    
    def save(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def list_config(self):
        return json.dumps(self.config, indent=2)

def main():
    p = argparse.ArgumentParser(description="Manage tool configurations")
    p.add_argument("--config", default="config.json", help="Config file")
    p.add_argument("--get", help="Get config value")
    p.add_argument("--set", nargs=2, metavar=('KEY', 'VALUE'), help="Set config value")
    p.add_argument("--list", action='store_true', help="List all config")
    args = p.parse_args()
    
    try:
        mgr = ConfigManager(args.config)
        
        if args.get:
            value = mgr.get(args.get)
            print(f"{args.get}: {value}")
        elif args.set:
            mgr.set(args.set[0], args.set[1])
            mgr.save()
            print(f"[+] Set {args.set[0]} = {args.set[1]}")
        elif args.list:
            print(mgr.list_config())
        else:
            print("[+] Configuration Manager")
            print(f"    Config file: {args.config}")
            print(f"    Entries: {len(mgr.config)}")
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
