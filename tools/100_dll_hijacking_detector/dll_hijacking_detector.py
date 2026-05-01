#!/usr/bin/env python3
"""DLL Hijacking Detector - Detects DLL sideloading and hijacking attacks (Windows)."""

import sys, os, json, argparse, hashlib
from pathlib import Path

RISKY_DLLS = ['mscoree.dll', 'kernel32.dll', 'ntdll.dll', 'ole32.dll', 'oleaut32.dll']
COMMON_ABUSE_DLLS = ['version.dll', 'wininet.dll', 'urlmon.dll', 'shell32.dll']

def find_dll_duplicates(path):
    """Find duplicate DLLs in system directories."""
    dll_map = {}
    duplicates = []
    
    try:
        for dll_file in Path(path).rglob('*.dll'):
            dll_name = dll_file.name.lower()
            if dll_name not in dll_map:
                dll_map[dll_name] = []
            dll_map[dll_name].append(str(dll_file))
    except:
        pass
    
    for dll_name, paths in dll_map.items():
        if len(paths) > 1 and dll_name in COMMON_ABUSE_DLLS:
            duplicates.append({'dll': dll_name, 'locations': paths})
    
    return duplicates

def detect_sideloading(path):
    """Detect DLL sideloading in application directories."""
    sideload = []
    
    try:
        for item in Path(path).iterdir():
            if item.is_dir() and item.name not in ['System32', 'SysWOW64']:
                for dll in item.glob('*.dll'):
                    if dll.name.lower() in COMMON_ABUSE_DLLS:
                        sideload.append({'application': item.name, 'dll': dll.name, 'path': str(dll)})
    except:
        pass
    
    return sideload

def calculate_dll_hash(filepath):
    """Calculate DLL hash for integrity checking."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

def main():
    p = argparse.ArgumentParser(description="Detect DLL hijacking and sideloading attacks")
    p.add_argument("--path", default='C:\\Windows\\System32', help="Path to scan")
    p.add_argument("--output", help="Output JSON file")
    args = p.parse_args()
    
    if not os.name == 'nt':
        print("[!] DLL hijacking detection is Windows-specific", file=sys.stderr)
        print("[*] Simulating on non-Windows system")
    
    try:
        duplicates = find_dll_duplicates(args.path) if os.path.exists(args.path) else []
        sideload = detect_sideloading(os.path.dirname(args.path)) if os.path.exists(os.path.dirname(args.path)) else []
        
        print(f"[+] DLL Hijacking Detection Report")
        print(f"    Duplicate risky DLLs: {len(duplicates)}")
        print(f"    Potential sideloading: {len(sideload)}")
        
        if duplicates:
            print(f"\n[!] DUPLICATE DLL ALERT:")
            for dup in duplicates[:3]:
                print(f"    {dup['dll']} found in {len(dup['locations'])} locations")
        
        if sideload:
            print(f"\n[!] SIDELOADING DETECTED:")
            for side in sideload[:3]:
                print(f"    {side['application']}: {side['dll']}")
        
        if args.output:
            json.dump({'duplicates': duplicates, 'sideload': sideload}, open(args.output, 'w'), indent=2)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
