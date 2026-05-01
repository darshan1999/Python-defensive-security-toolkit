#!/usr/bin/env python3
"""
Email Extractor - Extracts email addresses from files or directories.
Validates format and categorizes by provider (corporate/free/suspicious).
"""

import sys
import os
import re
import argparse
from collections import defaultdict
from pathlib import Path

EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

FREE_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com',
    'protonmail.com', 'tutanota.com', 'temp-mail.org', '10minutemail.com'
}

def extract_emails(text: str) -> set:
    """Extract email addresses from text."""
    emails = set()
    for match in re.finditer(EMAIL_PATTERN, text):
        email = match.group(0).lower()
        emails.add(email)
    return emails

def categorize_email(email: str) -> str:
    """Categorize email by provider type."""
    domain = email.split('@')[1].lower()
    
    if domain in FREE_PROVIDERS:
        return 'FREE'
    elif domain in ('localhost', '127.0.0.1'):
        return 'LOCAL'
    else:
        return 'CORPORATE'

def detect_typosquatting(emails: set) -> dict:
    """Detect email typosquatting."""
    typosquats = {}
    common_domains = {'gmail.com', 'microsoft.com', 'apple.com', 'paypal.com'}
    
    for email in emails:
        domain = email.split('@')[1].lower()
        for common in common_domains:
            if domain != common and common.replace('a', 'a|0') in domain:
                typosquats[email] = f"Possible typosquatting of {common}"
    
    return typosquats

def main():
    parser = argparse.ArgumentParser(
        description="Extract email addresses from files or directories",
        epilog="Example: python3 email_extractor.py report.txt --output emails.txt"
    )
    parser.add_argument("input", nargs='?', default='-', help="File/directory or - for stdin")
    parser.add_argument("--output", help="Output file")
    
    args = parser.parse_args()
    
    try:
        emails = set()
        
        if args.input == '-':
            text = sys.stdin.read()
            emails = extract_emails(text)
        elif os.path.isfile(args.input):
            with open(args.input, 'rb') as f:
                text = f.read().decode('utf-8', errors='ignore')
                emails = extract_emails(text)
        elif os.path.isdir(args.input):
            for root, dirs, files in os.walk(args.input):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'rb') as f:
                            text = f.read().decode('utf-8', errors='ignore')
                            emails.update(extract_emails(text))
                    except:
                        pass
        else:
            print(f"Error: {args.input} not found", file=sys.stderr)
            return 1
        
        # Categorize
        categorized = defaultdict(list)
        for email in emails:
            category = categorize_email(email)
            categorized[category].append(email)
        
        # Detect typosquats
        typosquats = detect_typosquatting(emails)
        
        # Output
        print(f"[+] Email Extraction Report")
        print(f"    Total emails: {len(emails)}")
        for category in ['CORPORATE', 'FREE', 'LOCAL']:
            if categorized[category]:
                print(f"    {category}: {len(categorized[category])}")
        
        if typosquats:
            print(f"\n[!] TYPOSQUATTING DETECTED:")
            for email, reason in typosquats.items():
                print(f"    {email} - {reason}")
        
        if args.output:
            with open(args.output, 'w') as f:
                for email in sorted(emails):
                    f.write(f"{email}\n")
            print(f"\n[+] Results saved to {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
