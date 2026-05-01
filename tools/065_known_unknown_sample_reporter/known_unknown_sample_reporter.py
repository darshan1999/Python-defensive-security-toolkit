#!/usr/bin/env python3
"""
Known/Unknown Sample Reporter - Classify batch of hashes as known-good/known-bad/unknown.
Maintain local JSON database of known hashes. For unknown samples, calculate suspicion score
based on first time seen, unusual path, non-standard extension. Output classification
report with counts and details.
"""

import sys
import os
import json
import argparse
import re
from datetime import datetime
from pathlib import Path


class KnownUnknownSampleReporter:
    """Classify hashes against known samples database."""
    
    DB_FILE = "known_samples.json"
    
    KNOWN_GOOD = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file
    ]
    
    KNOWN_BAD = [
        "5d41402abc4b2a76b9719d911017c592",  # common test hash
    ]
    
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.vbs', '.js', '.ps1', '.bat', '.cmd',
        '.com', '.pif', '.msi', '.rar', '.7z', '.zip'
    }
    
    SUSPICIOUS_PATHS = {
        'temp', 'tmp', 'appdata', 'programdata', 'windows\\system',
        'recycler', 'recycle.bin', 'downloads'
    }
    
    def __init__(self, db_file=None):
        self.db_file = db_file or self.DB_FILE
        self.database = self._load_database()
        self.session_timestamp = datetime.now().isoformat()
    
    def _load_database(self):
        """Load known samples database from JSON file."""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Warning: Failed to load database: {e}")
                return {'known_good': [], 'known_bad': [], 'unknown': []}
        return {'known_good': [], 'known_bad': [], 'unknown': []}
    
    def _save_database(self):
        """Save database to JSON file."""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.database, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Failed to save database: {e}")
    
    def classify_hash(self, sha256_hash, filepath=None):
        """Classify a hash as known-good, known-bad, or unknown."""
        hash_lower = sha256_hash.lower().strip()
        
        if not self._validate_sha256(hash_lower):
            return {'status': 'invalid', 'confidence': 0, 'evidence': []}
        
        # Check against built-in lists
        if hash_lower in self.KNOWN_GOOD or any(h['hash'] == hash_lower for h in self.database.get('known_good', [])):
            return {'status': 'known-good', 'confidence': 0.95, 'evidence': ['In known-good database']}
        
        if hash_lower in self.KNOWN_BAD or any(h['hash'] == hash_lower for h in self.database.get('known_bad', [])):
            return {'status': 'known-bad', 'confidence': 0.95, 'evidence': ['In known-bad database']}
        
        # Unknown classification with suspicion score
        suspicion_score = self._calculate_suspicion_score(hash_lower, filepath)
        evidence = self._gather_evidence(hash_lower, filepath)
        
        return {
            'status': 'unknown',
            'confidence': suspicion_score / 100.0,
            'suspicion_score': suspicion_score,
            'evidence': evidence
        }
    
    def _validate_sha256(self, hash_val):
        """Validate SHA256 hash format."""
        return bool(hash_val) and len(hash_val) == 64 and all(c in '0123456789abcdef' for c in hash_val)
    
    def _calculate_suspicion_score(self, hash_val, filepath=None):
        """Calculate suspicion score (0-100) for unknown sample."""
        score = 0
        
        # Time-based: first time seeing this hash
        score += 20
        
        # Path analysis
        if filepath:
            filepath_lower = filepath.lower()
            
            # Suspicious path locations
            for suspicious in self.SUSPICIOUS_PATHS:
                if suspicious in filepath_lower:
                    score += 15
                    break
            
            # Suspicious extensions
            ext = Path(filepath).suffix.lower()
            if ext in self.SUSPICIOUS_EXTENSIONS:
                score += 20
            
            # Unusual path patterns
            if '\\' in filepath and '/' in filepath:
                score += 10
        
        return min(score, 100)
    
    def _gather_evidence(self, hash_val, filepath=None):
        """Gather evidence for classification."""
        evidence = []
        evidence.append(f"Hash: {hash_val}")
        evidence.append("First time seen in this database")
        
        if filepath:
            evidence.append(f"Path: {filepath}")
            ext = Path(filepath).suffix.lower()
            if ext in self.SUSPICIOUS_EXTENSIONS:
                evidence.append(f"Suspicious extension: {ext}")
            
            filepath_lower = filepath.lower()
            for suspicious in self.SUSPICIOUS_PATHS:
                if suspicious in filepath_lower:
                    evidence.append(f"Suspicious path component: {suspicious}")
        
        return evidence
    
    def process_file(self, input_file):
        """Process file with one SHA256 hash per line."""
        classifications = {
            'known_good': [],
            'known_bad': [],
            'unknown': []
        }
        
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        try:
            with open(input_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    parts = line.strip().split(',', 1)
                    if not parts[0]:
                        continue
                    
                    hash_val = parts[0].strip()
                    filepath = parts[1].strip() if len(parts) > 1 else None
                    
                    result = self.classify_hash(hash_val, filepath)
                    result['line'] = line_num
                    
                    if result['status'] == 'known-good':
                        classifications['known_good'].append(result)
                    elif result['status'] == 'known-bad':
                        classifications['known_bad'].append(result)
                    elif result['status'] == 'unknown':
                        classifications['unknown'].append(result)
        
        except Exception as e:
            raise Exception(f"Failed to process file: {e}")
        
        return classifications
    
    def generate_report(self, classifications):
        """Generate formatted classification report."""
        report = []
        report.append("=" * 80)
        report.append("KNOWN/UNKNOWN SAMPLE CLASSIFICATION REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {self.session_timestamp}")
        report.append("")
        
        report.append("SUMMARY")
        report.append("-" * 80)
        total = len(classifications['known_good']) + len(classifications['known_bad']) + len(classifications['unknown'])
        report.append(f"  Total Samples: {total}")
        report.append(f"  Known-Good: {len(classifications['known_good'])}")
        report.append(f"  Known-Bad: {len(classifications['known_bad'])}")
        report.append(f"  Unknown: {len(classifications['unknown'])}")
        report.append("")
        
        if classifications['known_bad']:
            report.append("KNOWN MALICIOUS SAMPLES")
            report.append("-" * 80)
            for item in classifications['known_bad']:
                report.append(f"  SHA256: {item['evidence'][0].split(': ')[1]}")
                for evidence in item['evidence'][1:]:
                    report.append(f"    {evidence}")
            report.append("")
        
        if classifications['unknown']:
            report.append("UNKNOWN SAMPLES (Risk Assessment)")
            report.append("-" * 80)
            
            high_risk = [x for x in classifications['unknown'] if x.get('suspicion_score', 0) >= 50]
            medium_risk = [x for x in classifications['unknown'] if 20 <= x.get('suspicion_score', 0) < 50]
            low_risk = [x for x in classifications['unknown'] if x.get('suspicion_score', 0) < 20]
            
            if high_risk:
                report.append("  HIGH RISK (Suspicion ≥ 50):")
                for item in high_risk[:10]:
                    hash_val = item['evidence'][0].split(': ')[1]
                    score = item.get('suspicion_score', 0)
                    report.append(f"    [{score}] {hash_val}")
            
            if medium_risk:
                report.append("  MEDIUM RISK (20-50):")
                for item in medium_risk[:5]:
                    hash_val = item['evidence'][0].split(': ')[1]
                    score = item.get('suspicion_score', 0)
                    report.append(f"    [{score}] {hash_val}")
            
            report.append(f"  Total Unknown: {len(classifications['unknown'])}")
        
        report.append("=" * 80)
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description='Classify batch of hashes as known-good/known-bad/unknown',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 known_unknown_sample_reporter.py -i hashes.txt
  python3 known_unknown_sample_reporter.py -i hashes.txt -d custom_db.json
  
Input file format (one per line):
  sha256_hash,optional_file_path
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,/path/to/file.exe
        """)
    
    parser.add_argument('-i', '--input', required=True, help='Input file with SHA256 hashes (one per line)')
    parser.add_argument('-d', '--database', help='Path to known samples database JSON')
    
    args = parser.parse_args()
    
    try:
        reporter = KnownUnknownSampleReporter(db_file=args.database)
        classifications = reporter.process_file(args.input)
        report = reporter.generate_report(classifications)
        print(report)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
