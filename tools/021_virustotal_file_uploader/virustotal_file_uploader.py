#!/usr/bin/env python3
"""
VirusTotal File Uploader - Upload files to VirusTotal API v3 and poll for results.
"""

import sys, os, argparse, hashlib, json, time
import urllib.request, urllib.error
from datetime import datetime

class VirustotalFileUploader:
    """Upload files to VirusTotal API v3 and retrieve analysis results."""
    
    VT_API_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key):
        self.api_key = api_key
    
    def calculate_sha256(self, file_path):
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            print(f"[-] File not found: {file_path}"); sys.exit(1)
    
    def check_hash_exists(self, sha256_hash):
        """Check if file hash already exists in VirusTotal."""
        url = f"{self.VT_API_URL}/files/{sha256_hash}"
        req = urllib.request.Request(url, headers={"x-apikey": self.api_key})
        try:
            response = urllib.request.urlopen(req)
            return json.loads(response.read().decode()).get("data", {})
        except urllib.error.HTTPError as e:
            return None if e.code == 404 else (_ for _ in ()).throw(e)
    
    def upload_file(self, file_path):
        """Upload file to VirusTotal."""
        url = f"{self.VT_API_URL}/files"
        with open(file_path, "rb") as f:
            file_data = f.read()
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{os.path.basename(file_path)}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + file_data + f'\r\n--{boundary}--\r\n'.encode()
        req = urllib.request.Request(url, data=body, headers={
            "x-apikey": self.api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}"
        })
        try:
            response = urllib.request.urlopen(req)
            return json.loads(response.read().decode()).get("data", {}).get("id", "").split("/")[-1]
        except Exception as e:
            print(f"[-] Upload failed: {e}"); sys.exit(1)
    
    def get_analysis_results(self, analysis_id, timeout=60):
        """Poll for analysis results up to timeout seconds."""
        url = f"{self.VT_API_URL}/analyses/{analysis_id}"
        start_time = time.time()
        while time.time() - start_time < timeout:
            req = urllib.request.Request(url, headers={"x-apikey": self.api_key})
            try:
                data = json.loads(urllib.request.urlopen(req).read().decode())
                status = data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed": return data.get("data", {})
                print(f"[*] Polling... Status: {status}"); time.sleep(5)
            except urllib.error.HTTPError as e:
                print(f"[-] Error: {e}"); sys.exit(1)
        print("[-] Timeout: Analysis did not complete within 60 seconds"); return None
    
    def process(self, file_path):
        """Process file: calculate hash, check exists, upload if not, get results."""
        print(f"[*] Processing file: {file_path}")
        sha256_hash = self.calculate_sha256(file_path)
        print(f"[*] SHA256: {sha256_hash}")
        existing = self.check_hash_exists(sha256_hash)
        if existing:
            print("[+] File hash found in VirusTotal"); return existing
        print("[*] Uploading file...")
        analysis_id = self.upload_file(file_path)
        print(f"[*] Analysis ID: {analysis_id}")
        print("[*] Polling for results...")
        return self.get_analysis_results(analysis_id)
    
    def report(self, results):
        """Display threat analysis results."""
        if not results:
            print("[-] No results available"); return
        attrs = results.get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        print("\n" + "="*60)
        print("VIRUSTOTAL ANALYSIS REPORT")
        print("="*60)
        print(f"Detection Ratio: {last_analysis.get('malicious', 0)}/{last_analysis.get('malicious', 0) + last_analysis.get('undetected', 0)}")
        print(f"Malicious: {last_analysis.get('malicious', 0)} | Suspicious: {last_analysis.get('suspicious', 0)}")
        print("="*60)

def main():
    if "--example" in sys.argv:
        print("Usage:\n  VT_API_KEY=key python3 virustotal_file_uploader.py /path/to/file.exe"); sys.exit(0)
    parser = argparse.ArgumentParser(description="Upload file to VirusTotal API v3")
    parser.add_argument("file_path", help="Path to file to upload")
    parser.add_argument("-k", "--api-key", help="VirusTotal API key (or set VT_API_KEY env var)")
    args = parser.parse_args()
    api_key = args.api_key or os.getenv("VT_API_KEY")
    if not api_key:
        print("[-] VirusTotal API key not provided"); sys.exit(1)
    tool = VirustotalFileUploader(api_key)
    results = tool.process(args.file_path)
    tool.report(results)

if __name__ == "__main__":
    main()
