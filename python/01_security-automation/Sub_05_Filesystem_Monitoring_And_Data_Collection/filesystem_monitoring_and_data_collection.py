"""
Filesystem Monitoring And Data Collection

Security operations automation tool.
"""

import os
def list_all_files(base_path):
    for root, dirs, files in os.walk(base_path):
        for name in files:
            full_path = os.path.join(root, name)
            print(full_path)
list_all_files("/var/log")
import os
import time
def get_file_metadata(path):
    try:
        stat = os.stat(path)
        print(f"File: {path}")
        print(f"  Size: {stat.st_size} bytes")
        print(f"  Last Modified: {time.ctime(stat.st_mtime)}")
        print(f"  Created: {time.ctime(stat.st_ctime)}")
        print(f"  Permissions: {oct(stat.st_mode)[-3:]}")
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
get_file_metadata("/etc/passwd")
import hashlib
def hash_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            return hashlib.sha256(data).hexdigest()
    except Exception as e:
        return f"[ERROR] {e}"
print(hash_file("/etc/hosts"))
def hash_large_file(path, algo="sha256", buffer_size=65536):
    h = getattr(hashlib, algo)()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(buffer_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"[ERROR] {e}"
print(hash_large_file("/var/log/syslog"))
import json
def create_baseline(directory, output_file):
    baseline = {}
    for root, _, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            baseline[path] = hash_large_file(path)
    with open(output_file, "w") as out:
        json.dump(baseline, out, indent=2)
create_baseline("/etc", "baseline.json")
def compare_baseline(baseline_file):
    with open(baseline_file, "r") as f:
        old = json.load(f)
    for path, old_hash in old.items():
        new_hash = hash_large_file(path)
        if new_hash != old_hash:
            print(f"[MODIFIED] {path}")
compare_baseline("baseline.json")
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"[Modified] {event.src_path}")
    def on_created(self, event):
        print(f"[Created] {event.src_path}")
    def on_deleted(self, event):
        print(f"[Deleted] {event.src_path}")
def watch_directory(path):
    observer = Observer()
    handler = MonitorHandler()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    print(f"[INFO] Watching {path}... Press CTRL+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
watch_directory("/tmp")
import logging
logging.basicConfig(filename="fs_monitor.log", level=logging.INFO)
def log_change(event_type, path):
    logging.info(f"{event_type}: {path}")
if not path.endswith(".log"):
    hash_file(path)
from fnmatch import fnmatch
if not fnmatch(path, "*.log"):
    # Process file
    pass