#!/usr/bin/env python3
"""
Rotating Log Handler - Security-aware rotating log handler.

Writes events to file, rotating at size limit (default 10MB).
Keeps configurable backups (default 5).
Log format: ISO timestamp, severity, source, event_type, message.
Supports: DEBUG, INFO, WARNING, ERROR, CRITICAL levels.
Uses logging.handlers.RotatingFileHandler.
"""

import argparse
import logging
import logging.handlers
import json
from datetime import datetime

class SecurityLogHandler:
    """Security-focused rotating log handler."""
    
    def __init__(self, log_file, max_bytes=10*1024*1024, backup_count=5):
        self.log_file = log_file
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """Setup rotating file handler."""
        logger = logging.getLogger('security')
        logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        logger.handlers = []
        
        # Create rotating file handler
        handler = logging.handlers.RotatingFileHandler(
            self.log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        
        # Custom formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def log_event(self, severity, source, event_type, message):
        """Log a security event."""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'source': source,
            'event_type': event_type,
            'message': message
        }
        
        severity_upper = severity.upper()
        
        if severity_upper == 'CRITICAL':
            self.logger.critical(json.dumps(log_data))
        elif severity_upper == 'ERROR':
            self.logger.error(json.dumps(log_data))
        elif severity_upper == 'WARNING':
            self.logger.warning(json.dumps(log_data))
        elif severity_upper == 'INFO':
            self.logger.info(json.dumps(log_data))
        else:  # DEBUG
            self.logger.debug(json.dumps(log_data))
    
    def log_alert(self, source, alert_type, details):
        """Log a security alert."""
        self.log_event('CRITICAL', source, alert_type, json.dumps(details))
    
    def log_warning(self, source, warning_type, details):
        """Log a warning."""
        self.log_event('WARNING', source, warning_type, json.dumps(details))
    
    def get_logger(self):
        """Return the logger instance."""
        return self.logger

def main():
    parser = argparse.ArgumentParser(
        description='Security-aware rotating log handler.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rotating_log_handler.py --log security.log
  python3 rotating_log_handler.py --log /var/log/security.log --max 20 --backups 10
  python3 rotating_log_handler.py --log events.log --max 50 --backups 5
        """)
    
    parser.add_argument('--log', type=str, required=True, help='Log file path')
    parser.add_argument('--max', type=int, default=10, help='Max size in MB (default 10)')
    parser.add_argument('--backups', type=int, default=5, help='Number of backups (default 5)')
    parser.add_argument('--event', type=str, help='Log a test event')
    
    args = parser.parse_args()
    
    max_bytes = args.max * 1024 * 1024
    
    handler = SecurityLogHandler(
        args.log,
        max_bytes=max_bytes,
        backup_count=args.backups
    )
    
    print(f"[+] Security log handler initialized", flush=True)
    print(f"[+] Log file: {args.log}", flush=True)
    print(f"[+] Max size: {args.max}MB", flush=True)
    print(f"[+] Backups: {args.backups}", flush=True)
    
    if args.event:
        print(f"[*] Logging test event...", flush=True)
        handler.log_event('INFO', 'TEST', 'test_event', args.event)
        print(f"[+] Event logged")
    
    # Example usage
    print(f"\n[*] Example usage in Python:", flush=True)
    print(f"""
from rotating_log_handler import SecurityLogHandler

handler = SecurityLogHandler('security.log', max_bytes=20*1024*1024, backup_count=5)

# Log various events
handler.log_event('INFO', 'auth_system', 'login', 'User authenticated')
handler.log_alert('firewall', 'port_scan', {{'source_ip': '192.168.1.100', 'ports': '1-1000'}})
handler.log_warning('system', 'disk_usage', {{'disk': '/dev/sda1', 'usage': '95%'}})
    """)

if __name__ == "__main__":
    main()
