#!/usr/bin/env python3
"""
Telegram Alert Integration - Sends security alerts to Telegram bot.
Formats alerts with severity levels and timestamps.
"""

import argparse
import json
import os
import socket
import sys
import urllib.request
import urllib.error
from datetime import datetime

class TelegramAlertIntegration:
    """Sends formatted security alerts to Telegram."""
    
    SEVERITY_EMOJI = {
        'INFO': '🔵',
        'WARNING': '🟡',
        'CRITICAL': '🔴',
    }
    
    def __init__(self, bot_token=None, chat_id=None, test_mode=False):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.test_mode = test_mode
        self.hostname = socket.gethostname()
    
    def load_config(self, config_file):
        """Load credentials from config file."""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.bot_token = config.get('bot_token')
                self.chat_id = config.get('chat_id')
                print(f"[+] Config loaded from {config_file}")
                return True
        except FileNotFoundError:
            print(f"[-] Config file not found: {config_file}")
            return False
        except json.JSONDecodeError:
            print(f"[-] Invalid JSON in config file")
            return False
    
    def format_alert(self, message, severity='INFO'):
        """Format alert message with emoji, timestamp, and hostname."""
        if severity not in self.SEVERITY_EMOJI:
            severity = 'INFO'
        
        emoji = self.SEVERITY_EMOJI[severity]
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        formatted = (
            f"{emoji} [{severity}] {timestamp}\n"
            f"Host: {self.hostname}\n"
            f"Message: {message}"
        )
        
        return formatted
    
    def send_alert(self, message, severity='INFO'):
        """Send formatted alert to Telegram."""
        formatted_message = self.format_alert(message, severity)
        
        if self.test_mode:
            print(f"[TEST MODE] Alert formatted:\n{formatted_message}")
            return True
        
        if not self.bot_token or not self.chat_id:
            print("[-] Bot token or chat ID not configured")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            data = urllib.parse.urlencode({
                'chat_id': self.chat_id,
                'text': formatted_message,
                'parse_mode': 'Markdown'
            }).encode('utf-8')
            
            req = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                
                if result.get('ok'):
                    print(f"[+] Alert sent successfully (severity: {severity})")
                    return True
                else:
                    print(f"[-] Telegram API error: {result.get('description')}")
                    return False
        
        except urllib.error.URLError as e:
            print(f"[-] Network error: {e}")
            return False
        except Exception as e:
            print(f"[-] Error sending alert: {e}")
            return False
    
    def validate_credentials(self):
        """Validate bot token and chat ID format."""
        if not self.bot_token:
            print("[-] Bot token is required")
            return False
        
        if not self.chat_id:
            print("[-] Chat ID is required")
            return False
        
        if ':' not in self.bot_token or len(self.bot_token.split(':')) != 2:
            print("[-] Invalid bot token format (expected: ID:TOKEN)")
            return False
        
        try:
            int(self.chat_id)
        except ValueError:
            print("[-] Chat ID must be numeric")
            return False
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description='Send formatted security alerts to Telegram bot.'
    )
    parser.add_argument('message', help='Alert message')
    parser.add_argument('-t', '--token', help='Telegram bot token (or use config file)')
    parser.add_argument('-c', '--chat-id', help='Telegram chat ID (or use config file)')
    parser.add_argument('-s', '--severity', choices=['INFO', 'WARNING', 'CRITICAL'], 
                        default='INFO', help='Alert severity level (default: INFO)')
    parser.add_argument('-f', '--config', help='Config file with bot_token and chat_id')
    parser.add_argument('--test', action='store_true', help='Test mode (print alert without sending)')
    
    args = parser.parse_args()
    
    alerter = TelegramAlertIntegration(
        bot_token=args.token,
        chat_id=args.chat_id,
        test_mode=args.test
    )
    
    if args.config:
        if not alerter.load_config(args.config):
            sys.exit(1)
    
    if not alerter.test_mode and not alerter.validate_credentials():
        sys.exit(1)
    
    alerter.send_alert(args.message, args.severity)

if __name__ == "__main__":
    # Required for urllib
    import urllib.parse
    main()
