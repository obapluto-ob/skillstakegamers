# Advanced Security & Anti-Spam System

import time
import hashlib
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import re

class SecurityManager:
    def __init__(self):
        self.rate_limits = defaultdict(list)
        self.failed_attempts = defaultdict(int)
        self.banned_ips = set()
        self.suspicious_patterns = []
        
    def check_rate_limit(self, user_id, action, limit_per_minute=5):
        """Rate limiting per user per action"""
        now = time.time()
        key = f"{user_id}_{action}"
        
        # Clean old entries
        self.rate_limits[key] = [t for t in self.rate_limits[key] if now - t < 60]
        
        # Check limit
        if len(self.rate_limits[key]) >= limit_per_minute:
            return False
        
        # Add current request
        self.rate_limits[key].append(now)
        return True
    
    def check_ip_rate_limit(self, ip_address, limit_per_minute=20):
        """Global IP rate limiting"""
        now = time.time()
        
        # Clean old entries
        self.rate_limits[ip_address] = [t for t in self.rate_limits[ip_address] if now - t < 60]
        
        # Check limit
        if len(self.rate_limits[ip_address]) >= limit_per_minute:
            return False
        
        self.rate_limits[ip_address].append(now)
        return True
    
    def detect_spam_patterns(self, user_id, text_content):
        """Detect spam in user input"""
        if not text_content:
            return False
            
        spam_indicators = [
            r'http[s]?://',  # URLs
            r'www\.',        # Websites
            r'\.com|\.net|\.org',  # Domains
            r'[A-Z]{5,}',    # ALL CAPS
            r'(.)\1{4,}',    # Repeated characters
            r'money|cash|free|win|prize',  # Spam keywords
        ]
        
        text_lower = text_content.lower()
        spam_score = 0
        
        for pattern in spam_indicators:
            if re.search(pattern, text_lower):
                spam_score += 1
        
        return spam_score >= 3  # Threshold for spam
    
    def log_security_event(self, event_type, user_id, ip_address, details):
        """Log security events for monitoring"""
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO security_logs (event_type, user_id, ip_address, details, timestamp)
                     VALUES (?, ?, ?, ?, datetime('now'))''', 
                  (event_type, user_id, ip_address, details))
        
        conn.commit()
        conn.close()
    
    def check_suspicious_activity(self, user_id):
        """Check for suspicious user behavior"""
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Check recent activity patterns
        c.execute('''SELECT COUNT(*) FROM transactions 
                     WHERE user_id = ? AND created_at > datetime('now', '-1 hour')''', (user_id,))
        recent_transactions = c.fetchone()[0]
        
        c.execute('''SELECT COUNT(*) FROM matches 
                     WHERE (player1_id = ? OR player2_id = ?) 
                     AND created_at > datetime('now', '-1 hour')''', (user_id, user_id))
        recent_matches = c.fetchone()[0]
        
        conn.close()
        
        # Suspicious if too many transactions/matches in short time
        return recent_transactions > 10 or recent_matches > 15
    
    def validate_screenshot_integrity(self, screenshot_data):
        """Basic screenshot validation"""
        try:
            # Check file size (prevent huge uploads)
            if len(screenshot_data) > 5 * 1024 * 1024:  # 5MB limit
                return False, "Screenshot too large"
            
            # Check if it's actually an image
            if not screenshot_data.startswith('data:image/'):
                return False, "Invalid image format"
            
            # Check for duplicate screenshots (hash comparison)
            screenshot_hash = hashlib.md5(screenshot_data.encode()).hexdigest()
            
            conn = sqlite3.connect('gamebet.db')
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM match_results WHERE screenshot_hash = ?', (screenshot_hash,))
            duplicate_count = c.fetchone()[0]
            conn.close()
            
            if duplicate_count > 0:
                return False, "Duplicate screenshot detected"
            
            return True, screenshot_hash
            
        except Exception as e:
            return False, f"Screenshot validation failed: {str(e)}"

# Global security manager
security_manager = SecurityManager()