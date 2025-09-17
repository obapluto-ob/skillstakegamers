"""
Security Configuration Module for SkillStake Gaming Platform
Provides security validation, database connection management, and admin controls
"""

import sqlite3
import re
import html
from functools import wraps
from flask import session, flash, redirect, url_for

class SecurityConfig:
    """Security configuration and validation functions"""
    
    @staticmethod
    def validate_numeric_input(value, min_val=0, max_val=float('inf')):
        """Validate numeric input with range checking"""
        try:
            num_val = float(value)
            if min_val <= num_val <= max_val:
                return num_val
            return None
        except (ValueError, TypeError):
            return None
    
    @staticmethod
    def sanitize_input(text):
        """Sanitize text input to prevent XSS and injection attacks"""
        if not text:
            return ""
        
        # Remove potentially dangerous characters
        text = str(text).strip()
        
        # HTML escape
        text = html.escape(text)
        
        # Remove SQL injection patterns
        dangerous_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
            r'(--|#|/\*|\*/)',
            r'(\bOR\b.*=.*\bOR\b)',
            r'(\bAND\b.*=.*\bAND\b)',
            r'(\'|\"|`)',
        ]
        
        for pattern in dangerous_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        return text[:200]  # Limit length
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        if not email:
            return False
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        if not username:
            return False
        
        # 3-20 characters, letters, numbers, underscores only
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return re.match(pattern, username) is not None
    
    @staticmethod
    def validate_phone(phone):
        """Validate phone number format"""
        if not phone:
            return False
        
        # Kenyan phone number format
        pattern = r'^(\+254|0)[7-9]\d{8}$'
        return re.match(pattern, phone) is not None

class SecureDBConnection:
    """Secure database connection context manager"""
    
    def __init__(self):
        self.conn = None
    
    def __enter__(self):
        try:
            self.conn = sqlite3.connect('gamebet.db', timeout=30.0)
            self.conn.row_factory = sqlite3.Row
            
            # Enable foreign key constraints
            self.conn.execute('PRAGMA foreign_keys = ON')
            
            # Set secure journal mode
            self.conn.execute('PRAGMA journal_mode = WAL')
            
            return self.conn
        except Exception as e:
            if self.conn:
                self.conn.close()
            raise e
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                try:
                    self.conn.commit()
                except Exception:
                    self.conn.rollback()
                    raise
            else:
                self.conn.rollback()
            
            self.conn.close()

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin') or session.get('username') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def secure_headers(response):
    """Add security headers to response"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https: http:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "connect-src 'self' https:; "
        "frame-src 'none';"
    )
    
    return response

class FraudDetection:
    """Fraud detection and prevention utilities"""
    
    @staticmethod
    def check_velocity_limits(user_id, action_type, time_window_hours=1, max_actions=10):
        """Check if user is performing actions too quickly"""
        try:
            with SecureDBConnection() as conn:
                c = conn.cursor()
                
                if action_type == 'match_creation':
                    c.execute('''SELECT COUNT(*) FROM game_matches 
                                WHERE creator_id = ? AND created_at > datetime('now', '-{} hours')'''.format(time_window_hours), 
                             (user_id,))
                elif action_type == 'transactions':
                    c.execute('''SELECT COUNT(*) FROM transactions 
                                WHERE user_id = ? AND created_at > datetime('now', '-{} hours')'''.format(time_window_hours), 
                             (user_id,))
                else:
                    return False
                
                count = c.fetchone()[0]
                return count >= max_actions
                
        except Exception:
            return True  # Err on the side of caution
    
    @staticmethod
    def detect_collusion(user1_id, user2_id):
        """Detect potential collusion between users"""
        try:
            with SecureDBConnection() as conn:
                c = conn.cursor()
                
                # Check match frequency
                c.execute('''SELECT COUNT(*) FROM game_matches 
                            WHERE (creator_id = ? AND opponent_id = ?) OR (creator_id = ? AND opponent_id = ?)
                            AND created_at > datetime('now', '-7 days')''', 
                         (user1_id, user2_id, user2_id, user1_id))
                
                recent_matches = c.fetchone()[0]
                
                # More than 10 matches in a week is suspicious
                if recent_matches > 10:
                    return True
                
                # Check for alternating wins pattern
                c.execute('''SELECT winner_id FROM game_matches 
                            WHERE (creator_id = ? AND opponent_id = ?) OR (creator_id = ? AND opponent_id = ?)
                            AND status = 'completed' ORDER BY completed_at DESC LIMIT 6''', 
                         (user1_id, user2_id, user2_id, user1_id))
                
                winners = [row[0] for row in c.fetchall()]
                
                if len(winners) >= 4:
                    # Check for perfect alternation
                    alternating = True
                    for i in range(1, len(winners)):
                        if winners[i] == winners[i-1]:
                            alternating = False
                            break
                    
                    if alternating:
                        return True
                
                return False
                
        except Exception:
            return True  # Err on the side of caution
    
    @staticmethod
    def validate_match_result(creator_score, opponent_score, game_type):
        """Validate match result based on game type"""
        # Basic validation - scores should be reasonable
        if creator_score < 0 or opponent_score < 0:
            return False
        
        # Game-specific validation
        if game_type.lower() in ['fifa_mobile', 'efootball']:
            # Football games rarely have scores above 10
            if creator_score > 15 or opponent_score > 15:
                return False
        
        elif game_type.lower() == 'fpl_battles':
            # FPL scores are typically 30-150 points
            if creator_score > 200 or opponent_score > 200:
                return False
        
        return True

class RateLimiter:
    """Rate limiting utilities"""
    
    @staticmethod
    def check_rate_limit(user_id, action, limit_per_hour=10):
        """Check if user has exceeded rate limit for specific action"""
        try:
            with SecureDBConnection() as conn:
                c = conn.cursor()
                
                # Create rate_limits table if it doesn't exist
                c.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
                
                # Clean old entries
                c.execute('DELETE FROM rate_limits WHERE timestamp < datetime("now", "-1 hour")')
                
                # Check current count
                c.execute('SELECT COUNT(*) FROM rate_limits WHERE user_id = ? AND action = ?', 
                         (user_id, action))
                
                current_count = c.fetchone()[0]
                
                if current_count >= limit_per_hour:
                    return False
                
                # Add new entry
                c.execute('INSERT INTO rate_limits (user_id, action) VALUES (?, ?)', 
                         (user_id, action))
                
                return True
                
        except Exception:
            return False  # Deny on error

# Security middleware functions
def validate_session():
    """Validate session integrity"""
    required_keys = ['user_id', 'username']
    
    for key in required_keys:
        if key not in session:
            return False
    
    # Additional validation can be added here
    return True

def log_security_event(user_id, event_type, description, severity='medium'):
    """Log security events for monitoring"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Create security_logs table if it doesn't exist
            c.execute('''CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            c.execute('''INSERT INTO security_logs (user_id, event_type, description, severity) 
                        VALUES (?, ?, ?, ?)''', 
                     (user_id, event_type, description, severity))
            
    except Exception as e:
        print(f"Error logging security event: {e}")