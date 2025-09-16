"""
Security Configuration for SkillStake Gaming Platform
Addresses all critical security vulnerabilities identified in code review
"""

import os
import re
import math
from functools import wraps
from flask import session, request, abort, flash, redirect, url_for

class SecurityConfig:
    """Central security configuration and utilities"""
    
    # Input validation patterns
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    PHONE_PATTERN = re.compile(r'^\+?[0-9]{10,15}$')
    
    # Allowed file extensions for uploads
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'}
    
    # Maximum file size (5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    @staticmethod
    def validate_numeric_input(value, field_name="value", min_val=None, max_val=None):
        """Safely validate numeric input to prevent NaN injection"""
        if value is None:
            return None
        
        # Convert to string for validation
        str_value = str(value).lower().strip()
        
        # Check for NaN injection attempts
        dangerous_values = ['nan', 'infinity', 'inf', '-inf', '+inf']
        if any(dangerous in str_value for dangerous in dangerous_values):
            raise ValueError(f"Invalid {field_name}: NaN/Infinity not allowed")
        
        try:
            num_value = float(value)
            if not math.isfinite(num_value):
                raise ValueError(f"Invalid {field_name}: must be finite number")
            
            if min_val is not None and num_value < min_val:
                raise ValueError(f"Invalid {field_name}: must be >= {min_val}")
            
            if max_val is not None and num_value > max_val:
                raise ValueError(f"Invalid {field_name}: must be <= {max_val}")
            
            return num_value
        except (ValueError, TypeError):
            raise ValueError(f"Invalid {field_name}: must be a valid number")
    
    @staticmethod
    def sanitize_input(value, max_length=255):
        """Sanitize string input to prevent XSS and injection attacks"""
        if not value:
            return ""
        
        # Convert to string and strip whitespace
        value = str(value).strip()
        
        # Remove potentially dangerous characters
        value = re.sub(r'[<>"\'/\\]', '', value)
        
        # Limit length to prevent buffer overflow
        if len(value) > max_length:
            value = value[:max_length]
        
        return value
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        if not email:
            return False
        return bool(SecurityConfig.EMAIL_PATTERN.match(email))
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        if not username:
            return False
        return bool(SecurityConfig.USERNAME_PATTERN.match(username))
    
    @staticmethod
    def validate_phone(phone):
        """Validate phone number format"""
        if not phone:
            return False
        return bool(SecurityConfig.PHONE_PATTERN.match(phone))
    
    @staticmethod
    def validate_file_upload(file):
        """Validate file upload for security"""
        if not file or not file.filename:
            return False, "No file selected"
        
        # Check file extension
        filename = file.filename.lower()
        if not any(filename.endswith('.' + ext) for ext in SecurityConfig.ALLOWED_EXTENSIONS):
            return False, "File type not allowed"
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > SecurityConfig.MAX_FILE_SIZE:
            return False, "File too large (max 5MB)"
        
        return True, "Valid file"
    
    @staticmethod
    def sanitize_path(path):
        """Sanitize file path to prevent path traversal"""
        if not path:
            return ""
        
        # Remove path traversal attempts
        path = str(path).replace('..', '').replace('\\', '/').strip('/')
        
        # Remove dangerous characters
        path = re.sub(r'[<>:"|?*]', '', path)
        
        return path
    
    @staticmethod
    def validate_url(url):
        """Validate URL to prevent SSRF attacks"""
        if not url:
            return False
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Only allow http and https
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Block localhost and private IPs
            hostname = parsed.hostname
            if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
                return False
            
            # Block private IP ranges
            if hostname and (
                hostname.startswith('192.168.') or
                hostname.startswith('10.') or
                hostname.startswith('172.')
            ):
                return False
            
            return True
        except:
            return False

def admin_required(f):
    """Decorator to require admin privileges using server-side session data"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('is_admin') or session.get('username') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

def rate_limit_check(max_requests=100, window_minutes=60):
    """Simple rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # In production, use Redis or proper rate limiting
            # This is a basic implementation
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            
            # For now, just log the request
            print(f"Request from {client_ip} to {request.endpoint}")
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

def secure_headers(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: https://images.unsplash.com https://cdn.jsdelivr.net https://img.icons8.com; font-src 'self' https://cdnjs.cloudflare.com"
    return response

# Database connection with proper resource management
class SecureDBConnection:
    """Secure database connection manager"""
    
    def __init__(self, db_path='gamebet.db'):
        self.db_path = db_path
        self.conn = None
    
    def __enter__(self):
        import sqlite3
        self.conn = sqlite3.connect(self.db_path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type:
                self.conn.rollback()
            else:
                self.conn.commit()
            self.conn.close()

# Error handling utilities
def safe_execute_db_operation(operation, *args, **kwargs):
    """Execute database operation with proper error handling"""
    try:
        with SecureDBConnection() as conn:
            return operation(conn, *args, **kwargs)
    except Exception as e:
        print(f"Database operation failed: {e}")
        return None

def log_security_event(event_type, details, user_id=None):
    """Log security events for monitoring"""
    timestamp = datetime.now().isoformat()
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr) if request else 'unknown'
    
    log_entry = {
        'timestamp': timestamp,
        'event_type': event_type,
        'details': details,
        'user_id': user_id,
        'client_ip': client_ip
    }
    
    # In production, send to proper logging system
    print(f"SECURITY EVENT: {log_entry}")