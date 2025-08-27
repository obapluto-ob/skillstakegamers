# Security Configuration for GameBet Pro

import os
from datetime import timedelta

class SecurityConfig:
    # Session Security
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True  # No JS access
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # CSRF Protection
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = "memory://"
    
    # Financial Limits
    MAX_DEPOSIT = 50000  # KSh 50,000
    MIN_DEPOSIT = 100    # KSh 100
    MAX_WITHDRAWAL = 100000  # KSh 100,000
    MIN_WITHDRAWAL = 200     # KSh 200
    MAX_BET = 10000         # KSh 10,000
    MIN_BET = 50            # KSh 50
    
    # Platform Fees
    PLATFORM_FEE_RATE = 0.10  # 10%
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }

def validate_transaction_amount(amount, transaction_type):
    """Validate transaction amounts based on type"""
    try:
        amount = float(amount)
        
        if transaction_type == 'deposit':
            return SecurityConfig.MIN_DEPOSIT <= amount <= SecurityConfig.MAX_DEPOSIT
        elif transaction_type == 'withdrawal':
            return SecurityConfig.MIN_WITHDRAWAL <= amount <= SecurityConfig.MAX_WITHDRAWAL
        elif transaction_type == 'bet':
            return SecurityConfig.MIN_BET <= amount <= SecurityConfig.MAX_BET
            
        return False
    except (ValueError, TypeError):
        return False

def sanitize_input(input_string):
    """Basic input sanitization"""
    if not input_string:
        return ""
    return str(input_string).strip()