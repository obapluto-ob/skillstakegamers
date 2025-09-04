# Security Enhancements for SkillStake Platform

import hashlib
import secrets
import time
from functools import wraps
from flask import session, request, jsonify, abort
import sqlite3

# Rate limiting for financial operations
RATE_LIMITS = {
    'deposit': {'limit': 5, 'window': 3600},  # 5 deposits per hour
    'withdrawal': {'limit': 3, 'window': 3600},  # 3 withdrawals per hour
    'gift': {'limit': 20, 'window': 3600},  # 20 gifts per hour
    'match_create': {'limit': 10, 'window': 3600}  # 10 matches per hour
}

def rate_limit_financial(operation_type):
    """Rate limiting decorator for financial operations"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            user_id = session['user_id']
            current_time = int(time.time())
            
            # Check rate limit
            conn = sqlite3.connect('gamebet.db')
            c = conn.cursor()
            
            # Create rate limit table if not exists
            c.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                operation_type TEXT,
                timestamp INTEGER,
                ip_address TEXT
            )''')
            
            # Clean old entries
            window = RATE_LIMITS[operation_type]['window']
            c.execute('DELETE FROM rate_limits WHERE timestamp < ?', (current_time - window,))
            
            # Count recent operations
            c.execute('SELECT COUNT(*) FROM rate_limits WHERE user_id = ? AND operation_type = ? AND timestamp > ?',
                     (user_id, operation_type, current_time - window))
            count = c.fetchone()[0]
            
            if count >= RATE_LIMITS[operation_type]['limit']:
                conn.close()
                return jsonify({'error': f'Rate limit exceeded for {operation_type}'}), 429
            
            # Log this operation
            c.execute('INSERT INTO rate_limits (user_id, operation_type, timestamp, ip_address) VALUES (?, ?, ?, ?)',
                     (user_id, operation_type, current_time, request.remote_addr))
            
            conn.commit()
            conn.close()
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_transaction_amount(amount, min_amount=1, max_amount=100000):
    """Validate transaction amounts"""
    try:
        amount = float(amount)
        if amount < min_amount or amount > max_amount:
            return False, f'Amount must be between KSh {min_amount} and KSh {max_amount}'
        return True, amount
    except (ValueError, TypeError):
        return False, 'Invalid amount format'

def generate_transaction_hash(user_id, amount, transaction_type, timestamp):
    """Generate secure transaction hash for verification"""
    data = f"{user_id}:{amount}:{transaction_type}:{timestamp}:{secrets.token_hex(16)}"
    return hashlib.sha256(data.encode()).hexdigest()

def log_security_event(user_id, event_type, details, ip_address):
    """Log security events for monitoring"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('INSERT INTO security_logs (user_id, event_type, details, ip_address) VALUES (?, ?, ?, ?)',
             (user_id, event_type, details, ip_address))
    
    conn.commit()
    conn.close()

def verify_user_balance(user_id, required_amount):
    """Verify user has sufficient balance with lock"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Use transaction to prevent race conditions
    c.execute('BEGIN IMMEDIATE')
    
    try:
        c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        result = c.fetchone()
        
        if not result:
            conn.rollback()
            conn.close()
            return False, 'User not found'
        
        balance = result[0]
        if balance < required_amount:
            conn.rollback()
            conn.close()
            return False, f'Insufficient balance. Have: KSh {balance}, Need: KSh {required_amount}'
        
        conn.commit()
        conn.close()
        return True, balance
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return False, str(e)

def encrypt_sensitive_data(data):
    """Encrypt sensitive user data"""
    # Simple encryption for demo - use proper encryption in production
    return hashlib.sha256(str(data).encode()).hexdigest()

def validate_mpesa_number(number):
    """Validate M-Pesa number format"""
    import re
    # Kenyan mobile number format
    pattern = r'^(0[17][0-9]{8}|254[17][0-9]{8})$'
    return bool(re.match(pattern, str(number).replace(' ', '').replace('+', '')))

# Session security
def secure_session_check():
    """Enhanced session security check"""
    if 'user_id' not in session:
        return False
    
    # Check session timeout (4 hours)
    if 'login_time' in session:
        if time.time() - session['login_time'] > 14400:  # 4 hours
            session.clear()
            return False
    
    # Verify session integrity
    if 'session_hash' in session:
        expected_hash = hashlib.sha256(f"{session['user_id']}:{session.get('login_time', 0)}".encode()).hexdigest()
        if session['session_hash'] != expected_hash:
            session.clear()
            return False
    
    return True

# Financial transaction security
def secure_financial_transaction(user_id, amount, transaction_type, description):
    """Secure financial transaction with multiple validations"""
    
    # Validate amount
    valid, result = validate_transaction_amount(amount)
    if not valid:
        return False, result
    amount = result
    
    # Verify balance if deduction
    if amount < 0:
        valid, balance = verify_user_balance(user_id, abs(amount))
        if not valid:
            return False, balance
    
    # Generate transaction hash
    timestamp = int(time.time())
    tx_hash = generate_transaction_hash(user_id, amount, transaction_type, timestamp)
    
    # Execute transaction
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    try:
        c.execute('BEGIN IMMEDIATE')
        
        # Update balance
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        
        # Record transaction with hash
        c.execute('''INSERT INTO transactions (user_id, type, amount, description, transaction_hash, created_at)
                     VALUES (?, ?, ?, ?, ?, datetime('now'))''',
                 (user_id, transaction_type, amount, description, tx_hash))
        
        c.execute('COMMIT')
        conn.close()
        
        # Log security event
        log_security_event(user_id, 'financial_transaction', 
                          f'{transaction_type}: KSh {amount}', request.remote_addr)
        
        return True, tx_hash
        
    except Exception as e:
        c.execute('ROLLBACK')
        conn.close()
        return False, str(e)