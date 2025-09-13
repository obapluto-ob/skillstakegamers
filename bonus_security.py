# Comprehensive Bonus Abuse Prevention System
# This module prevents users from exploiting the bonus system

import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import request, session
import re

def get_db_connection():
    return sqlite3.connect('gamebet.db')

def create_bonus_security_tables():
    """Create tables for bonus security tracking"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Track user devices and IPs
        c.execute('''CREATE TABLE IF NOT EXISTS user_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_fingerprint TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            bonus_claims INTEGER DEFAULT 0,
            is_suspicious INTEGER DEFAULT 0
        )''')
        
        # Track bonus claims with security data
        c.execute('''CREATE TABLE IF NOT EXISTS bonus_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            ip_address TEXT NOT NULL,
            device_fingerprint TEXT NOT NULL,
            security_score REAL DEFAULT 0,
            risk_factors TEXT,
            claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Track suspicious activities
        c.execute('''CREATE TABLE IF NOT EXISTS security_violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            violation_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Add new columns to users table for security
        try:
            c.execute('ALTER TABLE users ADD COLUMN last_ip TEXT')
            c.execute('ALTER TABLE users ADD COLUMN user_agent TEXT')
            c.execute('ALTER TABLE users ADD COLUMN phone_verified INTEGER DEFAULT 0')
            c.execute('ALTER TABLE users ADD COLUMN total_deposited REAL DEFAULT 0')
            c.execute('ALTER TABLE users ADD COLUMN last_bonus_claim TIMESTAMP')
            c.execute('ALTER TABLE users ADD COLUMN bonus_restriction_level INTEGER DEFAULT 0')
        except:
            pass  # Columns might already exist
        
        conn.commit()

def generate_device_fingerprint(request):
    """Generate unique device fingerprint"""
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    
    # Create fingerprint from browser characteristics
    fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest()

def check_ip_abuse(ip_address):
    """Check if IP address is being abused for bonuses"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        today = datetime.now().date()
        
        # Count unique users from this IP claiming bonuses today
        c.execute('''SELECT COUNT(DISTINCT user_id) FROM bonus_claims 
                   WHERE ip_address = ? AND DATE(claimed_at) = ?''', 
                 (ip_address, today))
        
        ip_users_today = c.fetchone()[0] or 0
        
        # Count total bonus claims from this IP today
        c.execute('''SELECT COUNT(*) FROM bonus_claims 
                   WHERE ip_address = ? AND DATE(claimed_at) = ?''', 
                 (ip_address, today))
        
        ip_claims_today = c.fetchone()[0] or 0
        
        return {
            'users_today': ip_users_today,
            'claims_today': ip_claims_today,
            'is_suspicious': ip_users_today > 3 or ip_claims_today > 5
        }

def check_device_abuse(device_fingerprint):
    """Check if device is being abused for bonuses"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Count users using this device
        c.execute('''SELECT COUNT(DISTINCT user_id) FROM user_devices 
                   WHERE device_fingerprint = ?''', (device_fingerprint,))
        
        device_users = c.fetchone()[0] or 0
        
        # Count bonus claims from this device in last 24 hours
        c.execute('''SELECT COUNT(*) FROM bonus_claims 
                   WHERE device_fingerprint = ? 
                   AND claimed_at >= datetime('now', '-24 hours')''', 
                 (device_fingerprint,))
        
        device_claims_24h = c.fetchone()[0] or 0
        
        return {
            'total_users': device_users,
            'claims_24h': device_claims_24h,
            'is_suspicious': device_users > 2 or device_claims_24h > 3
        }

def calculate_user_risk_score(user_id, ip_address, device_fingerprint):
    """Calculate comprehensive risk score for user"""
    risk_score = 0
    risk_factors = []
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Get user data
        c.execute('''SELECT created_at, total_deposited, phone_verified, 
                           bonus_restriction_level FROM users WHERE id = ?''', (user_id,))
        user_data = c.fetchone()
        
        if not user_data:
            return 1.0, ['User not found']
        
        user_created, total_deposited, phone_verified, restriction_level = user_data
        user_age_days = (datetime.now() - datetime.fromisoformat(user_created)).days
        
        # Risk Factor 1: New account without verification
        if user_age_days < 1 and not phone_verified:
            risk_score += 0.3
            risk_factors.append('New unverified account')
        
        # Risk Factor 2: No deposits but claiming bonuses
        if total_deposited == 0 and user_age_days > 7:
            risk_score += 0.4
            risk_factors.append('No deposits after 7 days')
        
        # Risk Factor 3: Multiple accounts from same IP
        ip_check = check_ip_abuse(ip_address)
        if ip_check['is_suspicious']:
            risk_score += 0.5
            risk_factors.append(f"Suspicious IP activity: {ip_check['users_today']} users today")
        
        # Risk Factor 4: Device sharing
        device_check = check_device_abuse(device_fingerprint)
        if device_check['is_suspicious']:
            risk_score += 0.4
            risk_factors.append(f"Device sharing: {device_check['total_users']} users")
        
        # Risk Factor 5: Previous violations
        c.execute('''SELECT COUNT(*) FROM security_violations 
                   WHERE user_id = ? AND created_at >= datetime('now', '-30 days')''', 
                 (user_id,))
        recent_violations = c.fetchone()[0] or 0
        
        if recent_violations > 0:
            risk_score += 0.3 * recent_violations
            risk_factors.append(f'{recent_violations} recent violations')
        
        # Risk Factor 6: Existing restriction level
        if restriction_level > 0:
            risk_score += 0.2 * restriction_level
            risk_factors.append(f'Restriction level {restriction_level}')
        
        # Risk Factor 7: Bonus-only activity pattern
        c.execute('''SELECT COUNT(*) FROM transactions 
                   WHERE user_id = ? AND type = 'daily_bonus' ''', (user_id,))
        total_bonuses = c.fetchone()[0] or 0
        
        c.execute('''SELECT COUNT(*) FROM game_matches 
                   WHERE creator_id = ? OR opponent_id = ?''', (user_id, user_id))
        total_matches = c.fetchone()[0] or 0
        
        if total_bonuses > 5 and total_matches == 0:
            risk_score += 0.6
            risk_factors.append('Bonus-only activity pattern')
        
        # Risk Factor 8: Rapid successive claims
        c.execute('''SELECT COUNT(*) FROM bonus_claims 
                   WHERE user_id = ? AND claimed_at >= datetime('now', '-1 hour')''', 
                 (user_id,))
        recent_claims = c.fetchone()[0] or 0
        
        if recent_claims > 0:
            risk_score += 0.8
            risk_factors.append('Multiple claims in short time')
    
    return min(risk_score, 1.0), risk_factors

def log_security_violation(user_id, violation_type, severity, details, ip_address):
    """Log security violation"""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO security_violations 
                   (user_id, violation_type, severity, details, ip_address)
                   VALUES (?, ?, ?, ?, ?)''',
                 (user_id, violation_type, severity, details, ip_address))
        conn.commit()

def update_user_device_tracking(user_id, ip_address, device_fingerprint, user_agent):
    """Update device tracking for user"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Check if device already exists for user
        c.execute('''SELECT id, bonus_claims FROM user_devices 
                   WHERE user_id = ? AND device_fingerprint = ?''', 
                 (user_id, device_fingerprint))
        existing = c.fetchone()
        
        if existing:
            # Update existing device
            c.execute('''UPDATE user_devices SET 
                       last_seen = CURRENT_TIMESTAMP,
                       bonus_claims = bonus_claims + 1,
                       ip_address = ?
                       WHERE id = ?''', (ip_address, existing[0]))
        else:
            # Insert new device
            c.execute('''INSERT INTO user_devices 
                       (user_id, device_fingerprint, ip_address, user_agent, bonus_claims)
                       VALUES (?, ?, ?, ?, 1)''',
                     (user_id, device_fingerprint, ip_address, user_agent))
        
        conn.commit()

def apply_bonus_restrictions(user_id, risk_score, risk_factors):
    """Apply restrictions based on risk score"""
    restriction_level = 0
    bonus_multiplier = 1.0
    
    if risk_score >= 0.8:
        # High risk - severe restrictions
        restriction_level = 3
        bonus_multiplier = 0.1  # 90% reduction
        log_security_violation(user_id, 'high_risk_bonus_claim', 'HIGH', 
                             f'Risk score: {risk_score:.2f}, Factors: {", ".join(risk_factors)}',
                             request.remote_addr)
    elif risk_score >= 0.6:
        # Medium-high risk - moderate restrictions
        restriction_level = 2
        bonus_multiplier = 0.3  # 70% reduction
        log_security_violation(user_id, 'medium_risk_bonus_claim', 'MEDIUM',
                             f'Risk score: {risk_score:.2f}, Factors: {", ".join(risk_factors)}',
                             request.remote_addr)
    elif risk_score >= 0.4:
        # Medium risk - light restrictions
        restriction_level = 1
        bonus_multiplier = 0.6  # 40% reduction
    
    # Update user restriction level
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('UPDATE users SET bonus_restriction_level = ? WHERE id = ?',
                 (restriction_level, user_id))
        conn.commit()
    
    return bonus_multiplier, restriction_level

def check_daily_bonus_pool_limit():
    """Check if daily bonus pool limit is reached"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        today = datetime.now().date()
        c.execute('''SELECT SUM(amount) FROM bonus_claims 
                   WHERE DATE(claimed_at) = ?''', (today,))
        
        daily_total = c.fetchone()[0] or 0
        
        # Daily limit: 15,000 KSh
        daily_limit = 15000
        
        return {
            'total_paid': daily_total,
            'limit': daily_limit,
            'remaining': max(0, daily_limit - daily_total),
            'limit_reached': daily_total >= daily_limit
        }

def validate_bonus_eligibility(user_id):
    """Comprehensive bonus eligibility check"""
    ip_address = request.remote_addr
    device_fingerprint = generate_device_fingerprint(request)
    user_agent = request.headers.get('User-Agent', '')
    
    # Update device tracking
    update_user_device_tracking(user_id, ip_address, device_fingerprint, user_agent)
    
    # Calculate risk score
    risk_score, risk_factors = calculate_user_risk_score(user_id, ip_address, device_fingerprint)
    
    # Check daily pool limit
    pool_status = check_daily_bonus_pool_limit()
    
    # Apply restrictions
    bonus_multiplier, restriction_level = apply_bonus_restrictions(user_id, risk_score, risk_factors)
    
    return {
        'eligible': risk_score < 0.9 and not pool_status['limit_reached'],
        'risk_score': risk_score,
        'risk_factors': risk_factors,
        'bonus_multiplier': bonus_multiplier,
        'restriction_level': restriction_level,
        'pool_status': pool_status,
        'device_fingerprint': device_fingerprint,
        'ip_address': ip_address
    }

def record_bonus_claim(user_id, amount, security_data):
    """Record bonus claim with security data"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        c.execute('''INSERT INTO bonus_claims 
                   (user_id, amount, ip_address, device_fingerprint, 
                    security_score, risk_factors)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                 (user_id, amount, security_data['ip_address'], 
                  security_data['device_fingerprint'], security_data['risk_score'],
                  ', '.join(security_data['risk_factors'])))
        
        # Update user's last bonus claim
        c.execute('UPDATE users SET last_bonus_claim = CURRENT_TIMESTAMP WHERE id = ?', 
                 (user_id,))
        
        conn.commit()

# Initialize security tables
create_bonus_security_tables()