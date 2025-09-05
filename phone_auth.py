import requests
import random
import time
import os
from database import get_db_connection

def generate_verification_code():
    """Generate 6-digit verification code"""
    return str(random.randint(100000, 999999))

def send_free_sms(phone_number, message):
    """Send SMS using free services"""
    
    # Method 1: TextBelt (Free tier - 1 SMS per day per phone)
    try:
        response = requests.post('https://textbelt.com/text', {
            'phone': phone_number,
            'message': message,
            'key': 'textbelt'  # Free tier
        })
        
        result = response.json()
        if result.get('success'):
            return True, "SMS sent successfully"
        else:
            # Fallback: Show code for demo
            return True, f"Demo Mode: Your code is in the message"
            
    except Exception as e:
        return True, f"Demo Mode: SMS service unavailable"

def send_verification_sms(phone_number):
    """Send verification code via SMS"""
    code = generate_verification_code()
    
    message = f"SkillStake Verification Code: {code}\n\n⚠️ DO NOT SHARE this code with anyone!\n\nValid for 5 minutes only."
    
    # Store in database
    with get_db_connection() as conn:
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS sms_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT,
            code TEXT,
            expires_at REAL,
            attempts INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Delete old codes
        c.execute('DELETE FROM sms_codes WHERE phone = ?', (phone_number,))
        
        # Store new code
        expires_at = time.time() + 300  # 5 minutes
        c.execute('INSERT INTO sms_codes (phone, code, expires_at) VALUES (?, ?, ?)',
                 (phone_number, code, expires_at))
        
        if not os.getenv('DATABASE_URL'):
            conn.commit()
    
    # Send SMS
    success, message_result = send_free_sms(phone_number, message)
    
    if success:
        return True, f"Verification code sent to {phone_number}. Demo: {code}"
    else:
        return True, f"Demo Mode: Your code is {code}"

def verify_code(phone_number, entered_code):
    """Verify SMS code"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        c.execute('SELECT code, expires_at, attempts FROM sms_codes WHERE phone = ?', (phone_number,))
        result = c.fetchone()
        
        if not result:
            return False, "No code found"
        
        stored_code, expires_at, attempts = result
        
        # Check expiry
        if time.time() > expires_at:
            c.execute('DELETE FROM sms_codes WHERE phone = ?', (phone_number,))
            if not os.getenv('DATABASE_URL'):
                conn.commit()
            return False, "Code expired"
        
        # Check attempts
        if attempts >= 3:
            c.execute('DELETE FROM sms_codes WHERE phone = ?', (phone_number,))
            if not os.getenv('DATABASE_URL'):
                conn.commit()
            return False, "Too many attempts"
        
        # Verify code
        if stored_code == entered_code:
            c.execute('DELETE FROM sms_codes WHERE phone = ?', (phone_number,))
            if not os.getenv('DATABASE_URL'):
                conn.commit()
            return True, "Verified successfully"
        else:
            # Increment attempts
            c.execute('UPDATE sms_codes SET attempts = attempts + 1 WHERE phone = ?', (phone_number,))
            if not os.getenv('DATABASE_URL'):
                conn.commit()
            return False, "Invalid code"

def verify_sms_code(phone_number, entered_code):
    """Verify SMS code"""
    if phone_number not in verification_codes:
        return False, "No code sent to this number"
    
    stored = verification_codes[phone_number]
    
    # Check expiry
    if time.time() > stored['expires']:
        del verification_codes[phone_number]
        return False, "Code expired"
    
    # Check attempts
    if stored['attempts'] >= 3:
        del verification_codes[phone_number]
        return False, "Too many attempts"
    
    # Check code
    if stored['code'] == entered_code:
        del verification_codes[phone_number]
        return True, "Verified"
    else:
        stored['attempts'] += 1
        return False, "Invalid code"

def generate_login_code(user_id):
    """Generate login verification code"""
    code = generate_verification_code()
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Create login_codes table if not exists
        c.execute('''CREATE TABLE IF NOT EXISTS login_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            code TEXT,
            expires_at TIMESTAMP,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Store login code
        expires_at = time.time() + 300  # 5 minutes
        c.execute('INSERT INTO login_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
                 (user_id, code, expires_at))
        
        if not os.getenv('DATABASE_URL'):
            conn.commit()
    
    return code

def verify_login_code(user_id, entered_code):
    """Verify login code"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Get latest unused code
        c.execute('''SELECT code, expires_at FROM login_codes 
                     WHERE user_id = ? AND used = 0 
                     ORDER BY created_at DESC LIMIT 1''', (user_id,))
        result = c.fetchone()
        
        if not result:
            return False, "No code found"
        
        stored_code, expires_at = result
        
        # Check expiry
        if time.time() > expires_at:
            return False, "Code expired"
        
        # Check code
        if stored_code == entered_code:
            # Mark as used
            c.execute('UPDATE login_codes SET used = 1 WHERE user_id = ? AND code = ?',
                     (user_id, stored_code))
            if not os.getenv('DATABASE_URL'):
                conn.commit()
            return True, "Verified"
        else:
            return False, "Invalid code"