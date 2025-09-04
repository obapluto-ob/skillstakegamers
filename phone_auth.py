import random
import time
import os
from database import get_db_connection

# SMS verification codes storage (in production, use Redis)
verification_codes = {}

def generate_verification_code():
    """Generate 6-digit verification code"""
    return str(random.randint(100000, 999999))

def send_sms_code(phone_number):
    """Send SMS verification code"""
    code = generate_verification_code()
    
    # Store code with expiry (5 minutes)
    verification_codes[phone_number] = {
        'code': code,
        'expires': time.time() + 300,  # 5 minutes
        'attempts': 0
    }
    
    # For demo - just return the code (in production, use Twilio/SMS API)
    print(f"SMS Code for {phone_number}: {code}")
    return code

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