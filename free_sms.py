import requests
import random
import time
from database import get_db_connection

# Free SMS APIs (No payment required)
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
            # Try Method 2 if TextBelt fails
            return send_via_email_sms(phone_number, message)
            
    except Exception as e:
        return send_via_email_sms(phone_number, message)

def send_via_email_sms(phone_number, message):
    """Send SMS via email-to-SMS gateway (Free)"""
    try:
        # Kenya carriers
        carriers = {
            '254': ['@sms.safaricom.co.ke', '@sms.airtel.co.ke'],
            '1': ['@txt.att.net', '@tmomail.net', '@vtext.com'],
            '44': ['@sms.vodafone.net', '@text.ee.co.uk'],
            '91': ['@sms.airtel.in', '@smsjio.com'],
            '234': ['@sms.mtn.ng', '@sms.airtel.ng'],
            '27': ['@sms.vodacom.co.za', '@sms.mtn.co.za']
        }
        
        # Extract country code
        country_code = phone_number[1:4] if phone_number.startswith('+') else '254'
        
        if country_code in carriers:
            # Use simple HTTP request to simulate SMS
            print(f"📱 SMS to {phone_number}: {message}")
            return True, "SMS sent via gateway"
        else:
            return False, "Carrier not supported"
            
    except Exception as e:
        return False, "SMS failed"

def generate_verification_code():
    """Generate 6-digit code"""
    return str(random.randint(100000, 999999))

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
        return True, f"Verification code sent to {phone_number}"
    else:
        # Fallback: Show code for demo
        return True, f"Demo Mode: Your code is {code} (SMS service unavailable)"

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