import threading
import time

# In-memory storage for codes
sms_codes = {}
login_codes = {}
lock = threading.Lock()

def verify_code(identifier, entered_code):
    """Verify SMS/email code"""
    with lock:
        if identifier not in sms_codes:
            return False, "No code found"
        
        code_data = sms_codes[identifier]
        
        # Check expiry
        if time.time() > code_data['expires']:
            del sms_codes[identifier]
            return False, "Code expired"
        
        # Check attempts
        if code_data['attempts'] >= 3:
            del sms_codes[identifier]
            return False, "Too many attempts"
        
        # Check code
        if code_data['code'] == entered_code:
            del sms_codes[identifier]
            return True, "Code verified"
        else:
            code_data['attempts'] += 1
            return False, "Invalid code"