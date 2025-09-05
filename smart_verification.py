import re
from memory_sms import send_verification_code, verify_code, check_sms_rate_limit
from email_verification import send_email_code, verify_email_code

def is_email(contact):
    """Check if contact is email"""
    return '@' in contact and '.' in contact

def is_phone(contact):
    """Check if contact is phone number"""
    return re.match(r'^[0-9+\-\s()]+$', contact) and len(contact.replace(' ', '').replace('-', '').replace('(', '').replace(')', '').replace('+', '')) >= 10

def send_smart_verification(contact):
    """Smart verification - tries SMS first, falls back to email"""
    
    if is_email(contact):
        # Email verification
        print(f"Sending verification code to email: {contact}")
        return send_email_code(contact)
    
    elif is_phone(contact):
        # SMS verification with fallback
        print(f"Sending verification code to phone: {contact}")
        
        # Check SMS rate limit first
        can_send, rate_msg = check_sms_rate_limit(contact)
        if not can_send:
            return False, rate_msg
        
        # Try SMS
        sms_success, sms_result = send_verification_code(contact)
        
        # If SMS fails and we have email, try email fallback
        if not sms_success and "Demo Mode" not in sms_result:
            print("SMS failed, asking for email fallback...")
            return False, "SMS failed. Please provide your email for verification."
        
        return sms_success, sms_result
    
    else:
        return False, "Invalid contact format. Use phone (0712345678) or email (user@example.com)"

def verify_smart_code(contact, entered_code):
    """Verify code for both SMS and email"""
    if is_email(contact):
        return verify_email_code(contact, entered_code)
    elif is_phone(contact):
        return verify_code(contact, entered_code)
    else:
        return False, "Invalid contact format"

def send_dual_verification(phone, email):
    """Send verification to both phone and email"""
    results = []
    
    # Try SMS
    if phone:
        can_send, rate_msg = check_sms_rate_limit(phone)
        if can_send:
            sms_success, sms_result = send_verification_code(phone)
            results.append(f"SMS to {phone}: {sms_result}")
        else:
            results.append(f"SMS to {phone}: {rate_msg}")
    
    # Try Email
    if email:
        email_success, email_result = send_email_code(email)
        results.append(f"Email to {email}: {email_result}")
    
    return True, " | ".join(results)

def verify_dual_code(phone, email, entered_code):
    """Verify code from either phone or email"""
    
    # Try phone verification
    if phone:
        phone_valid, phone_msg = verify_code(phone, entered_code)
        if phone_valid:
            return True, f"Verified via SMS: {phone_msg}"
    
    # Try email verification
    if email:
        email_valid, email_msg = verify_email_code(email, entered_code)
        if email_valid:
            return True, f"Verified via Email: {email_msg}"
    
    return False, "Invalid code for both phone and email"