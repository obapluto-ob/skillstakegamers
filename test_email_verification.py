#!/usr/bin/env python3
"""Test email verification system"""

from smart_verification import *

def test_email_verification():
    """Test email verification"""
    email = "test@example.com"
    
    print(f"Testing email verification for: {email}")
    print("=" * 40)
    
    # Send verification code
    success, result = send_smart_verification(email)
    print(f"Send result: {result}")
    
    if success:
        # Get code from memory for testing
        from memory_sms import sms_codes
        if email in sms_codes:
            code = sms_codes[email]['code']
            print(f"Generated code: {code}")
            
            # Test verification
            valid, msg = verify_smart_code(email, code)
            print(f"Verification: {msg}")
            
            return valid
    
    return False

def test_phone_verification():
    """Test phone verification"""
    phone = "0729237059"
    
    print(f"\nTesting phone verification for: {phone}")
    print("=" * 40)
    
    # Send verification code
    success, result = send_smart_verification(phone)
    print(f"Send result: {result}")
    
    if success:
        # Get code from memory for testing
        from memory_sms import sms_codes
        if phone in sms_codes:
            code = sms_codes[phone]['code']
            print(f"Generated code: {code}")
            
            # Test verification
            valid, msg = verify_smart_code(phone, code)
            print(f"Verification: {msg}")
            
            return valid
    
    return False

def test_dual_verification():
    """Test dual verification (both phone and email)"""
    phone = "0729237059"
    email = "user@example.com"
    
    print(f"\nTesting dual verification:")
    print(f"Phone: {phone}")
    print(f"Email: {email}")
    print("=" * 40)
    
    # Send to both
    success, result = send_dual_verification(phone, email)
    print(f"Dual send result: {result}")
    
    # Get any code for testing
    from memory_sms import sms_codes
    test_code = None
    
    if phone in sms_codes:
        test_code = sms_codes[phone]['code']
    elif email in sms_codes:
        test_code = sms_codes[email]['code']
    
    if test_code:
        print(f"Test code: {test_code}")
        
        # Verify with dual system
        valid, msg = verify_dual_code(phone, email, test_code)
        print(f"Dual verification: {msg}")
        
        return valid
    
    return False

def test_smart_detection():
    """Test smart contact detection"""
    contacts = [
        "0729237059",
        "+254729237059", 
        "user@example.com",
        "test@gmail.com",
        "invalid_contact"
    ]
    
    print(f"\nTesting smart contact detection:")
    print("=" * 40)
    
    for contact in contacts:
        if is_email(contact):
            print(f"{contact} -> EMAIL")
        elif is_phone(contact):
            print(f"{contact} -> PHONE")
        else:
            print(f"{contact} -> INVALID")

if __name__ == "__main__":
    print("Smart Verification System Test")
    print("=" * 50)
    
    # Test smart detection
    test_smart_detection()
    
    # Test email verification
    if test_email_verification():
        print("[OK] Email verification passed")
    else:
        print("[FAIL] Email verification failed")
    
    # Test phone verification
    if test_phone_verification():
        print("[OK] Phone verification passed")
    else:
        print("[FAIL] Phone verification failed")
    
    # Test dual verification
    if test_dual_verification():
        print("[OK] Dual verification passed")
    else:
        print("[FAIL] Dual verification failed")
    
    print("\nSmart verification system ready!")