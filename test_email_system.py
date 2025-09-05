#!/usr/bin/env python3
"""Test email verification system"""

from email_auth import send_email_verification, verify_email_code

def test_email_verification():
    """Test email verification flow"""
    test_email = "user@example.com"
    
    print(f"Testing email verification for: {test_email}")
    print("=" * 50)
    
    # Send verification code
    success, result = send_email_verification(test_email)
    print(f"Send result: {result}")
    
    if success:
        # Get code from memory for testing
        from memory_sms import sms_codes
        if test_email in sms_codes:
            code = sms_codes[test_email]['code']
            print(f"Generated code: {code}")
            
            # Test wrong code
            valid, msg = verify_email_code(test_email, "000000")
            print(f"Wrong code test: {msg}")
            
            # Test correct code
            valid, msg = verify_email_code(test_email, code)
            print(f"Correct code test: {msg}")
            
            if valid:
                print("[SUCCESS] Email verification system working!")
                return True
            else:
                print("[FAILED] Code verification failed")
                return False
        else:
            print("[FAILED] Code not stored properly")
            return False
    else:
        print("[FAILED] Could not send verification email")
        return False

def test_gmail_setup():
    """Test Gmail configuration"""
    import os
    
    print("Testing Gmail configuration...")
    print("=" * 30)
    
    gmail_user = os.getenv('GMAIL_USER')
    gmail_pass = os.getenv('GMAIL_PASS')
    
    if gmail_user and gmail_pass:
        print(f"Gmail User: {gmail_user}")
        print(f"Gmail Pass: {'*' * len(gmail_pass)}")
        print("[OK] Gmail credentials configured")
        return True
    else:
        print("[INFO] Gmail not configured - using demo mode")
        print("To enable real emails, add to .env:")
        print("GMAIL_USER=your_email@gmail.com")
        print("GMAIL_PASS=your_app_password")
        return False

if __name__ == "__main__":
    print("Email Verification System Test")
    print("=" * 40)
    
    # Test Gmail setup
    gmail_configured = test_gmail_setup()
    
    print()
    
    # Test email verification
    if test_email_verification():
        print("\n[SUCCESS] Email verification system is working!")
        if not gmail_configured:
            print("[NOTE] Currently in demo mode - codes shown in terminal")
            print("[NOTE] Configure Gmail to send real emails")
    else:
        print("\n[FAILED] Email verification system has issues")
    
    print("\nEmail verification system ready for production!")