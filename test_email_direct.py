#!/usr/bin/env python3

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import email verification
from email_verification import send_email_code, verify_email_code

def test_email_system():
    print("=== DIRECT EMAIL SYSTEM TEST ===")
    
    # Test email
    test_email = "obedemoni153@gmail.com"
    
    print(f"Testing email to: {test_email}")
    print(f"Gmail User: {os.getenv('GMAIL_USER')}")
    print(f"Gmail Pass: {'SET' if os.getenv('GMAIL_PASS') else 'NOT SET'}")
    
    # Send verification code
    success, message = send_email_code(test_email)
    
    print(f"Send Result: {success}")
    print(f"Message: {message}")
    
    if success:
        print("✅ Email system is working!")
        print("📧 Check your email for the verification code")
        
        # Test verification
        code = input("Enter the code you received: ")
        is_valid, verify_msg = verify_email_code(test_email, code)
        
        print(f"Verification Result: {is_valid}")
        print(f"Verification Message: {verify_msg}")
    else:
        print("❌ Email system failed")

if __name__ == "__main__":
    test_email_system()