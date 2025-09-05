#!/usr/bin/env python3

import os
from dotenv import load_dotenv
from email_verification import send_email_code

# Load environment variables
load_dotenv()

def test_email_sending():
    print("=== EMAIL DEBUG TEST ===")
    
    # Check environment variables
    gmail_user = os.getenv('GMAIL_USER')
    gmail_pass = os.getenv('GMAIL_PASS')
    
    print(f"Gmail User: {gmail_user}")
    print(f"Gmail Pass: {'*' * len(gmail_pass) if gmail_pass else 'NOT SET'}")
    
    # Test email sending
    test_email = input("Enter test email address: ").strip()
    
    if not test_email:
        print("No email provided!")
        return
    
    print(f"\nSending verification code to: {test_email}")
    
    try:
        success, message = send_email_code(test_email)
        print(f"Result: {success}")
        print(f"Message: {message}")
        
        if success:
            print("\n✅ Email verification code sent successfully!")
        else:
            print("\n❌ Email sending failed!")
            
    except Exception as e:
        print(f"\n💥 Error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_email_sending()