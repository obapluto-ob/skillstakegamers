#!/usr/bin/env python3

import os
from dotenv import load_dotenv
from email_verification import send_email_code

# Load environment variables
load_dotenv()

def test_registration_flow():
    print("=== REGISTRATION EMAIL TEST ===")
    
    test_email = "obedemoni153@gmail.com"
    print(f"Testing registration email to: {test_email}")
    
    try:
        success, message = send_email_code(test_email)
        print(f"\nResult: {success}")
        print(f"Message: {message}")
        
        # Check what's in terminal output
        print("\nCheck terminal for any DEBUG messages...")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_registration_flow()