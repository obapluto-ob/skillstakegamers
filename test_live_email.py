#!/usr/bin/env python3

import requests
import time

def test_live_registration():
    print("=== LIVE EMAIL VERIFICATION TEST ===")
    
    # Test the live server
    base_url = "http://127.0.0.1:5000"
    
    # Test email sending
    email = "obedemoni153@gmail.com"
    print(f"Testing email verification to: {email}")
    
    try:
        response = requests.post(f"{base_url}/send_verification", 
                               json={"email": email},
                               timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print("✅ SUCCESS: Email verification code sent!")
                print("📧 Check your email inbox and spam folder")
                print("⏰ Email may take 1-5 minutes to arrive")
            else:
                print(f"❌ FAILED: {result.get('message')}")
        else:
            print(f"❌ HTTP ERROR: {response.status_code}")
            
    except Exception as e:
        print(f"💥 ERROR: {str(e)}")

if __name__ == "__main__":
    test_live_registration()