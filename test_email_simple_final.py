#!/usr/bin/env python3

from email_auth import send_email_verification, verify_email_code

def test_complete_flow():
    print("=== Final Email System Test ===")
    
    # Test 1: Send verification email
    print("\n1. Testing email sending...")
    test_email = "obedemoni@gmail.com"
    success, message = send_email_verification(test_email)
    print(f"Send Email: {success} - {message}")
    
    if success:
        # Test 2: Get the code and verify it
        from email_auth import email_codes
        if test_email in email_codes:
            code = email_codes[test_email]['code']
            print(f"Generated Code: {code}")
            
            # Test verification
            verify_success, verify_message = verify_email_code(test_email, code)
            print(f"Verify Code: {verify_success} - {verify_message}")
            
            if verify_success:
                print("\nEMAIL SYSTEM WORKING PERFECTLY!")
                print("Users can now register with email verification.")
                return True
            else:
                print(f"\nVerification failed: {verify_message}")
                return False
        else:
            print("\nCode not stored properly")
            return False
    else:
        print(f"\nEmail sending failed: {message}")
        return False

if __name__ == "__main__":
    test_complete_flow()