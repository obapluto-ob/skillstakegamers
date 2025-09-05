#!/usr/bin/env python3

from email_auth import send_email_verification, verify_email_code

def test_registration_flow():
    print("=== Testing Complete Registration Flow ===")
    
    # Test email sending
    print("\n1. Testing email verification...")
    test_email = "test@example.com"
    
    success, message = send_email_verification(test_email)
    print(f"Send result: {success}, Message: {message}")
    
    if not success:
        print("ERROR: Email sending failed!")
        return False
    
    # Get the code from memory (for testing)
    from email_auth import email_codes
    if test_email in email_codes:
        test_code = email_codes[test_email]['code']
        print(f"Generated code: {test_code}")
        
        # Test verification
        print("\n2. Testing code verification...")
        verify_success, verify_message = verify_email_code(test_email, test_code)
        print(f"Verify result: {verify_success}, Message: {verify_message}")
        
        if verify_success:
            print("\n✓ REGISTRATION FLOW TEST PASSED!")
            return True
        else:
            print(f"\n✗ Code verification failed: {verify_message}")
            return False
    else:
        print("ERROR: Code not found in memory!")
        return False

if __name__ == "__main__":
    test_registration_flow()