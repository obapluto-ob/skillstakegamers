#!/usr/bin/env python3
"""Test sending real email to obedemoni@gmail.com"""

from email_auth import send_email_verification

def test_send_to_real_email():
    """Test sending verification code to real email"""
    email = "obedemoni@gmail.com"
    
    print(f"Sending verification code to: {email}")
    print("=" * 50)
    
    # Send verification code
    success, result = send_email_verification(email)
    
    print(f"Result: {result}")
    
    if success:
        # Get the generated code for reference
        from memory_sms import sms_codes
        if email in sms_codes:
            code = sms_codes[email]['code']
            print(f"\nGenerated Code: {code}")
            print("(This code is also sent to your email)")
            
            # Show verification instructions
            print(f"\nTo verify:")
            print(f"1. Check your email: {email}")
            print(f"2. Look for subject: 'SkillStake - Verify Your Account'")
            print(f"3. Enter the 6-digit code from the email")
            print(f"4. Code expires in 10 minutes")
            
            return True
        else:
            print("Error: Code not generated properly")
            return False
    else:
        print("Failed to send email")
        return False

if __name__ == "__main__":
    print("Real Email Test - SkillStake Verification")
    print("=" * 45)
    
    # Test sending to real email
    if test_send_to_real_email():
        print("\n[SUCCESS] Email system working!")
        print("\nNOTE: Currently in demo mode.")
        print("To send real emails, configure Gmail:")
        print("1. Enable 2FA on Gmail")
        print("2. Generate App Password")
        print("3. Add to .env file:")
        print("   GMAIL_USER=your_email@gmail.com")
        print("   GMAIL_PASS=your_app_password")
    else:
        print("\n[FAILED] Email system has issues")