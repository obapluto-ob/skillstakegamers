#!/usr/bin/env python3
"""Direct Gmail test"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

def test_gmail_direct():
    """Test Gmail SMTP directly"""
    
    gmail_user = os.getenv('GMAIL_USER')
    gmail_pass = os.getenv('GMAIL_PASS')
    
    print(f"Gmail User: {gmail_user}")
    print(f"Gmail Pass: {gmail_pass}")
    
    if not gmail_user or not gmail_pass:
        print("Gmail credentials not found in .env file")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = "obedemoni@gmail.com"
        msg['Subject'] = "SkillStake - Test Email"
        
        body = """
        Test email from SkillStake Gaming Platform!
        
        Your verification code is: 123456
        
        This is a test to confirm email delivery is working.
        
        Best regards,
        SkillStake Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to Gmail SMTP
        print("Connecting to Gmail SMTP...")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        
        print("Logging in...")
        server.login(gmail_user, gmail_pass)
        
        print("Sending email...")
        server.send_message(msg)
        server.quit()
        
        print("SUCCESS: Email sent to obedemoni@gmail.com!")
        return True
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return False

if __name__ == "__main__":
    test_gmail_direct()