#!/usr/bin/env python3

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

def test_email_sending():
    gmail_user = os.getenv('GMAIL_USER')
    gmail_pass = os.getenv('GMAIL_PASS')
    
    print(f"Gmail User: {gmail_user}")
    print(f"Gmail Pass: {'*' * len(gmail_pass) if gmail_pass else 'NOT SET'}")
    
    if not gmail_user or not gmail_pass:
        print("ERROR: Gmail credentials not found in .env file")
        return False
    
    try:
        test_email = "obedemoni@gmail.com"
        code = "123456"
        
        subject = "SkillStake - Test Email Verification"
        body = f"""
Test email from SkillStake Gaming Platform!

Your verification code is: {code}

This is a test email to verify the email system is working.

Best regards,
SkillStake Team
        """
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = test_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        print("Connecting to Gmail SMTP server...")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        
        print("Logging in...")
        server.login(gmail_user, gmail_pass)
        
        print("Sending email...")
        server.send_message(msg)
        server.quit()
        
        print("EMAIL SENT SUCCESSFULLY!")
        return True
        
    except Exception as e:
        print(f"EMAIL FAILED: {str(e)}")
        return False

if __name__ == "__main__":
    test_email_sending()