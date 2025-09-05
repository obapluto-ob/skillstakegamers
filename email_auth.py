import smtplib
import random
import time
import os
import threading
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# In-memory storage for email codes
email_codes = {}
lock = threading.Lock()

def generate_code():
    return str(random.randint(100000, 999999))

def send_email_verification(email):
    """Send verification code via email"""
    code = generate_code()
    
    # Store in memory
    with lock:
        email_codes[email] = {
            'code': code,
            'attempts': 0,
            'expires': time.time() + 600,  # 10 minutes for email
            'created': time.time()
        }
    
    # Send real email
    success = send_real_email(email, code)
    
    if success:
        return True, "Verification code sent to your email"
    else:
        return False, "Failed to send email. Please try again."

def send_real_email(email, code):
    """Send real email using Gmail"""
    gmail_user = os.getenv('GMAIL_USER')
    gmail_pass = os.getenv('GMAIL_PASS')
    
    if not gmail_user or not gmail_pass:
        return False
    
    try:
        subject = "SkillStake - Verify Your Account"
        body = f"""
Welcome to SkillStake Gaming Platform!

Your verification code is: {code}

This code will expire in 10 minutes.

Please enter this code to complete your registration.

If you didn't create an account, please ignore this email.

Best regards,
SkillStake Team
        """
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False

def verify_email_code(email, entered_code):
    """Verify email code"""
    with lock:
        if email not in email_codes:
            return False, "Code expired or not found"
        
        data = email_codes[email]
        
        # Check expiry
        if time.time() > data['expires']:
            del email_codes[email]
            return False, "Code expired"
        
        # Check attempts
        if data['attempts'] >= 3:
            del email_codes[email]
            return False, "Too many attempts"
        
        # Verify code
        if data['code'] == entered_code:
            del email_codes[email]
            return True, "Email verified successfully"
        else:
            data['attempts'] += 1
            return False, f"Invalid code. {3 - data['attempts']} attempts left"