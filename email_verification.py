import smtplib
import random
import time
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from memory_sms import sms_codes, login_codes, lock

def generate_code():
    return str(random.randint(100000, 999999))

def send_email_code(email):
    """Send verification code via email"""
    code = generate_code()
    
    # Store in same memory system as SMS
    with lock:
        sms_codes[email] = {
            'code': code,
            'attempts': 0,
            'expires': time.time() + 300,  # 5 minutes
            'created': time.time()
        }
    
    # Email content
    subject = "SkillStake Verification Code"
    body = f"""
    Your SkillStake verification code is: {code}
    
    This code will expire in 5 minutes.
    
    DO NOT SHARE this code with anyone!
    
    If you didn't request this code, please ignore this email.
    
    Best regards,
    SkillStake Team
    """
    
    # Try multiple email methods
    success, result = send_email_multiple_ways(email, subject, body)
    
    if success:
        return True, "Verification code sent to your email"
    else:
        # Fallback: show code in terminal for demo
        print(f"EMAIL CODE for {email}: {code}")
        return True, f"Demo Mode: Your verification code is {code}"

def send_email_multiple_ways(to_email, subject, body):
    """Try multiple email sending methods"""
    
    # Method 1: Gmail SMTP (if configured)
    try:
        gmail_user = os.getenv('GMAIL_USER')
        gmail_pass = os.getenv('GMAIL_PASS')
        
        print(f"DEBUG: Gmail User: {gmail_user}")
        print(f"DEBUG: Gmail Pass: {'SET' if gmail_pass else 'NOT SET'}")
        
        if gmail_user and gmail_pass:
            result = send_gmail(to_email, subject, body, gmail_user, gmail_pass)
            print(f"DEBUG: Gmail result: {result}")
            return result
        else:
            print("DEBUG: Gmail credentials not found")
    except Exception as e:
        print(f"DEBUG: Gmail exception: {str(e)}")
    
    # Method 2: SendGrid (if configured)
    try:
        sendgrid_key = os.getenv('SENDGRID_API_KEY')
        if sendgrid_key:
            return send_sendgrid(to_email, subject, body, sendgrid_key)
        else:
            print("DEBUG: SendGrid not configured")
    except Exception as e:
        print(f"DEBUG: SendGrid exception: {str(e)}")
    
    # Method 3: Mailgun (if configured)
    try:
        mailgun_key = os.getenv('MAILGUN_API_KEY')
        mailgun_domain = os.getenv('MAILGUN_DOMAIN')
        if mailgun_key and mailgun_domain:
            return send_mailgun(to_email, subject, body, mailgun_key, mailgun_domain)
        else:
            print("DEBUG: Mailgun not configured")
    except Exception as e:
        print(f"DEBUG: Mailgun exception: {str(e)}")
    
    return False, "No email service configured"

def send_gmail(to_email, subject, body, gmail_user, gmail_pass):
    """Send email via Gmail SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = f'SkillStake Gaming <{gmail_user}>'
        msg['To'] = to_email
        msg['Subject'] = subject
        msg['Reply-To'] = gmail_user
        msg['X-Mailer'] = 'SkillStake Platform'
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        server.send_message(msg)
        server.quit()
        
        return True, "Email sent via Gmail"
    except Exception as e:
        return False, f"Gmail error: {str(e)}"

def send_sendgrid(to_email, subject, body, api_key):
    """Send email via SendGrid"""
    try:
        import sendgrid
        from sendgrid.helpers.mail import Mail
        
        sg = sendgrid.SendGridAPIClient(api_key=api_key)
        mail = Mail(
            from_email='noreply@skillstake.com',
            to_emails=to_email,
            subject=subject,
            plain_text_content=body
        )
        
        response = sg.send(mail)
        return True, f"Email sent via SendGrid: {response.status_code}"
    except Exception as e:
        return False, f"SendGrid error: {str(e)}"

def send_mailgun(to_email, subject, body, api_key, domain):
    """Send email via Mailgun"""
    try:
        import requests
        
        response = requests.post(
            f"https://api.mailgun.net/v3/{domain}/messages",
            auth=("api", api_key),
            data={
                "from": f"SkillStake <noreply@{domain}>",
                "to": to_email,
                "subject": subject,
                "text": body
            }
        )
        
        if response.status_code == 200:
            return True, "Email sent via Mailgun"
        else:
            return False, f"Mailgun error: {response.status_code}"
    except Exception as e:
        return False, f"Mailgun error: {str(e)}"

def verify_email_code(email, entered_code):
    """Verify email code (uses same system as SMS)"""
    from memory_sms import verify_code
    return verify_code(email, entered_code)