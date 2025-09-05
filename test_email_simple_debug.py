import smtplib
import os
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

def test_gmail_direct():
    gmail_user = os.getenv('GMAIL_USER')
    gmail_pass = os.getenv('GMAIL_PASS')
    
    print(f"Testing Gmail SMTP with: {gmail_user}")
    
    # Test email
    test_email = input("Enter recipient email: ").strip()
    
    try:
        msg = MIMEText("Test email from SkillStake platform")
        msg['Subject'] = "SkillStake Test Email"
        msg['From'] = gmail_user
        msg['To'] = test_email
        
        print("Connecting to Gmail SMTP...")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        
        print("Logging in...")
        server.login(gmail_user, gmail_pass)
        
        print("Sending email...")
        server.send_message(msg)
        server.quit()
        
        print("SUCCESS: Email sent!")
        
    except Exception as e:
        print(f"ERROR: {str(e)}")

if __name__ == "__main__":
    test_gmail_direct()