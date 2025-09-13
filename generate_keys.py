"""
Generate secure keys for SkillStake Gaming Platform
Run this script to generate new secure keys for production
"""
import secrets
import string
from werkzeug.security import generate_password_hash

def generate_secret_key(length=64):
    """Generate a cryptographically secure secret key"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_admin_password(length=16):
    """Generate a secure admin password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    print("SkillStake Security Key Generator")
    print("=" * 50)
    
    # Generate new keys
    secret_key = generate_secret_key()
    admin_password = generate_admin_password()
    admin_password_hash = generate_password_hash(admin_password)
    
    print(f"SECRET_KEY={secret_key}")
    print(f"ADMIN_PASSWORD={admin_password}")
    print()
    print("IMPORTANT SECURITY NOTES:")
    print("1. Copy these values to your .env file")
    print("2. Never commit these keys to version control")
    print("3. Store the admin password securely")
    print("4. Change NOWPayments API key if compromised")
    print("5. Generate new Gmail app password")
    print()
    print("Updated .env file should look like:")
    print("=" * 50)
    print(f"SECRET_KEY={secret_key}")
    print(f"ADMIN_PASSWORD={admin_password}")
    print("GMAIL_USER=your_new_gmail@gmail.com")
    print("GMAIL_PASS=your_new_app_password")
    print("NOWPAYMENTS_API_KEY=your_new_api_key")
    print("NOWPAYMENTS_WEBHOOK_URL=https://your-domain.com/nowpayments_webhook")
    print("PAYPAL_CLIENT_ID=your_paypal_client_id")
    print("PAYPAL_CLIENT_SECRET=your_paypal_client_secret")

if __name__ == "__main__":
    main()