import re
import socket

def is_valid_email(email):
    """Check if email format is valid"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def domain_exists(email):
    """Check if email domain can receive emails"""
    try:
        domain = email.split('@')[1]
        socket.getaddrinfo(domain, None)
        return True
    except:
        return False

def validate_email(email):
    """Complete email validation"""
    if not is_valid_email(email):
        return False, "Invalid email format"
    
    if not domain_exists(email):
        return False, "Domain doesn't exist"
    
    # Check for test domains
    test_domains = ['example.com', 'test.com', 'localhost']
    domain = email.split('@')[1].lower()
    if domain in test_domains:
        return False, f"Test domain {domain} doesn't receive emails"
    
    return True, "Valid email"

# Quick test
if __name__ == "__main__":
    test_emails = [
        "test@example.com",
        "user@gmail.com", 
        "invalid-email",
        "real@yahoo.com"
    ]
    
    for email in test_emails:
        valid, message = validate_email(email)
        print(f"{email}: {valid} - {message}")