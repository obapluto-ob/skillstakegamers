import re

def validate_amount(amount):
    """Validate monetary amount"""
    try:
        amount = float(amount)
        if amount <= 0:
            return False, "Amount must be greater than 0"
        if amount > 100000:
            return False, "Amount too large"
        return True, amount
    except (ValueError, TypeError):
        return False, "Invalid amount format"

def validate_mpesa_number(number):
    """Validate M-Pesa phone number"""
    if not number:
        return False, "M-Pesa number is required"
    
    # Remove spaces and special characters
    clean_number = re.sub(r'[^\d]', '', number)
    
    # Check format (0712345678 or 712345678)
    if re.match(r'^0[17][0-9]{8}$', clean_number) or re.match(r'^[17][0-9]{8}$', clean_number):
        return True, clean_number
    
    return False, "Invalid M-Pesa number format"

def validate_username(username):
    """Validate username"""
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 20:
        return False, "Username must be less than 20 characters"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, username

def validate_file_upload(file):
    """Validate file upload"""
    if not file or not file.filename:
        return False, "No file selected"
    
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif'}
    file_ext = '.' + file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in allowed_extensions:
        return False, "Only JPG, PNG, and GIF files are allowed"
    
    return True, "File is valid"