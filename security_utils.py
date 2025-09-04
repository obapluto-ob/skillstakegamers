import re

def validate_payment_amount(amount):
    """Validate payment amount"""
    try:
        amount = float(amount)
        if amount < 100:
            return False, "Minimum deposit is KSh 100"
        if amount > 50000:
            return False, "Maximum deposit is KSh 50,000"
        return True, amount
    except (ValueError, TypeError):
        return False, "Invalid amount"

def sanitize_payment_id(payment_id):
    """Sanitize payment ID"""
    if not payment_id:
        return None
    return re.sub(r'[^a-zA-Z0-9_-]', '', str(payment_id)[:50])