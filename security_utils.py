def validate_payment_amount(amount):
    """Validate payment amount"""
    try:
        amount = float(amount)
        if amount < 100:
            return False, 'Minimum amount is KSh 100'
        if amount > 100000:
            return False, 'Maximum amount is KSh 100,000'
        return True, amount
    except (ValueError, TypeError):
        return False, 'Invalid amount format'

def sanitize_payment_id(payment_id):
    """Sanitize payment ID"""
    if not payment_id:
        return None
    return str(payment_id).strip()[:50]  # Limit length