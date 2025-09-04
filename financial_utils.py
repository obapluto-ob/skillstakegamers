def safe_money_calculation(amount):
    """Safely calculate money amounts"""
    return round(float(amount), 2)

def calculate_fees(amount, fee_rate):
    """Calculate fees"""
    return safe_money_calculation(amount * fee_rate)

def calculate_winnings(bet_amount, multiplier):
    """Calculate winnings"""
    return safe_money_calculation(bet_amount * multiplier)

def validate_balance_operation(user_balance, operation_amount):
    """Validate balance operations"""
    return user_balance >= operation_amount