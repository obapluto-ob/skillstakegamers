from decimal import Decimal, ROUND_HALF_UP

def safe_money_calculation(amount):
    """Safely calculate money amounts with proper precision"""
    return float(Decimal(str(amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))

def calculate_fees(amount, fee_rate):
    """Calculate fees with proper rounding"""
    return safe_money_calculation(amount * fee_rate)

def calculate_winnings(bet_amount, multiplier):
    """Calculate winnings with proper precision"""
    return safe_money_calculation(bet_amount * multiplier)

def validate_balance_operation(current_balance, operation_amount):
    """Validate balance operations"""
    if operation_amount < 0 and abs(operation_amount) > current_balance:
        return False, "Insufficient balance"
    return True, "Valid operation"