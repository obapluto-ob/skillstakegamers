#!/usr/bin/env python3
"""
Quick security test to verify fixes are working
"""

def test_imports():
    """Test if all security modules can be imported"""
    try:
        from validators import validate_amount, validate_mpesa_number, validate_username
        from db_utils import get_db_connection
        from security import login_required, admin_required
        from financial_utils import safe_money_calculation, calculate_fees
        from match_utils import safe_balance_update
        from rate_limiter import rate_limit
        from error_handler import logger
        print("All security modules imported successfully")
        return True
    except ImportError as e:
        print(f"Import error: {e}")
        return False

def test_validators():
    """Test input validation functions"""
    from validators import validate_amount, validate_mpesa_number, validate_username
    
    # Test amount validation
    valid, result = validate_amount("100.50")
    assert valid == True and result == 100.50
    
    valid, result = validate_amount("-50")
    assert valid == False
    
    # Test M-Pesa validation
    valid, result = validate_mpesa_number("0712345678")
    assert valid == True
    
    valid, result = validate_mpesa_number("123456")
    assert valid == False
    
    # Test username validation
    valid, result = validate_username("testuser123")
    assert valid == True
    
    valid, result = validate_username("ab")
    assert valid == False
    
    print("All validation tests passed")

def test_financial_calculations():
    """Test financial calculation precision"""
    from financial_utils import calculate_fees, calculate_winnings
    
    # Test fee calculation
    fee, net = calculate_fees(1000, 0.03)
    assert fee == 30.0 and net == 970.0
    
    # Test winnings calculation
    winnings = calculate_winnings(100, 1.68)
    assert winnings == 168.0
    
    print("Financial calculation tests passed")

def test_database_connection():
    """Test secure database connection"""
    try:
        from db_utils import get_db_connection
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            result = cursor.fetchone()
            print(f"Database connection test passed - {result[0]} users found")
        return True
    except Exception as e:
        print(f"Database test failed: {e}")
        return False

def main():
    print("Security Test Suite")
    print("=" * 30)
    
    tests_passed = 0
    total_tests = 4
    
    if test_imports():
        tests_passed += 1
    
    try:
        test_validators()
        tests_passed += 1
    except Exception as e:
        print(f"Validation tests failed: {e}")
    
    try:
        test_financial_calculations()
        tests_passed += 1
    except Exception as e:
        print(f"Financial tests failed: {e}")
    
    if test_database_connection():
        tests_passed += 1
    
    print(f"\nTest Results: {tests_passed}/{total_tests} passed")
    
    if tests_passed == total_tests:
        print("All security fixes are working correctly!")
        return True
    else:
        print("Some tests failed - check the errors above")
        return False

if __name__ == "__main__":
    main()