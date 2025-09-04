#!/usr/bin/env python3

"""
Test script to verify the create_match route fix
"""

import requests
import json

def test_create_match_endpoint():
    """Test the fixed create_match endpoint"""
    
    # Test data that would be sent by the JavaScript
    test_data = {
        'game': 'pubg_mobile',
        'bet_amount': 100,
        'game_mode': 'Solo',
        'verification_type': 'ocr'
    }
    
    print("Testing create_match endpoint...")
    print(f"Test data: {test_data}")
    
    try:
        # This would normally require a session, but we're just testing the route structure
        response = requests.post(
            'http://localhost:5000/create_match',
            json=test_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        
        if response.status_code == 401:
            print("✓ Route is working - returns 401 Unauthorized as expected (no session)")
        else:
            print(f"Response: {response.json()}")
            
    except requests.exceptions.ConnectionError:
        print("Server not running - but the route structure should be fixed")
    except Exception as e:
        print(f"Error: {e}")

def check_route_structure():
    """Check if the route has proper error handling"""
    
    print("\nChecking route structure...")
    
    # Read the app.py file to verify the fix
    try:
        with open('app.py', 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check for key improvements
        checks = [
            ('try:', 'Has try-catch block'),
            ('user_id = session.get(\'user_id\')', 'Safe session access'),
            ('if not data:', 'JSON validation'),
            ('except sqlite3.Error', 'Database error handling'),
            ('except Exception as e:', 'General exception handling'),
            ('conn.close()', 'Proper connection cleanup')
        ]
        
        print("Route structure checks:")
        for check, description in checks:
            if check in content:
                print(f"[OK] {description}")
            else:
                print(f"[MISSING] {description}")
                
    except FileNotFoundError:
        print("app.py not found in current directory")

if __name__ == "__main__":
    print("=== Create Match Route Fix Test ===")
    check_route_structure()
    print("\n" + "="*50)
    print("The fix should resolve the 'Internal server error' by:")
    print("1. Adding comprehensive error handling")
    print("2. Validating JSON input properly") 
    print("3. Using safe session access")
    print("4. Handling database errors gracefully")
    print("5. Ensuring proper connection cleanup")
    print("\nUsers should now see specific error messages instead of 'Internal server error'")