# PayPal Production Test Script
import requests
import os
from dotenv import load_dotenv

load_dotenv()

def test_paypal_mode():
    """Test if PayPal is in sandbox or production mode"""
    
    client_id = os.getenv('PAYPAL_CLIENT_ID')
    base_url = os.getenv('PAYPAL_BASE_URL', 'https://api.sandbox.paypal.com')
    
    print("=== PAYPAL CONFIGURATION TEST ===")
    print(f"Base URL: {base_url}")
    print(f"Client ID: {client_id[:10]}..." if client_id else "No Client ID")
    
    if 'sandbox' in base_url:
        print("STATUS: SANDBOX MODE (NO REAL MONEY)")
        print("All payments are fake")
        print("No money goes to your business account")
        print("Users get free credits")
    else:
        print("STATUS: PRODUCTION MODE (REAL MONEY)")
        print("Real payments processed")
        print("Money goes to your business account")
        print("Users pay real money")
    
    # Test API connectivity
    try:
        auth_url = f"{base_url}/v1/oauth2/token"
        print(f"\nTesting API connectivity to: {auth_url}")
        
        response = requests.post(auth_url, timeout=5)
        if response.status_code in [200, 401]:
            print("API endpoint reachable")
        else:
            print(f"API error: {response.status_code}")
            
    except Exception as e:
        print(f"Connection failed: {e}")
    
    print("\n=== RECOMMENDATIONS ===")
    if 'sandbox' in base_url:
        print("1. Get production PayPal credentials")
        print("2. Update PAYPAL_BASE_URL to https://api.paypal.com")
        print("3. Update PAYPAL_CLIENT_ID with live credentials")
        print("4. Test with small real payment")
    else:
        print("1. Verify business account is set up")
        print("2. Test with small payment")
        print("3. Monitor transaction logs")

if __name__ == "__main__":
    test_paypal_mode()