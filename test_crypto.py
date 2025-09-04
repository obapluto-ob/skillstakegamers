import requests
import os
from dotenv import load_dotenv

load_dotenv()

NOWPAYMENTS_API_KEY = os.getenv('NOWPAYMENTS_API_KEY')

def test_crypto_payment():
    headers = {
        'x-api-key': NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json'
    }
    
    # Test API status first
    try:
        response = requests.get('https://api.nowpayments.io/v1/status', headers=headers, timeout=10)
        print(f"API Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ NOWPayments API is working!")
            
            # Test creating a payment
            payment_data = {
                'price_amount': 15,
                'price_currency': 'usd',
                'pay_currency': 'usdttrc20',
                'order_id': f'test_{int(time.time())}',
                'order_description': 'Test payment'
            }
            
            payment_response = requests.post(
                'https://api.nowpayments.io/v1/payment',
                json=payment_data,
                headers=headers,
                timeout=10
            )
            
            print(f"Payment Status: {payment_response.status_code}")
            print(f"Payment Response: {payment_response.text}")
            
        else:
            print("❌ API not working")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    import time
    test_crypto_payment()