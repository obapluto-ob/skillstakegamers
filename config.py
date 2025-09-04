import os
from dotenv import load_dotenv

load_dotenv()

# NOWPayments Configuration
NOWPAYMENTS_API_KEY = os.getenv('NOWPAYMENTS_API_KEY', 'your-api-key-here')
NOWPAYMENTS_API_URL = 'https://api.nowpayments.io'
REQUEST_TIMEOUT = 30

# PayPal Configuration (create this file if it doesn't exist)
PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID', 'your-paypal-client-id')
PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET', 'your-paypal-client-secret')
PAYPAL_BASE_URL = os.getenv('PAYPAL_BASE_URL', 'https://api.sandbox.paypal.com')