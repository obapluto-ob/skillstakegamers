import os

# PayPal configuration
PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID', 'your-paypal-client-id')
PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET', 'your-paypal-client-secret')
PAYPAL_BASE_URL = 'https://api.sandbox.paypal.com'  # Use https://api.paypal.com for production