import os

# NOWPayments configuration
NOWPAYMENTS_API_KEY = os.getenv('NOWPAYMENTS_API_KEY')
if not NOWPAYMENTS_API_KEY:
    raise ValueError('NOWPAYMENTS_API_KEY environment variable is required')
NOWPAYMENTS_API_URL = 'https://api.nowpayments.io/v1'
REQUEST_TIMEOUT = 30