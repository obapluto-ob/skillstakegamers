import os

# NOWPayments configuration
NOWPAYMENTS_API_KEY = os.getenv('NOWPAYMENTS_API_KEY', 'your-api-key-here')
NOWPAYMENTS_API_URL = 'https://api.nowpayments.io/v1'
REQUEST_TIMEOUT = 30