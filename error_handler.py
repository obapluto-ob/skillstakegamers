import logging
from flask import jsonify

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def handle_error(e):
    """Handle application errors"""
    logger.error(f"Application error: {str(e)}")
    return jsonify({'error': 'An error occurred'}), 500

def log_transaction(user_id, transaction_type, amount, description):
    """Log transaction"""
    logger.info(f"Transaction: User {user_id}, Type: {transaction_type}, Amount: {amount}")

def log_security_event(event_type, user_id, details):
    """Log security events"""
    logger.warning(f"Security Event: {event_type}, User: {user_id}, Details: {details}")