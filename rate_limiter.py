from functools import wraps
from flask import request, jsonify
import time

# Rate limiting storage
rate_limit_data = {}

def rate_limit(max_requests=5, window=300):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            if client_ip not in rate_limit_data:
                rate_limit_data[client_ip] = []
            
            # Clean old requests
            rate_limit_data[client_ip] = [
                req_time for req_time in rate_limit_data[client_ip]
                if current_time - req_time < window
            ]
            
            if len(rate_limit_data[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            rate_limit_data[client_ip].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator