from functools import wraps
from flask import request, jsonify
import time

# Simple rate limiting
_rate_limit_storage = {}

def rate_limit(max_requests=10, window=60):
    """Simple rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            if client_ip not in _rate_limit_storage:
                _rate_limit_storage[client_ip] = []
            
            # Clean old requests
            _rate_limit_storage[client_ip] = [
                req_time for req_time in _rate_limit_storage[client_ip] 
                if current_time - req_time < window
            ]
            
            # Check limit
            if len(_rate_limit_storage[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            # Add current request
            _rate_limit_storage[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator