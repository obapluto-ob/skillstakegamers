from functools import wraps
from flask import request, jsonify, session
import time
import secrets

# Rate limiting storage
rate_limits = {}

def rate_limit_endpoint(max_requests=5, window=300):
    """Rate limit decorator for endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            if client_ip not in rate_limits:
                rate_limits[client_ip] = []
            
            # Clean old requests
            rate_limits[client_ip] = [
                req_time for req_time in rate_limits[client_ip]
                if current_time - req_time < window
            ]
            
            if len(rate_limits[client_ip]) >= max_requests:
                from flask import flash, redirect, url_for
                if request.method == 'POST':
                    flash(f'Too many attempts. Please wait {window//60} minutes before trying again.', 'error')
                    return redirect(request.url)
                return jsonify({'error': f'Too many requests. Wait {window//60} minutes.'}), 429
            
            rate_limits[client_ip].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def add_security_headers(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def generate_csrf_token():
    """Generate CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return token == session.get('csrf_token')

def secure_admin_check():
    """Secure admin check"""
    return session.get('username') == 'admin' and 'user_id' in session