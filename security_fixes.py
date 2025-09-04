from functools import wraps
from flask import session, redirect, url_for, jsonify, request
import sqlite3
import time

# Rate limiting storage
rate_limit_storage = {}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Login required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('username') != 'admin':
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def safe_db_execute(cursor, query, params=None):
    """Safely execute database queries with error handling"""
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return True, None
    except sqlite3.Error as e:
        return False, str(e)

def safe_float_conversion(value, field_name):
    """Safely convert value to float"""
    try:
        return float(value) if value else 0.0
    except (ValueError, TypeError):
        return 0.0

def validate_amount(amount):
    """Validate monetary amount"""
    try:
        amount = float(amount)
        if amount <= 0:
            return False, "Amount must be greater than 0"
        return True, amount
    except (ValueError, TypeError):
        return False, "Invalid amount"

def validate_user_id(user_id):
    """Validate user ID"""
    try:
        return int(user_id) if user_id else 0
    except (ValueError, TypeError):
        return 0

def handle_db_errors(func):
    """Decorator to handle database errors"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.Error as e:
            return jsonify({'error': 'Database error occurred'}), 500
        except Exception as e:
            return jsonify({'error': 'An error occurred'}), 500
    return wrapper

def rate_limit(max_requests=5, window=300):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            if client_ip not in rate_limit_storage:
                rate_limit_storage[client_ip] = []
            
            # Clean old requests
            rate_limit_storage[client_ip] = [
                req_time for req_time in rate_limit_storage[client_ip]
                if current_time - req_time < window
            ]
            
            if len(rate_limit_storage[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            rate_limit_storage[client_ip].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_file_upload(file):
    """Validate file upload"""
    if not file or not file.filename:
        return False, "No file selected"
    
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif'}
    file_ext = '.' + file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in allowed_extensions:
        return False, "Only JPG, PNG, and GIF files are allowed"
    
    return True, "File is valid"

# Valid bonus types
VALID_BONUS_TYPES = ['referral', 'deposit', 'match_win', 'streaming']