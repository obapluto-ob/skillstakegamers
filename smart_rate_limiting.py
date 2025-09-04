from functools import wraps
from flask import request, jsonify, session, flash, redirect
import time
import sqlite3

# Smart rate limiting with user-based tracking
def smart_rate_limit(max_requests=5, window=300, user_based=True):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_time = time.time()
            
            # Use user ID if logged in, otherwise IP
            if user_based and 'user_id' in session:
                identifier = f"user_{session['user_id']}"
            else:
                identifier = f"ip_{request.remote_addr}"
            
            with sqlite3.connect("gamebet.db") as conn:
                c = conn.cursor()
                
                # Create rate_limit_tracking table
                c.execute('''CREATE TABLE IF NOT EXISTS rate_limit_tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier TEXT,
                    endpoint TEXT,
                    timestamp REAL,
                    created_at DATETIME DEFAULT (datetime('now'))
                )''')
                
                endpoint = request.endpoint or f.__name__
                
                # Clean old entries
                c.execute('DELETE FROM rate_limit_tracking WHERE timestamp < ?', 
                         (current_time - window,))
                
                # Count recent requests
                c.execute('SELECT COUNT(*) FROM rate_limit_tracking WHERE identifier = ? AND endpoint = ?',
                         (identifier, endpoint))
                count = c.fetchone()[0]
                
                if count >= max_requests:
                    wait_time = window // 60
                    if request.method == 'POST':
                        flash(f'Too many attempts. Please wait {wait_time} minutes.', 'error')
                        return redirect(request.url)
                    return jsonify({'error': f'Rate limited. Wait {wait_time} minutes.'}), 429
                
                # Record this request
                c.execute('INSERT INTO rate_limit_tracking (identifier, endpoint, timestamp) VALUES (?, ?, ?)',
                         (identifier, endpoint, current_time))
                conn.commit()
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator