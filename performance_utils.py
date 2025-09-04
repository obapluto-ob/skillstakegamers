import sqlite3
from functools import wraps
import time

def cache_db_query(timeout=300):
    """Simple query caching"""
    cache = {}
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            cache_key = f"{f.__name__}_{str(args)}_{str(kwargs)}"
            current_time = time.time()
            
            if cache_key in cache:
                result, timestamp = cache[cache_key]
                if current_time - timestamp < timeout:
                    return result
            
            result = f(*args, **kwargs)
            cache[cache_key] = (result, current_time)
            return result
        return decorated_function
    return decorator

def optimize_database():
    """Optimize database performance"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Add indexes for better performance
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
            'CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)',
            'CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status)',
            'CREATE INDEX IF NOT EXISTS idx_matches_players ON matches(player1_id, player2_id)',
            'CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type)',
            'CREATE INDEX IF NOT EXISTS idx_streams_status ON streams(status)',
        ]
        
        for index in indexes:
            try:
                c.execute(index)
            except sqlite3.Error:
                pass
        
        # Clean old data
        c.execute('DELETE FROM rate_limit_tracking WHERE created_at < datetime("now", "-7 days")')
        c.execute('DELETE FROM admin_activity WHERE id NOT IN (SELECT id FROM admin_activity ORDER BY id DESC LIMIT 100)')
        
        conn.commit()

@cache_db_query(60)
def get_platform_stats():
    """Get cached platform statistics"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
        total_users = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM matches WHERE status = "active"')
        active_matches = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM streams WHERE status = "live"')
        live_streams = c.fetchone()[0]
        
        return {
            'users': total_users,
            'matches': active_matches,
            'streams': live_streams
        }