from flask import session
import sqlite3
from datetime import datetime, timedelta

def cleanup_expired_sessions():
    """Clean up expired sessions and inactive data"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Clean old rate limiting data
        c.execute('DELETE FROM rate_limit_tracking WHERE created_at < datetime("now", "-1 day")')
        
        # Clean old admin notifications
        c.execute('DELETE FROM admin_notifications WHERE created_at < datetime("now", "-30 days") AND status = "read"')
        
        # Clean old match messages
        c.execute('DELETE FROM match_messages WHERE created_at < datetime("now", "-7 days")')
        
        conn.commit()

def refresh_user_session(user_id):
    """Refresh user session data"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('SELECT username, balance FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        
        if user:
            session['username'] = user[0]
            session['balance'] = user[1]
            return True
    return False