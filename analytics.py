from flask import request, session
from datetime import datetime
import json

def track_user_activity(action, details=None):
    """Simple analytics tracking"""
    try:
        activity = {
            'timestamp': datetime.now().isoformat(),
            'user_id': session.get('user_id'),
            'action': action,
            'details': details,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')[:100]
        }
        
        # Log to file (Render logs are accessible)
        with open('activity.log', 'a') as f:
            f.write(json.dumps(activity) + '\n')
            
    except Exception:
        pass  # Silent fail for analytics

def get_platform_stats():
    """Get basic platform statistics"""
    from database_manager import db_manager
    
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Active users today
            c.execute("SELECT COUNT(DISTINCT user_id) FROM transactions WHERE DATE(created_at) = DATE('now')")
            daily_active = c.fetchone()[0] or 0
            
            # Total revenue today
            c.execute("SELECT SUM(commission) FROM game_matches WHERE DATE(completed_at) = DATE('now')")
            daily_revenue = c.fetchone()[0] or 0
            
            # Active matches
            c.execute("SELECT COUNT(*) FROM game_matches WHERE status = 'active'")
            active_matches = c.fetchone()[0] or 0
            
            return {
                'daily_active_users': daily_active,
                'daily_revenue': float(daily_revenue),
                'active_matches': active_matches,
                'status': 'healthy'
            }
    except Exception:
        return {'status': 'error'}