from flask import jsonify
from datetime import datetime, timedelta
from database_manager import db_manager

def get_real_time_stats():
    """Get real-time platform statistics"""
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Today's stats
            today = datetime.now().date()
            
            # Revenue today
            c.execute('SELECT SUM(commission) FROM game_matches WHERE DATE(completed_at) = ?', (today,))
            daily_revenue = c.fetchone()[0] or 0
            
            # Active users today
            c.execute('SELECT COUNT(DISTINCT user_id) FROM transactions WHERE DATE(created_at) = ?', (today,))
            daily_users = c.fetchone()[0] or 0
            
            # Matches today
            c.execute('SELECT COUNT(*) FROM game_matches WHERE DATE(created_at) = ?', (today,))
            daily_matches = c.fetchone()[0] or 0
            
            # Total platform balance
            c.execute('SELECT SUM(balance) FROM users WHERE username != "admin"')
            total_balance = c.fetchone()[0] or 0
            
            # Growth rate (vs yesterday)
            yesterday = today - timedelta(days=1)
            c.execute('SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?', (yesterday,))
            yesterday_signups = c.fetchone()[0] or 1
            
            c.execute('SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?', (today,))
            today_signups = c.fetchone()[0] or 0
            
            growth_rate = ((today_signups - yesterday_signups) / yesterday_signups) * 100 if yesterday_signups > 0 else 0
            
            return {
                'daily_revenue': float(daily_revenue),
                'daily_users': daily_users,
                'daily_matches': daily_matches,
                'total_balance': float(total_balance),
                'growth_rate': round(growth_rate, 1),
                'status': 'healthy',
                'timestamp': datetime.now().isoformat()
            }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def get_revenue_breakdown():
    """Get detailed revenue breakdown"""
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Last 7 days revenue
            c.execute('''SELECT DATE(completed_at) as date, SUM(commission) as revenue 
                        FROM game_matches 
                        WHERE completed_at >= datetime('now', '-7 days') 
                        GROUP BY DATE(completed_at) 
                        ORDER BY date''')
            
            daily_revenue = c.fetchall()
            
            # Revenue by game type
            c.execute('''SELECT game_type, SUM(commission) as revenue, COUNT(*) as matches
                        FROM game_matches 
                        WHERE completed_at >= datetime('now', '-30 days')
                        GROUP BY game_type''')
            
            game_revenue = c.fetchall()
            
            return {
                'daily_revenue': daily_revenue,
                'game_revenue': game_revenue
            }
    except:
        return {'daily_revenue': [], 'game_revenue': []}