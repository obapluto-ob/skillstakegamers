import random
import string
from datetime import datetime, timedelta
from database_manager import db_manager

class MarketingSystem:
    def __init__(self):
        self.promo_codes = {
            'WELCOME50': {'amount': 50, 'uses': 100, 'type': 'signup'},
            'GAMER100': {'amount': 100, 'uses': 50, 'type': 'deposit'},
            'SKILL200': {'amount': 200, 'uses': 25, 'type': 'first_match'}
        }
    
    def generate_referral_link(self, user_id):
        """Generate trackable referral link"""
        try:
            with db_manager.get_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT referral_code FROM users WHERE id = ?', (user_id,))
                code = c.fetchone()[0]
                return f"https://your-app.onrender.com/register?ref={code}"
        except:
            return None
    
    def create_viral_campaign(self):
        """Create viral sharing incentives"""
        campaigns = {
            'share_bonus': {
                'reward': 25,
                'description': 'Share on WhatsApp/Twitter and get 25 KSh',
                'action': 'social_share'
            },
            'friend_challenge': {
                'reward': 100,
                'description': 'Challenge a friend to a match and both get 100 KSh',
                'action': 'friend_match'
            }
        }
        return campaigns
    
    def track_user_source(self, user_id, source):
        """Track where users come from"""
        try:
            with db_manager.get_connection() as conn:
                c = conn.cursor()
                c.execute('INSERT INTO user_sources (user_id, source, created_at) VALUES (?, ?, ?)',
                         (user_id, source, datetime.now()))
        except:
            pass
    
    def get_top_referrers(self, limit=10):
        """Get top referrers for leaderboard"""
        try:
            with db_manager.get_connection() as conn:
                c = conn.cursor()
                c.execute('''SELECT u.username, COUNT(r.id) as referrals, 
                            SUM(CASE WHEN r.created_at > datetime('now', '-30 days') THEN 1 ELSE 0 END) as recent
                            FROM users u 
                            LEFT JOIN users r ON u.id = r.referred_by 
                            GROUP BY u.id, u.username 
                            HAVING referrals > 0 
                            ORDER BY referrals DESC LIMIT ?''', (limit,))
                return c.fetchall()
        except:
            return []

marketing = MarketingSystem()