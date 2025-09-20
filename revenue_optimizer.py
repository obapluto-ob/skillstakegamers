from datetime import datetime, timedelta
from database_manager import db_manager

class RevenueOptimizer:
    def __init__(self):
        self.base_commission = 0.06  # 6% base (reduced from 8%)
        self.loyalty_discount = 0.02  # 2% discount for loyal users
        self.volume_bonus = 0.01     # 1% extra for high volume
        
    def calculate_dynamic_commission(self, user_id, stake_amount):
        """Calculate commission that benefits both platform and user"""
        commission_rate = self.base_commission
        
        # Loyalty discount (played 10+ matches)
        if self.get_user_match_count(user_id) >= 10:
            commission_rate -= self.loyalty_discount
            
        # High stake bonus for platform
        if stake_amount >= 1000:
            commission_rate += self.volume_bonus
            
        # Minimum 3%, maximum 8%
        commission_rate = max(0.03, min(0.08, commission_rate))
        
        return commission_rate
    
    def get_user_match_count(self, user_id):
        try:
            with db_manager.get_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT COUNT(*) FROM game_matches WHERE (creator_id = ? OR opponent_id = ?) AND status = "completed"', (user_id, user_id))
                return c.fetchone()[0] or 0
        except:
            return 0
    
    def add_user_rewards(self, user_id, match_count):
        """Add rewards to keep users engaged"""
        rewards = {
            5: 100,   # 5 matches = 100 KSh bonus
            10: 250,  # 10 matches = 250 KSh bonus  
            25: 500,  # 25 matches = 500 KSh bonus
            50: 1000  # 50 matches = 1000 KSh bonus
        }
        
        if match_count in rewards:
            try:
                with db_manager.get_connection() as conn:
                    c = conn.cursor()
                    bonus = rewards[match_count]
                    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bonus, user_id))
                    c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                             (user_id, 'loyalty_bonus', bonus, f'Loyalty bonus for {match_count} matches'))
                    return bonus
            except:
                pass
        return 0

revenue_optimizer = RevenueOptimizer()