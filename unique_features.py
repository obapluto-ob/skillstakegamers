# Unique SkillStake Features Implementation

from flask import request, jsonify, session
import sqlite3
from datetime import datetime, timedelta
import random

def get_db_connection():
    return sqlite3.connect('gamebet.db')

def init_unique_tables():
    """Initialize unique feature tables"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Skill Insurance
        c.execute('''CREATE TABLE IF NOT EXISTS skill_insurance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            insurance_fee REAL DEFAULT 50,
            activated INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Revenge Matches
        c.execute('''CREATE TABLE IF NOT EXISTS revenge_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_match_id INTEGER NOT NULL,
            challenger_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            multiplier REAL DEFAULT 1.5,
            humiliation_fee REAL DEFAULT 0,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Skill Ratings
        c.execute('''CREATE TABLE IF NOT EXISTS skill_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            wins INTEGER DEFAULT 0,
            losses INTEGER DEFAULT 0,
            skill_score REAL DEFAULT 1000,
            win_streak INTEGER DEFAULT 0,
            bounty_amount REAL DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Live Bets
        c.execute('''CREATE TABLE IF NOT EXISTS live_bets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER NOT NULL,
            bettor_id INTEGER NOT NULL,
            bet_type TEXT NOT NULL,
            bet_amount REAL NOT NULL,
            prediction TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Skill Tokens
        c.execute('''CREATE TABLE IF NOT EXISTS skill_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_type TEXT NOT NULL,
            amount INTEGER NOT NULL,
            source TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()

# 1. SKILL INSURANCE SYSTEM
def buy_skill_insurance(match_id, user_id):
    """Buy insurance for a match"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            balance = c.fetchone()[0]
            
            if balance < 50:
                return {'success': False, 'message': 'Insufficient balance for insurance'}
            
            # Deduct insurance fee
            c.execute('UPDATE users SET balance = balance - 50 WHERE id = ?', (user_id,))
            
            # Add insurance record
            c.execute('''INSERT INTO skill_insurance (match_id, user_id, insurance_fee) 
                       VALUES (?, ?, 50)''', (match_id, user_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (user_id, 'insurance_fee', -50, f'Skill Insurance for Match #{match_id}'))
            
            conn.commit()
            return {'success': True, 'message': 'Insurance purchased! Get 50% back if you lose by 1 goal only'}
            
    except Exception as e:
        return {'success': False, 'message': str(e)}

def activate_insurance(match_id, user_id, goal_difference):
    """Activate insurance if conditions met"""
    if goal_difference == 1:  # Lost by exactly 1 goal
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # Check if user has insurance
                c.execute('SELECT * FROM skill_insurance WHERE match_id = ? AND user_id = ? AND activated = 0', 
                         (match_id, user_id))
                insurance = c.fetchone()
                
                if insurance:
                    # Get match stake
                    c.execute('SELECT stake_amount FROM game_matches WHERE id = ?', (match_id,))
                    stake = c.fetchone()[0]
                    
                    # Refund 50% of stake
                    refund = stake * 0.5
                    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund, user_id))
                    
                    # Mark insurance as activated
                    c.execute('UPDATE skill_insurance SET activated = 1 WHERE id = ?', (insurance[0],))
                    
                    # Record refund
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                               VALUES (?, ?, ?, ?)''',
                             (user_id, 'insurance_payout', refund, f'Insurance payout - lost by 1 goal only'))
                    
                    conn.commit()
                    return True
        except:
            pass
    return False

# 2. REVENGE MATCH SYSTEM
def create_revenge_match(original_match_id, challenger_id, target_id):
    """Create a revenge match challenge"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get original match details
            c.execute('SELECT stake_amount FROM game_matches WHERE id = ?', (original_match_id,))
            original_stake = c.fetchone()[0]
            
            # Calculate revenge stakes (1.5x multiplier)
            revenge_stake = original_stake * 1.5
            humiliation_fee = original_stake * 0.2
            
            # Check challenger balance
            c.execute('SELECT balance FROM users WHERE id = ?', (challenger_id,))
            balance = c.fetchone()[0]
            
            if balance < revenge_stake:
                return {'success': False, 'message': 'Insufficient balance for revenge match'}
            
            # Create revenge match record
            c.execute('''INSERT INTO revenge_matches 
                       (original_match_id, challenger_id, target_id, multiplier, humiliation_fee) 
                       VALUES (?, ?, ?, 1.5, ?)''', 
                     (original_match_id, challenger_id, target_id, humiliation_fee))
            
            conn.commit()
            return {'success': True, 'message': f'Revenge challenge sent! Stakes: KSh {revenge_stake}'}
            
    except Exception as e:
        return {'success': False, 'message': str(e)}

# 3. SKILL RATING & BOUNTY SYSTEM
def update_skill_rating(user_id, won=True):
    """Update user skill rating and bounty"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get or create skill rating
            c.execute('SELECT * FROM skill_ratings WHERE user_id = ?', (user_id,))
            rating = c.fetchone()
            
            if not rating:
                c.execute('''INSERT INTO skill_ratings (user_id, wins, losses, skill_score, win_streak) 
                           VALUES (?, 0, 0, 1000, 0)''', (user_id,))
                rating = (None, user_id, 0, 0, 1000, 0, 0, None)
            
            wins, losses, skill_score, win_streak, bounty = rating[2], rating[3], rating[4], rating[5], rating[6]
            
            if won:
                wins += 1
                win_streak += 1
                skill_score += 25
                
                # Increase bounty for win streaks
                if win_streak >= 3:
                    bounty += 100 * win_streak
                    
            else:
                losses += 1
                win_streak = 0
                skill_score -= 15
                bounty = 0  # Reset bounty on loss
            
            # Update rating
            c.execute('''UPDATE skill_ratings SET wins = ?, losses = ?, skill_score = ?, 
                       win_streak = ?, bounty_amount = ?, last_updated = CURRENT_TIMESTAMP 
                       WHERE user_id = ?''', 
                     (wins, losses, skill_score, win_streak, bounty, user_id))
            
            conn.commit()
            return bounty
            
    except Exception as e:
        return 0

# 4. LIVE BETTING SYSTEM
def place_live_bet(match_id, bettor_id, bet_type, amount, prediction):
    """Place a live bet on ongoing match"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check if match is active
            c.execute('SELECT status FROM game_matches WHERE id = ?', (match_id,))
            status = c.fetchone()
            
            if not status or status[0] != 'active':
                return {'success': False, 'message': 'Match not available for betting'}
            
            # Check bettor balance
            c.execute('SELECT balance FROM users WHERE id = ?', (bettor_id,))
            balance = c.fetchone()[0]
            
            if balance < amount:
                return {'success': False, 'message': 'Insufficient balance'}
            
            # Deduct bet amount
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, bettor_id))
            
            # Place bet
            c.execute('''INSERT INTO live_bets (match_id, bettor_id, bet_type, bet_amount, prediction) 
                       VALUES (?, ?, ?, ?, ?)''', 
                     (match_id, bettor_id, bet_type, amount, prediction))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (bettor_id, 'live_bet', -amount, f'Live bet on Match #{match_id}: {prediction}'))
            
            conn.commit()
            return {'success': True, 'message': f'Live bet placed: {prediction} for KSh {amount}'}
            
    except Exception as e:
        return {'success': False, 'message': str(e)}

# 5. SKILL TOKENS SYSTEM
def award_skill_tokens(user_id, token_type, amount, source):
    """Award skill tokens to user"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            c.execute('''INSERT INTO skill_tokens (user_id, token_type, amount, source) 
                       VALUES (?, ?, ?, ?)''', 
                     (user_id, token_type, amount, source))
            
            conn.commit()
            return True
    except:
        return False

def get_user_tokens(user_id):
    """Get user's skill token balance"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''SELECT token_type, SUM(amount) FROM skill_tokens 
                       WHERE user_id = ? GROUP BY token_type''', (user_id,))
            return dict(c.fetchall())
    except:
        return {}

# 6. DAILY BONUSES & STREAKS
def claim_daily_bonus(user_id):
    """Claim daily login bonus"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check if already claimed today
            today = datetime.now().date()
            c.execute('''SELECT * FROM transactions WHERE user_id = ? AND type = 'daily_bonus' 
                       AND DATE(created_at) = ?''', (user_id, today))
            
            if c.fetchone():
                return {'success': False, 'message': 'Daily bonus already claimed'}
            
            # Award bonus
            bonus_amount = random.randint(50, 100)
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bonus_amount, user_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (user_id, 'daily_bonus', bonus_amount, f'Daily login bonus: KSh {bonus_amount}'))
            
            # Award skill tokens
            award_skill_tokens(user_id, 'daily', 10, 'daily_login')
            
            conn.commit()
            return {'success': True, 'message': f'Daily bonus claimed: KSh {bonus_amount} + 10 tokens!'}
            
    except Exception as e:
        return {'success': False, 'message': str(e)}

# Initialize tables when imported
init_unique_tables()