#!/usr/bin/env python3
"""
SkillStake Referral Commission System
Implements ongoing commission for referrers when their referred users lose matches
"""

import sqlite3
from datetime import datetime

def setup_referral_commission_system():
    """Set up the referral commission tracking system"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Create referral_commissions table for tracking
        c.execute('''CREATE TABLE IF NOT EXISTS referral_commissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER,
            referred_user_id INTEGER,
            match_id INTEGER,
            loss_amount REAL,
            commission_amount REAL,
            commission_rate REAL DEFAULT 0.04,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (referrer_id) REFERENCES users(id),
            FOREIGN KEY (referred_user_id) REFERENCES users(id),
            FOREIGN KEY (match_id) REFERENCES matches(id)
        )''')
        
        # Add index for performance
        c.execute('CREATE INDEX IF NOT EXISTS idx_referral_commissions_referrer ON referral_commissions(referrer_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_referral_commissions_referred ON referral_commissions(referred_user_id)')
        
        conn.commit()
        print("[SUCCESS] Referral commission system tables created")

def calculate_referral_commission(match_id, winner_id, loser_id, bet_amount):
    """Calculate and award referral commission when a user loses a match"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Check if the loser was referred by someone
        c.execute('SELECT referred_by, username FROM users WHERE id = ?', (loser_id,))
        loser_data = c.fetchone()
        
        if not loser_data or not loser_data[0]:
            return False  # No referrer
        
        referrer_id = loser_data[0]
        loser_username = loser_data[1]
        
        # Calculate 4% commission on the loss
        commission_rate = 0.04
        commission_amount = bet_amount * commission_rate
        
        # Award commission to referrer
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', 
                 (commission_amount, referrer_id))
        
        # Record the commission transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (referrer_id, 'referral_commission', commission_amount, 
                  f'4% commission from {loser_username} match loss - KSh {bet_amount} × 4% = KSh {commission_amount:.2f}'))
        
        # Track the commission for analytics
        c.execute('''INSERT INTO referral_commissions 
                     (referrer_id, referred_user_id, match_id, loss_amount, commission_amount, commission_rate)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 (referrer_id, loser_id, match_id, bet_amount, commission_amount, commission_rate))
        
        # Reduce platform commission slightly to account for referral payout
        platform_reduction = commission_amount
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (1, 'referral_commission_cost', -platform_reduction, 
                  f'Referral commission paid out - Match #{match_id}'))
        
        conn.commit()
        
        # Get referrer username for logging
        c.execute('SELECT username FROM users WHERE id = ?', (referrer_id,))
        referrer_username = c.fetchone()[0]
        
        print(f"[COMMISSION] {referrer_username} earned KSh {commission_amount:.2f} from {loser_username}'s loss")
        return True

def get_referral_earnings(user_id):
    """Get total referral earnings for a user"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Get signup bonuses
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "referral_bonus"', (user_id,))
        signup_bonuses = c.fetchone()[0]
        
        # Get ongoing commissions
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "referral_commission"', (user_id,))
        ongoing_commissions = c.fetchone()[0]
        
        # Get referred users count
        c.execute('SELECT COUNT(*) FROM users WHERE referred_by = ?', (user_id,))
        referred_count = c.fetchone()[0]
        
        # Get total commission from referral_commissions table
        c.execute('SELECT COALESCE(SUM(commission_amount), 0) FROM referral_commissions WHERE referrer_id = ?', (user_id,))
        total_commissions = c.fetchone()[0]
        
        return {
            'signup_bonuses': signup_bonuses,
            'ongoing_commissions': ongoing_commissions,
            'total_earnings': signup_bonuses + ongoing_commissions,
            'referred_count': referred_count,
            'lifetime_commissions': total_commissions
        }

def add_deposit_processing_fee():
    """Add 3% processing fee to deposits for platform revenue"""
    return """
    # Add this to the add_funds route in app.py
    
    # Calculate processing fee (3% of deposit)
    processing_fee = amount * 0.03
    net_amount = amount - processing_fee
    
    # Credit net amount to user
    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (net_amount, user_id))
    
    # Record user transaction
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (user_id, 'deposit', net_amount, 
              f'M-Pesa deposit KSh {amount} - Processing fee: KSh {processing_fee:.2f} - Net credited: KSh {net_amount:.2f}'))
    
    # Record platform fee
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (1, 'deposit_fee', processing_fee, 
              f'3% processing fee from KSh {amount} deposit - User ID {user_id}'))
    """

def implement_tournament_fees():
    """Implement 15% platform fee on tournament entries"""
    return """
    # Add this to tournament entry processing
    
    def process_tournament_entry(user_id, entry_fee):
        platform_fee = entry_fee * 0.15  # 15% platform fee
        prize_contribution = entry_fee * 0.85  # 85% goes to prize pool
        
        # Deduct full entry fee from user
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (entry_fee, user_id))
        
        # Record user transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (user_id, 'tournament_entry', -entry_fee, 
                  f'Tournament entry fee - KSh {prize_contribution:.2f} to prize pool, KSh {platform_fee:.2f} platform fee'))
        
        # Record platform commission
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (1, 'tournament_commission', platform_fee, 
                  f'15% tournament commission from entry fee - User ID {user_id}'))
        
        return prize_contribution
    """

def update_match_completion_with_referrals():
    """Updated match completion logic with referral commissions"""
    return """
    # Replace the match completion logic in app.py with this:
    
    def complete_match(match_id, winner_id, loser_id, bet_amount):
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Calculate winnings (68% of total pot)
            total_pot = bet_amount * 2
            winnings = total_pot * 0.68
            platform_commission = total_pot * 0.32
            
            # Award winner
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1 WHERE id = ?', 
                     (winnings, winner_id))
            c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (loser_id,))
            
            # Record winner transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (winner_id, 'match_win', winnings, 
                      f'Match #{match_id} victory - KSh {winnings:.2f} (68% of KSh {total_pot})'))
            
            # Process referral commission for loser
            referral_paid = calculate_referral_commission(match_id, winner_id, loser_id, bet_amount)
            
            # Adjust platform commission if referral was paid
            if referral_paid:
                referral_cost = bet_amount * 0.04
                net_platform_commission = platform_commission - referral_cost
            else:
                net_platform_commission = platform_commission
            
            # Record platform commission
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (1, 'match_commission', net_platform_commission, 
                      f'Match #{match_id} commission - 32% minus referral costs'))
            
            # Update match status
            c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', 
                     (winner_id, match_id))
            
            conn.commit()
    """

if __name__ == "__main__":
    print("Setting up SkillStake Referral Commission System...")
    setup_referral_commission_system()
    
    print("\n[GUIDE] Implementation Guide:")
    print("1. Run this script to create referral commission tables")
    print("2. Update match completion logic in app.py")
    print("3. Add deposit processing fees (3%)")
    print("4. Implement tournament platform fees (15%)")
    print("5. Update referral dashboard to show ongoing earnings")
    
    print("\n[REVENUE] Revenue Breakdown:")
    print("- Match Commission: 32% of total pot")
    print("- Referral Commission: 4% of referred user losses")
    print("- Deposit Fees: 3% of all deposits")
    print("- Withdrawal Fees: KSh 25 per withdrawal")
    print("- Tournament Fees: 15% of entry fees")
    print("- Fraud Penalties: KSh 50-100 per violation")
    
    print("\n[SUCCESS] Referral commission system ready!")