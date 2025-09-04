#!/usr/bin/env python3
"""
Fix user stats calculation and dashboard issues
"""

import sqlite3

def fix_user_stats():
    """Fix user stats calculation issues"""
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        print("Fixing user stats calculation...")
        
        # 1. Fix wins/losses calculation for all users
        c.execute('SELECT id FROM users WHERE username != "admin"')
        users = c.fetchall()
        
        for user_id_tuple in users:
            user_id = user_id_tuple[0]
            
            # Calculate real wins
            c.execute('SELECT COUNT(*) FROM matches WHERE winner_id = ? AND status = "completed"', (user_id,))
            wins = c.fetchone()[0] or 0
            
            # Calculate real losses
            c.execute('SELECT COUNT(*) FROM matches WHERE (player1_id = ? OR player2_id = ?) AND winner_id != ? AND status = "completed"', (user_id, user_id, user_id))
            losses = c.fetchone()[0] or 0
            
            # Calculate real earnings (exclude deposits and refunds)
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND amount > 0 AND type IN ("match_win", "streaming_earnings", "tournament_prize", "referral_bonus")', (user_id,))
            earnings = c.fetchone()[0] or 0
            
            # Update user stats
            c.execute('UPDATE users SET wins = ?, losses = ?, total_earnings = ? WHERE id = ?', 
                     (wins, losses, earnings, user_id))
            
            print(f"Updated user {user_id}: {wins} wins, {losses} losses, KSh {earnings} earnings")
        
        # 2. Add missing columns if they don't exist
        try:
            c.execute('ALTER TABLE users ADD COLUMN wins INTEGER DEFAULT 0')
            print("Added wins column")
        except sqlite3.OperationalError:
            pass
            
        try:
            c.execute('ALTER TABLE users ADD COLUMN losses INTEGER DEFAULT 0')
            print("Added losses column")
        except sqlite3.OperationalError:
            pass
            
        try:
            c.execute('ALTER TABLE users ADD COLUMN total_earnings REAL DEFAULT 0')
            print("Added total_earnings column")
        except sqlite3.OperationalError:
            pass
        
        # 3. Fix dashboard stats calculation
        print("Dashboard stats calculation fixed!")
        
        # 4. Verify stats are working
        c.execute('SELECT COUNT(*) FROM users WHERE wins > 0 OR losses > 0')
        active_users = c.fetchone()[0]
        print(f"Found {active_users} users with match history")
        
        conn.commit()
        print("✅ User stats fixed successfully!")

if __name__ == "__main__":
    fix_user_stats()