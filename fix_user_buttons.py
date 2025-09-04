#!/usr/bin/env python3
"""
Fix user account button issues and missing APIs
"""

import sqlite3

def fix_user_buttons():
    """Fix user button and API issues"""
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        print("Fixing user button issues...")
        
        # 1. Check for missing columns and add them
        try:
            c.execute('ALTER TABLE users ADD COLUMN phone TEXT')
            print("Added phone column")
        except sqlite3.OperationalError:
            pass
            
        # 2. Fix any NULL balance issues
        c.execute('UPDATE users SET balance = 0.0 WHERE balance IS NULL')
        affected = c.rowcount
        if affected > 0:
            print(f"Fixed {affected} users with NULL balance")
        
        # 3. Fix any NULL wins/losses
        c.execute('UPDATE users SET wins = 0 WHERE wins IS NULL')
        c.execute('UPDATE users SET losses = 0 WHERE losses IS NULL')
        c.execute('UPDATE users SET total_earnings = 0.0 WHERE total_earnings IS NULL')
        
        # 4. Check for users with database issues
        c.execute('SELECT id, username, balance, wins, losses FROM users WHERE username != "admin"')
        users = c.fetchall()
        
        print("User account status:")
        for user in users:
            user_id, username, balance, wins, losses = user
            print(f"User {user_id} ({username}): Balance={balance}, W/L={wins}/{losses}")
        
        # 5. Create missing API endpoints table if needed
        c.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )''')
        
        conn.commit()
        print("User button fixes completed!")

if __name__ == "__main__":
    fix_user_buttons()