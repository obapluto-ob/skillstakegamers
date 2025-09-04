#!/usr/bin/env python3
"""
Fix Real Users - Remove fake users and restore only real ones
"""

import sqlite3
from werkzeug.security import generate_password_hash

def fix_real_users():
    """Remove fake users and keep only real ones"""
    
    # REAL users that actually registered and deposited money
    real_users_only = [
        'plutomania',  # Real user with KSh 4391.16
        'pluto',       # Real user with KSh 150.00
        'kaleb',       # Real user 
        'kasongo',     # Real user
        'kasongomustgo', # Real user
        'kolu',        # Real user
        'kolul',       # Real user
        'obapluto',    # Real user
        'plutot',      # Real user
        'skubii',      # Real user
        'testuser',    # Real user
        'test_deposit_user',    # Real user
        'test_withdrawal_user', # Real user
        'test_refund_user'      # Real user
    ]
    
    with sqlite3.connect('gamebet.db') as conn:
        c = conn.cursor()
        
        print("Fixing user database - removing fake users...")
        
        # Get all current users
        c.execute('SELECT username FROM users WHERE username != "admin"')
        all_users = [row[0] for row in c.fetchall()]
        
        fake_users_removed = 0
        
        for username in all_users:
            if username not in real_users_only:
                print(f"Removing fake user: {username}")
                
                # Get user ID
                c.execute('SELECT id FROM users WHERE username = ?', (username,))
                user_data = c.fetchone()
                if user_data:
                    user_id = user_data[0]
                    
                    # Remove user's transactions
                    c.execute('DELETE FROM transactions WHERE user_id = ?', (user_id,))
                    
                    # Remove user
                    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
                    
                    fake_users_removed += 1
        
        conn.commit()
        
        print(f"\n=== CLEANUP COMPLETE ===")
        print(f"Fake users removed: {fake_users_removed}")
        
        # Show remaining real users
        c.execute('SELECT username, balance FROM users WHERE username != "admin" ORDER BY username')
        real_users = c.fetchall()
        
        print(f"\n=== REAL USERS REMAINING ===")
        for username, balance in real_users:
            print(f"  {username}: KSh {balance:.2f}")
        
        print(f"\nTotal real users: {len(real_users)}")

if __name__ == "__main__":
    fix_real_users()