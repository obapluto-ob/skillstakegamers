#!/usr/bin/env python3
"""
Quick script to credit 190 KSh to a user
Usage: python credit_190.py <username_or_email>
"""

import sqlite3
import sys
from datetime import datetime

def credit_user_190(user_identifier):
    """Credit 190 KSh to the specified user"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    try:
        # Find user by username or email
        if '@' in user_identifier:
            c.execute('SELECT id, username, email, balance FROM users WHERE email = ?', (user_identifier,))
        else:
            c.execute('SELECT id, username, email, balance FROM users WHERE username = ?', (user_identifier,))
        
        user = c.fetchone()
        
        if not user:
            print(f"❌ User not found: {user_identifier}")
            return False
        
        user_id, username, email, current_balance = user
        amount = 190
        new_balance = current_balance + amount
        
        # Update user balance
        c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
        
        # Record transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                   VALUES (?, ?, ?, ?)''',
                 (user_id, 'admin_credit', amount, 'Manual credit for missing M-Pesa deposit of KSh 190 - Admin resolved'))
        
        conn.commit()
        
        print(f"✅ SUCCESS!")
        print(f"   User: {username} ({email})")
        print(f"   Amount Credited: KSh {amount}")
        print(f"   Previous Balance: KSh {current_balance}")
        print(f"   New Balance: KSh {new_balance}")
        print(f"   Transaction recorded in user's history")
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python credit_190.py <username_or_email>")
        print("Example: python credit_190.py john123")
        print("Example: python credit_190.py user@email.com")
        sys.exit(1)
    
    user_identifier = sys.argv[1]
    print(f"Crediting 190 KSh to: {user_identifier}")
    print("-" * 40)
    
    success = credit_user_190(user_identifier)
    
    if success:
        print("\n🎉 The user should now see the funds in their wallet!")
    else:
        print("\n❌ Credit failed. Please check the username/email.")