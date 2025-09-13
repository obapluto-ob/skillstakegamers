#!/usr/bin/env python3
"""
Manual User Credit Script for SkillStake
Use this to credit the missing 190 KSh deposit to a user
"""

import sqlite3
from datetime import datetime

def credit_user(user_identifier, amount, reason="Manual credit for missing deposit"):
    """
    Credit a user with the specified amount
    
    Args:
        user_identifier: Username, email, or user ID
        amount: Amount to credit (e.g., 190)
        reason: Reason for the credit
    """
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    try:
        # Find user by username, email, or ID
        if user_identifier.isdigit():
            # User ID
            c.execute('SELECT id, username, email, balance FROM users WHERE id = ?', (int(user_identifier),))
        elif '@' in user_identifier:
            # Email
            c.execute('SELECT id, username, email, balance FROM users WHERE email = ?', (user_identifier,))
        else:
            # Username
            c.execute('SELECT id, username, email, balance FROM users WHERE username = ?', (user_identifier,))
        
        user = c.fetchone()
        
        if not user:
            print(f"❌ User not found: {user_identifier}")
            return False
        
        user_id, username, email, current_balance = user
        new_balance = current_balance + amount
        
        # Update user balance
        c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
        
        # Record transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                   VALUES (?, ?, ?, ?)''',
                 (user_id, 'admin_credit', amount, reason))
        
        conn.commit()
        
        print(f"✅ SUCCESS: Credited KSh {amount} to {username} ({email})")
        print(f"   Previous Balance: KSh {current_balance}")
        print(f"   New Balance: KSh {new_balance}")
        print(f"   Reason: {reason}")
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return False
    finally:
        conn.close()

def list_recent_users():
    """List recent users to help identify who needs the credit"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    print("\n=== RECENT USERS (Last 10) ===")
    c.execute('''SELECT id, username, email, balance, created_at 
               FROM users 
               WHERE username != 'admin' 
               ORDER BY created_at DESC LIMIT 10''')
    users = c.fetchall()
    
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Balance: KSh {user[3]}, Joined: {user[4][:10]}")
    
    conn.close()

def search_deposits():
    """Search for recent deposit activity"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    print("\n=== RECENT DEPOSIT ACTIVITY ===")
    c.execute('''SELECT t.id, u.username, u.email, t.type, t.amount, t.description, t.created_at
               FROM transactions t
               JOIN users u ON t.user_id = u.id
               WHERE t.type LIKE '%deposit%'
               ORDER BY t.created_at DESC LIMIT 10''')
    deposits = c.fetchall()
    
    for dep in deposits:
        print(f"User: {dep[1]} ({dep[2]}), Type: {dep[3]}, Amount: KSh {dep[4]}, Date: {dep[6][:16]}")
        print(f"   Description: {dep[5][:80]}...")
        print()
    
    conn.close()

if __name__ == "__main__":
    print("🏦 SkillStake Manual Credit Tool")
    print("=" * 40)
    
    # Show recent users and deposits
    list_recent_users()
    search_deposits()
    
    print("\n💰 CREDIT THE 190 KSh DEPOSIT")
    print("=" * 40)
    
    # Get user input
    user_input = input("Enter username, email, or user ID to credit: ").strip()
    
    if user_input:
        amount = 190
        reason = "Manual credit for missing M-Pesa deposit of KSh 190 - Admin resolved"
        
        confirm = input(f"Credit KSh {amount} to '{user_input}'? (y/N): ").strip().lower()
        
        if confirm == 'y':
            success = credit_user(user_input, amount, reason)
            if success:
                print("\n🎉 Credit completed successfully!")
                print("The user should now see the funds in their wallet.")
            else:
                print("\n❌ Credit failed. Please check the user identifier.")
        else:
            print("❌ Credit cancelled.")
    else:
        print("❌ No user specified.")
    
    print("\n" + "=" * 40)
    print("Credit tool finished.")