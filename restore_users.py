#!/usr/bin/env python3
"""
User Restoration Script for SkillStake Gaming Platform
This script helps restore missing users and their referral relationships
"""

import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

def restore_user(username, phone, referrer_username=None, balance=0):
    """
    Restore a missing user with referral relationship
    
    Args:
        username: User's username
        phone: User's M-Pesa number
        referrer_username: Username of the person who referred them (optional)
        balance: Starting balance (default 0)
    """
    conn = None
    try:
        conn = sqlite3.connect('gamebet.db')
        cursor = conn.cursor()
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE phone = ?', (phone,))
        existing = cursor.fetchone()
        
        if existing:
            print(f"❌ User {username} already exists with ID {existing[0]}")
            return existing[0]
        
        # Get referrer ID if provided
        referred_by = None
        if referrer_username:
            cursor.execute('SELECT id FROM users WHERE username = ?', (referrer_username,))
            referrer = cursor.fetchone()
            if referrer:
                referred_by = referrer[0]
                print(f"✅ Found referrer: {referrer_username} (ID: {referred_by})")
            else:
                print(f"⚠️  Referrer {referrer_username} not found")
        
        # Generate user data
        password = generate_password_hash('password123')
        email = phone + '@gamebet.local'
        referral_code = username[:3].upper() + str(hash(username))[-4:]
        
        # Create user
        cursor.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code, referred_by, created_at) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (username, email, password, balance, phone, referral_code, referred_by, datetime.now().isoformat()))
        
        user_id = cursor.lastrowid
        print(f"✅ Created user: {username} (ID: {user_id})")
        
        # Add referral bonus if user was referred
        if referred_by:
            # Give referral bonus to referrer
            cursor.execute('UPDATE users SET balance = balance + 30 WHERE id = ?', (referred_by,))
            cursor.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                             VALUES (?, ?, ?, ?)''', 
                         (referred_by, 'referral_bonus', 30, f'Referral bonus for inviting {username}'))
            
            # Admin profit from referral
            cursor.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                             VALUES (?, ?, ?, ?)''', 
                         (1, 'admin_referral_profit', 20, f'Admin profit from {username} referral'))
            
            print(f"✅ Added referral bonus: KSh 30 to {referrer_username}")
        
        conn.commit()
        return user_id
        
    except Exception as e:
        print(f"❌ Error creating user {username}: {str(e)}")
        conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def check_referral_system():
    """Check the current state of the referral system"""
    conn = sqlite3.connect('gamebet.db')
    cursor = conn.cursor()
    
    print("=== REFERRAL SYSTEM STATUS ===")
    
    # Get all users and their referral info
    cursor.execute('SELECT id, username, referral_code, referred_by FROM users WHERE username != "admin"')
    users = cursor.fetchall()
    
    for user in users:
        user_id, username, ref_code, referred_by = user
        
        # Count referred users
        cursor.execute('SELECT COUNT(*) FROM users WHERE referred_by = ?', (user_id,))
        referred_count = cursor.fetchone()[0]
        
        # Get referral earnings
        cursor.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "referral_bonus"', (user_id,))
        earnings = cursor.fetchone()[0]
        
        print(f"{username}: Code={ref_code}, Referred={referred_count} users, Earned=KSh {earnings}")
    
    conn.close()

if __name__ == "__main__":
    print("SkillStake User Restoration Script")
    print("==================================")
    
    # Example usage - restore missing users
    # Uncomment and modify these lines to restore specific users
    
    # restore_user("friend1", "0756789012", "testuser")  # friend1 was referred by testuser
    # restore_user("friend2", "0767890123", "testuser")  # friend2 was referred by testuser
    # restore_user("kolul", "0734567890", "kolu")       # kolul was referred by kolu
    
    # Check current system status
    check_referral_system()
    
    print("\n✅ Script completed!")
    print("\nTo restore a user, use:")
    print("restore_user('username', 'phone_number', 'referrer_username')")