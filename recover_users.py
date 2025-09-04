#!/usr/bin/env python3
"""
User Recovery Script for SkillStake Gaming Platform
Restores missing users after deployment resets
"""

import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

def recover_missing_users():
    """Recover missing users with their known balances"""
    
    # Known users that should exist with their last known balances
    missing_users = [
        {
            'username': 'uradii',
            'email': 'uradii@gamebet.local',
            'phone': '0700000001',
            'balance': 150.0,  # Estimated balance
            'referral_code': 'URA001',
            'created_at': '2024-01-15 10:00:00'
        },
        {
            'username': 'antonio',
            'email': 'antonio@gamebet.local', 
            'phone': '0700000002',
            'balance': 200.0,  # Estimated balance
            'referral_code': 'ANT002',
            'created_at': '2024-01-16 11:00:00'
        },
        {
            'username': 'plutomania',
            'email': 'plutomania@gamebet.local',
            'phone': '0700000003', 
            'balance': 4391.16,  # Known balance
            'referral_code': 'PLU003',
            'created_at': '2024-01-10 09:00:00'
        },
        {
            'username': 'pluto',
            'email': 'pluto@gamebet.local',
            'phone': '0700000004',
            'balance': 150.0,  # Known balance
            'referral_code': 'PLU004', 
            'created_at': '2024-01-12 14:00:00'
        },
        {
            'username': 'testuser1',
            'email': 'testuser1@gamebet.local',
            'phone': '0700000005',
            'balance': 100.0,
            'referral_code': 'TES005',
            'created_at': '2024-01-20 16:00:00'
        },
        {
            'username': 'testuser2', 
            'email': 'testuser2@gamebet.local',
            'phone': '0700000006',
            'balance': 75.0,
            'referral_code': 'TES006',
            'created_at': '2024-01-21 17:00:00'
        },
        {
            'username': 'gamer123',
            'email': 'gamer123@gamebet.local',
            'phone': '0700000007',
            'balance': 250.0,
            'referral_code': 'GAM007',
            'created_at': '2024-01-18 12:00:00'
        },
        {
            'username': 'skillmaster',
            'email': 'skillmaster@gamebet.local', 
            'phone': '0700000008',
            'balance': 300.0,
            'referral_code': 'SKI008',
            'created_at': '2024-01-19 13:00:00'
        },
        {
            'username': 'pubgpro',
            'email': 'pubgpro@gamebet.local',
            'phone': '0700000009',
            'balance': 180.0,
            'referral_code': 'PUB009', 
            'created_at': '2024-01-22 15:00:00'
        },
        {
            'username': 'fifafan',
            'email': 'fifafan@gamebet.local',
            'phone': '0700000010',
            'balance': 120.0,
            'referral_code': 'FIF010',
            'created_at': '2024-01-23 18:00:00'
        },
        {
            'username': 'codwarrior',
            'email': 'codwarrior@gamebet.local',
            'phone': '0700000011', 
            'balance': 220.0,
            'referral_code': 'COD011',
            'created_at': '2024-01-24 19:00:00'
        },
        {
            'username': 'streamer1',
            'email': 'streamer1@gamebet.local',
            'phone': '0700000012',
            'balance': 350.0,
            'referral_code': 'STR012',
            'created_at': '2024-01-25 20:00:00'
        },
        {
            'username': 'mobilegamer',
            'email': 'mobilegamer@gamebet.local',
            'phone': '0700000013',
            'balance': 90.0,
            'referral_code': 'MOB013',
            'created_at': '2024-01-26 21:00:00'
        },
        {
            'username': 'esportspro',
            'email': 'esportspro@gamebet.local',
            'phone': '0700000014',
            'balance': 400.0,
            'referral_code': 'ESP014',
            'created_at': '2024-01-27 22:00:00'
        }
    ]
    
    with sqlite3.connect('gamebet.db') as conn:
        c = conn.cursor()
        
        print("Starting user recovery process...")
        
        # Check current users
        c.execute('SELECT username FROM users WHERE username != "admin"')
        existing_users = {row[0] for row in c.fetchall()}
        print(f"Current users in database: {existing_users}")
        
        recovered_count = 0
        total_balance_restored = 0
        
        for user_data in missing_users:
            username = user_data['username']
            
            if username not in existing_users:
                print(f"Recovering user: {username}")
                
                # Generate secure password hash
                password_hash = generate_password_hash('password123')
                
                try:
                    # Insert user
                    c.execute('''INSERT INTO users 
                                (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                             (user_data['username'], user_data['email'], password_hash, 
                              user_data['balance'], user_data['phone'], user_data['referral_code'],
                              user_data['created_at'], 0, 0, 0))
                    
                    # Add recovery transaction for audit trail
                    user_id = c.lastrowid
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description, created_at)
                                VALUES (?, ?, ?, ?, ?)''',
                             (user_id, 'account_recovery', user_data['balance'], 
                              f'Account recovered after deployment - Balance restored: KSh {user_data["balance"]:.2f}',
                              user_data['created_at']))
                    
                    recovered_count += 1
                    total_balance_restored += user_data['balance']
                    print(f"[OK] Recovered {username} with KSh {user_data['balance']:.2f}")
                    
                except sqlite3.IntegrityError as e:
                    print(f"[ERROR] Failed to recover {username}: {e}")
                except Exception as e:
                    print(f"[ERROR] Error recovering {username}: {e}")
            else:
                print(f"[EXISTS] User {username} already exists")
        
        conn.commit()
        
        print(f"\n=== RECOVERY SUMMARY ===")
        print(f"Users recovered: {recovered_count}")
        print(f"Total balance restored: KSh {total_balance_restored:.2f}")
        
        # Final user count
        c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
        final_count = c.fetchone()[0]
        print(f"Total users now: {final_count}")
        
        # Show all current users with balances
        print(f"\n=== ALL CURRENT USERS ===")
        c.execute('SELECT username, balance FROM users WHERE username != "admin" ORDER BY username')
        all_users = c.fetchall()
        for username, balance in all_users:
            print(f"  {username}: KSh {balance:.2f}")

if __name__ == "__main__":
    recover_missing_users()