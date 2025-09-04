#!/usr/bin/env python3
"""
Emergency User Data Backup and Recovery System
Critical for preserving user data during Render deployments
"""

import sqlite3
import json
import os
from datetime import datetime

def backup_all_users():
    """Backup all user data to JSON file"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Get all users with complete data
            c.execute('''SELECT id, username, email, password, balance, wins, losses, 
                                total_earnings, created_at, phone, referral_code, referred_by
                         FROM users WHERE username != "admin"''')
            users = c.fetchall()
            
            # Get all transactions
            c.execute('''SELECT id, user_id, type, amount, description, created_at 
                         FROM transactions ORDER BY created_at DESC''')
            transactions = c.fetchall()
            
            # Get all matches
            c.execute('''SELECT id, game, player1_id, player2_id, bet_amount, total_pot,
                                winner_id, status, game_mode, created_at
                         FROM matches ORDER BY created_at DESC''')
            matches = c.fetchall()
            
            backup_data = {
                'backup_timestamp': datetime.now().isoformat(),
                'users': [dict(zip(['id', 'username', 'email', 'password', 'balance', 'wins', 'losses', 
                                   'total_earnings', 'created_at', 'phone', 'referral_code', 'referred_by'], user)) 
                         for user in users],
                'transactions': [dict(zip(['id', 'user_id', 'type', 'amount', 'description', 'created_at'], tx)) 
                               for tx in transactions],
                'matches': [dict(zip(['id', 'game', 'player1_id', 'player2_id', 'bet_amount', 'total_pot',
                                     'winner_id', 'status', 'game_mode', 'created_at'], match)) 
                           for match in matches]
            }
            
            # Save to file
            backup_filename = f"user_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(backup_filename, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            print(f"Backup created: {backup_filename}")
            print(f"Users backed up: {len(users)}")
            print(f"Transactions backed up: {len(transactions)}")
            print(f"Matches backed up: {len(matches)}")
            
            return backup_filename
            
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return None

def restore_users_from_backup(backup_file):
    """Restore users from backup file"""
    try:
        if not os.path.exists(backup_file):
            print(f"❌ Backup file not found: {backup_file}")
            return False
            
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Restore users (skip if already exists)
            restored_users = 0
            for user in backup_data['users']:
                try:
                    c.execute('SELECT id FROM users WHERE username = ?', (user['username'],))
                    if not c.fetchone():  # User doesn't exist
                        c.execute('''INSERT INTO users (username, email, password, balance, wins, losses,
                                                       total_earnings, created_at, phone, referral_code, referred_by)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                 (user['username'], user['email'], user['password'], user['balance'],
                                  user['wins'] or 0, user['losses'] or 0, user['total_earnings'] or 0,
                                  user['created_at'], user['phone'], user['referral_code'], user['referred_by']))
                        restored_users += 1
                except Exception as e:
                    print(f"⚠️ Failed to restore user {user['username']}: {e}")
            
            # Restore transactions (check for duplicates by description and amount)
            restored_transactions = 0
            for tx in backup_data['transactions']:
                try:
                    c.execute('SELECT id FROM transactions WHERE user_id = ? AND amount = ? AND description = ?',
                             (tx['user_id'], tx['amount'], tx['description']))
                    if not c.fetchone():  # Transaction doesn't exist
                        c.execute('''INSERT INTO transactions (user_id, type, amount, description, created_at)
                                     VALUES (?, ?, ?, ?, ?)''',
                                 (tx['user_id'], tx['type'], tx['amount'], tx['description'], tx['created_at']))
                        restored_transactions += 1
                except Exception as e:
                    print(f"⚠️ Failed to restore transaction: {e}")
            
            conn.commit()
            
            print(f"✅ Restoration completed!")
            print(f"👥 Users restored: {restored_users}")
            print(f"💰 Transactions restored: {restored_transactions}")
            
            return True
            
    except Exception as e:
        print(f"❌ Restoration failed: {e}")
        return False

def emergency_user_recovery():
    """Emergency recovery - recreate missing users from transaction history"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Find user IDs from transactions that don't exist in users table
            c.execute('''SELECT DISTINCT t.user_id, t.description, t.created_at
                         FROM transactions t
                         LEFT JOIN users u ON t.user_id = u.id
                         WHERE u.id IS NULL AND t.user_id > 1
                         ORDER BY t.created_at''')
            missing_users = c.fetchall()
            
            recovered = 0
            for user_id, description, created_at in missing_users:
                # Try to extract username from transaction descriptions
                username = f"recovered_user_{user_id}"
                if "from" in description.lower():
                    parts = description.split("from")
                    if len(parts) > 1:
                        potential_name = parts[1].strip().split()[0]
                        if potential_name and len(potential_name) > 2:
                            username = potential_name
                
                # Create recovered user account
                try:
                    c.execute('''INSERT INTO users (id, username, email, password, balance, created_at, phone)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
                             (user_id, username, f"{username}@recovered.local", 
                              generate_password_hash("password123"), 0.0, created_at, f"070000{user_id}"))
                    recovered += 1
                    print(f"🔄 Recovered user: {username} (ID: {user_id})")
                except Exception as e:
                    print(f"⚠️ Failed to recover user ID {user_id}: {e}")
            
            conn.commit()
            print(f"✅ Emergency recovery completed: {recovered} users recovered")
            
    except Exception as e:
        print(f"❌ Emergency recovery failed: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "backup":
            backup_all_users()
        elif sys.argv[1] == "restore" and len(sys.argv) > 2:
            restore_users_from_backup(sys.argv[2])
        elif sys.argv[1] == "emergency":
            emergency_user_recovery()
        else:
            print("Usage: python backup_users.py [backup|restore <file>|emergency]")
    else:
        print("EMERGENCY USER DATA RECOVERY")
        print("1. Creating backup...")
        backup_file = backup_all_users()
        print("\n2. Running emergency recovery...")
        emergency_user_recovery()
        print(f"\nRecovery complete! Backup saved as: {backup_file}")