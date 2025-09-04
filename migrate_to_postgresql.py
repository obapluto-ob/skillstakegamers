#!/usr/bin/env python3
"""
Migrate data from SQLite to PostgreSQL
"""

import sqlite3
import json
import os
from database import get_db_connection, init_database

def migrate_data():
    """Migrate all data from SQLite to PostgreSQL"""
    
    print("=== MIGRATING TO POSTGRESQL ===")
    
    # Initialize PostgreSQL database
    init_database()
    
    # Load backup data
    backup_file = 'migration_backup_20250904_152720.json'
    if not os.path.exists(backup_file):
        print(f"[ERROR] Backup file not found: {backup_file}")
        return False
    
    with open(backup_file, 'r') as f:
        data = json.load(f)
    
    # Connect to PostgreSQL
    with get_db_connection() as conn:
        c = conn.cursor()
        
        print(f"[OK] Migrating {len(data['users'])} users...")
        
        # Migrate users
        for user in data['users']:
            try:
                c.execute('''INSERT INTO users 
                            (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings, referred_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (username) DO NOTHING''', 
                         (user[1], user[2], user[3], user[4], user[5], user[6], user[7], 
                          user[8] or 0, user[9] or 0, user[10] or 0, user[11] if len(user) > 11 else None))
            except Exception as e:
                print(f"[ERROR] Failed to migrate user {user[1]}: {e}")
        
        print(f"[OK] Migrating {len(data['transactions'])} transactions...")
        
        # Get user ID mapping
        c.execute('SELECT id, username FROM users')
        user_mapping = {row[1]: row[0] for row in c.fetchall()}
        
        # Migrate transactions
        for tx in data['transactions']:
            try:
                # Find user by original user_id
                original_user_id = tx[1]
                # Find username from original users data
                username = None
                for user in data['users']:
                    if user[0] == original_user_id:
                        username = user[1]
                        break
                
                if username and username in user_mapping:
                    new_user_id = user_mapping[username]
                    c.execute('''INSERT INTO transactions 
                                (user_id, type, amount, description, created_at)
                                VALUES (%s, %s, %s, %s, %s)''', 
                             (new_user_id, tx[2], tx[3], tx[4], tx[5]))
            except Exception as e:
                print(f"[ERROR] Failed to migrate transaction: {e}")
        
        print(f"[OK] Migrating {len(data['matches'])} matches...")
        
        # Migrate matches
        for match in data['matches']:
            try:
                # Map player IDs
                player1_username = None
                player2_username = None
                
                for user in data['users']:
                    if user[0] == match[2]:
                        player1_username = user[1]
                    if user[0] == match[3]:
                        player2_username = user[1]
                
                player1_id = user_mapping.get(player1_username)
                player2_id = user_mapping.get(player2_username)
                
                if player1_id:
                    c.execute('''INSERT INTO matches 
                                (game, player1_id, player2_id, bet_amount, total_pot, winner_id, status, game_mode, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''', 
                             (match[1], player1_id, player2_id, match[4], match[5], 
                              match[6], match[7], match[8], match[9]))
            except Exception as e:
                print(f"[ERROR] Failed to migrate match: {e}")
        
        conn.commit()
        
        # Verify migration
        c.execute('SELECT COUNT(*) FROM users WHERE username != %s', ('admin',))
        user_count = c.fetchone()[0]
        
        c.execute('SELECT COALESCE(SUM(balance), 0) FROM users WHERE username != %s', ('admin',))
        total_balance = c.fetchone()[0]
        
        print(f"\n=== MIGRATION COMPLETE ===")
        print(f"Users migrated: {user_count}")
        print(f"Total balance: KSh {total_balance:.2f}")
        print(f"PostgreSQL database ready!")
        
        return True

if __name__ == "__main__":
    migrate_data()