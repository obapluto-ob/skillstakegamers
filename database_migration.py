#!/usr/bin/env python3
"""
Database Migration System
Backup and restore user data during deployments
"""

import sqlite3
import json
import os
from datetime import datetime

def export_all_data():
    """Export all user data to JSON for migration"""
    
    with sqlite3.connect('gamebet.db') as conn:
        c = conn.cursor()
        
        # Export users
        c.execute('SELECT * FROM users WHERE username != "admin"')
        users = c.fetchall()
        
        # Export transactions
        c.execute('''SELECT t.* FROM transactions t 
                     JOIN users u ON t.user_id = u.id 
                     WHERE u.username != "admin"''')
        transactions = c.fetchall()
        
        # Export matches
        c.execute('''SELECT m.* FROM matches m 
                     JOIN users u1 ON m.player1_id = u1.id 
                     WHERE u1.username != "admin"''')
        matches = c.fetchall()
        
        migration_data = {
            'export_date': datetime.now().isoformat(),
            'users': [list(user) for user in users],
            'transactions': [list(tx) for tx in transactions],
            'matches': [list(match) for match in matches],
            'user_count': len(users),
            'total_balance': sum(user[4] for user in users if user[4])
        }
        
        # Save to file
        filename = f'migration_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w') as f:
            json.dump(migration_data, f, indent=2)
        
        print(f"[OK] Data exported to: {filename}")
        print(f"[OK] Users exported: {len(users)}")
        print(f"[OK] Transactions exported: {len(transactions)}")
        print(f"[OK] Matches exported: {len(matches)}")
        
        return filename

def import_data_from_backup(filename):
    """Import data from backup file"""
    
    if not os.path.exists(filename):
        print(f"[ERROR] Backup file not found: {filename}")
        return False
    
    with open(filename, 'r') as f:
        data = json.load(f)
    
    with sqlite3.connect('gamebet.db') as conn:
        c = conn.cursor()
        
        # Clear existing data (except admin)
        c.execute('DELETE FROM transactions WHERE user_id != 1')
        c.execute('DELETE FROM matches WHERE player1_id != 1 AND player2_id != 1')
        c.execute('DELETE FROM users WHERE username != "admin"')
        
        # Import users
        for user in data['users']:
            try:
                c.execute('''INSERT INTO users 
                            (id, username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings, referred_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', user[:12])
            except Exception as e:
                print(f"Error importing user {user[1]}: {e}")
        
        # Import transactions
        for tx in data['transactions']:
            try:
                c.execute('''INSERT INTO transactions 
                            (id, user_id, type, amount, description, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)''', tx[:6])
            except Exception as e:
                print(f"Error importing transaction: {e}")
        
        # Import matches
        for match in data['matches']:
            try:
                c.execute('''INSERT INTO matches 
                            (id, game, player1_id, player2_id, bet_amount, total_pot, winner_id, status, game_mode, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', match[:10])
            except Exception as e:
                print(f"Error importing match: {e}")
        
        conn.commit()
        
        print(f"[OK] Data imported successfully from {filename}")
        print(f"[OK] Users restored: {len(data['users'])}")
        print(f"[OK] Total balance restored: KSh {data['total_balance']:.2f}")
        
        return True

def create_render_backup_script():
    """Create script for Render deployment"""
    
    script_content = '''#!/bin/bash
# Render Pre-Deploy Script
# Add this to your Render service build command

echo "Starting deployment with data backup..."

# Export current data before deployment
python database_migration.py export

# After deployment, restore data
python database_migration.py import

echo "Deployment completed with data preservation"
'''
    
    with open('render_deploy_script.sh', 'w') as f:
        f.write(script_content)
    
    print("[OK] Render deployment script created: render_deploy_script.sh")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python database_migration.py export")
        print("  python database_migration.py import <backup_file>")
        print("  python database_migration.py create_script")
    elif sys.argv[1] == 'export':
        export_all_data()
    elif sys.argv[1] == 'import' and len(sys.argv) > 2:
        import_data_from_backup(sys.argv[2])
    elif sys.argv[1] == 'create_script':
        create_render_backup_script()
    else:
        print("Invalid command")