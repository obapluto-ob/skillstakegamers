#!/usr/bin/env python3
"""
Safe Deployment Script - Prevents User Data Loss
Run this before every Render deployment
"""

import sqlite3
import json
import os
import subprocess
from datetime import datetime
from werkzeug.security import generate_password_hash

def create_persistent_backup():
    """Create backup that survives deployments"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Get critical user data
            c.execute('''SELECT username, email, password, balance, phone, referral_code, created_at
                         FROM users WHERE username != "admin" ORDER BY created_at''')
            users = c.fetchall()
            
            # Get user balances and earnings
            c.execute('''SELECT user_id, SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as deposits,
                                SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as withdrawals
                         FROM transactions 
                         WHERE type IN ('deposit', 'paypal_deposit', 'crypto_deposit', 'withdrawal')
                         GROUP BY user_id''')
            financial_data = c.fetchall()
            
            # Create environment variable format for Render
            user_data = []
            for user in users:
                user_record = {
                    'username': user[0],
                    'email': user[1], 
                    'password_hash': user[2],
                    'balance': float(user[3]),
                    'phone': user[4],
                    'referral_code': user[5],
                    'created_at': user[6]
                }
                user_data.append(user_record)
            
            # Save as compressed JSON
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'users': user_data,
                'financial_summary': dict(financial_data)
            }
            
            # Write to multiple locations
            backup_json = json.dumps(backup_data, separators=(',', ':'))
            
            # 1. Local backup file
            with open('user_backup.json', 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            # 2. Environment variable format (for Render)
            with open('.env.backup', 'w') as f:
                f.write(f'USER_BACKUP_DATA="{backup_json}"\n')
            
            print(f"✅ Persistent backup created: {len(user_data)} users")
            return True
            
    except Exception as e:
        print(f"❌ Backup creation failed: {e}")
        return False

def restore_from_env():
    """Restore users from environment variable (for Render deployment)"""
    try:
        backup_data_str = os.getenv('USER_BACKUP_DATA')
        if not backup_data_str:
            print("⚠️ No backup data found in environment")
            return False
            
        backup_data = json.loads(backup_data_str)
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            restored = 0
            for user in backup_data['users']:
                try:
                    # Check if user exists
                    c.execute('SELECT id FROM users WHERE username = ?', (user['username'],))
                    if not c.fetchone():
                        # Restore user
                        c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code, created_at)
                                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                 (user['username'], user['email'], user['password_hash'], 
                                  user['balance'], user['phone'], user['referral_code'], user['created_at']))
                        restored += 1
                except Exception as e:
                    print(f"⚠️ Failed to restore {user['username']}: {e}")
            
            conn.commit()
            print(f"✅ Restored {restored} users from environment backup")
            return True
            
    except Exception as e:
        print(f"❌ Environment restore failed: {e}")
        return False

def init_database_with_recovery():
    """Initialize database and recover users if needed"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Create tables if they don't exist
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance REAL DEFAULT 0.0,
                wins INTEGER DEFAULT 0,
                losses INTEGER DEFAULT 0,
                total_earnings REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                phone TEXT,
                referral_code TEXT,
                referred_by INTEGER,
                banned INTEGER DEFAULT 0
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                payment_proof TEXT
            )''')
            
            # Create admin if doesn't exist
            admin_password = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'change-me-in-production'))
            c.execute('''INSERT OR IGNORE INTO users (username, email, password, balance, phone, referral_code) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     ('admin', 'admin@skillstake.com', admin_password, 0.0, '0700000000', 'ADMIN001'))
            
            conn.commit()
            
            # Check if we need to restore users
            c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
            user_count = c.fetchone()[0]
            
            if user_count == 0:
                print("🔄 No users found, attempting recovery...")
                restore_from_env()
            else:
                print(f"✅ Database initialized with {user_count} users")
                
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "backup":
            create_persistent_backup()
        elif sys.argv[1] == "restore":
            restore_from_env()
        elif sys.argv[1] == "init":
            init_database_with_recovery()
    else:
        print("🚨 SAFE DEPLOYMENT PREPARATION")
        print("Creating backup before deployment...")
        if create_persistent_backup():
            print("✅ Ready for safe deployment!")
            print("📋 Next steps:")
            print("1. Copy user_backup.json to safe location")
            print("2. Add USER_BACKUP_DATA from .env.backup to Render environment variables")
            print("3. Deploy to Render")
        else:
            print("❌ Backup failed - DO NOT DEPLOY!")