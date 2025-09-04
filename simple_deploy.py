#!/usr/bin/env python3
"""
Simple deployment script - just migrate users after deployment
"""

import json

def create_simple_migration():
    """Create simple user migration for after deployment"""
    
    # Load the backup data
    with open('migration_backup_20250904_152720.json', 'r') as f:
        data = json.load(f)
    
    # Create simple SQL script for PostgreSQL
    sql_script = """
-- Simple user migration for PostgreSQL
-- Run this after deployment

-- Insert users
"""
    
    for user in data['users']:
        username = user[1].replace("'", "''")  # Escape quotes
        email = user[2].replace("'", "''")
        password = user[3].replace("'", "''")
        balance = user[4]
        phone = user[5] or ''
        referral_code = user[6] or ''
        created_at = user[7] or 'NOW()'
        
        sql_script += f"""
INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('{username}', '{email}', '{password}', {balance}, '{phone}', '{referral_code}', '{created_at}', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;
"""
    
    # Save SQL script
    with open('restore_users.sql', 'w') as f:
        f.write(sql_script)
    
    print("[OK] Created restore_users.sql")
    print(f"[OK] Will restore {len(data['users'])} users")
    print(f"[OK] Total balance: KSh {data['total_balance']:.2f}")

if __name__ == "__main__":
    create_simple_migration()