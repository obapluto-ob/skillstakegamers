#!/usr/bin/env python3
"""
User Backup Script for SkillStake Gaming Platform
Creates environment variable backup of all users
"""

import sqlite3
import json
import os

def backup_users_to_env():
    """Backup all users to environment variable"""
    
    with sqlite3.connect('gamebet.db') as conn:
        c = conn.cursor()
        
        # Get all users except admin
        c.execute('''SELECT username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings
                     FROM users WHERE username != "admin" ORDER BY username''')
        users = c.fetchall()
        
        backup_data = {
            'users': [],
            'backup_date': '2024-01-28',
            'total_users': len(users),
            'total_balance': sum(user[3] for user in users)
        }
        
        for user in users:
            backup_data['users'].append({
                'username': user[0],
                'email': user[1], 
                'password_hash': user[2],
                'balance': user[3],
                'phone': user[4],
                'referral_code': user[5],
                'created_at': user[6],
                'wins': user[7] or 0,
                'losses': user[8] or 0,
                'total_earnings': user[9] or 0
            })
        
        # Convert to JSON string
        backup_json = json.dumps(backup_data, indent=2)
        
        print(f"=== USER BACKUP CREATED ===")
        print(f"Total users backed up: {len(users)}")
        print(f"Total balance: KSh {backup_data['total_balance']:.2f}")
        
        # Save to .env file
        env_content = f"""# PayPal Configuration
PAYPAL_CLIENT_ID=AT-oazZhMmPUtklfCvlFyO9qL3FypQWL4VE-03iehC1wgrTaWRh4C3J6CBh2fykV-xUUrZ9KEjdC8lDq
PAYPAL_CLIENT_SECRET=EGmDqVftpYT7vR1fS1BprWAZ4xL4hIFGkSIkAbaMSzj3cLrMs5hHVMY871sVzlzjo3OkivzdLTl8pEtn
PAYPAL_BASE_URL=https://api-m.sandbox.paypal.com

# NOWPayments Configuration
NOWPAYMENTS_API_KEY=YSRK1WV-3AF4QJ8-MWQ7V1D-BZK2018
NOWPAYMENTS_WEBHOOK_SECRET=your-webhook-secret-here

# Security
SECRET_KEY=gamebet_secret_key_2024_secure_random_string

# User Backup Data (Auto-restore on deployment)
USER_BACKUP_DATA='{backup_json.replace("'", "\\'")}'
"""
        
        with open('.env', 'w') as f:
            f.write(env_content)
        
        print("Backup saved to .env file")
        print("\nTo restore users after deployment, the app will automatically")
        print("detect empty database and restore from USER_BACKUP_DATA")
        
        # Also save as separate backup file
        with open('user_backup.json', 'w') as f:
            f.write(backup_json)
        
        print("Backup also saved to user_backup.json")

if __name__ == "__main__":
    backup_users_to_env()