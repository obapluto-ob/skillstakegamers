#!/usr/bin/env python3
"""
Create Real User Backup - Only backup actual users with real data
"""

import sqlite3
import json
import os
from datetime import datetime

def create_real_backup():
    """Create backup of only real users with actual deposits/activity"""
    
    with sqlite3.connect('gamebet.db') as conn:
        c = conn.cursor()
        
        # Get all real users (excluding admin and test accounts)
        c.execute('''SELECT u.username, u.email, u.password, u.balance, u.phone, u.referral_code, 
                            u.created_at, u.wins, u.losses, u.total_earnings,
                            COUNT(t.id) as transaction_count,
                            COALESCE(SUM(CASE WHEN t.type IN ('deposit', 'paypal_deposit', 'crypto_deposit') THEN t.amount ELSE 0 END), 0) as total_deposits
                     FROM users u
                     LEFT JOIN transactions t ON u.id = t.user_id
                     WHERE u.username != "admin" 
                     GROUP BY u.id, u.username, u.email, u.password, u.balance, u.phone, u.referral_code, 
                              u.created_at, u.wins, u.losses, u.total_earnings
                     ORDER BY u.username''')
        users = c.fetchall()
        
        real_users = []
        total_real_balance = 0
        
        print("=== ANALYZING USERS FOR BACKUP ===")
        
        for user in users:
            username = user[0]
            balance = user[3]
            transaction_count = user[10]
            total_deposits = user[11]
            
            # Determine if user is "real" based on activity
            is_real = (
                balance > 0 or  # Has money
                transaction_count > 0 or  # Has transactions
                total_deposits > 0 or  # Made deposits
                username in ['plutomania', 'pluto', 'kaleb', 'kasongo', 'kasongomustgo', 'kolu', 'obapluto']  # Known real users
            )
            
            if is_real:
                real_users.append({
                    'username': user[0],
                    'email': user[1], 
                    'password_hash': user[2],
                    'balance': user[3],
                    'phone': user[4],
                    'referral_code': user[5],
                    'created_at': user[6],
                    'wins': user[7] or 0,
                    'losses': user[8] or 0,
                    'total_earnings': user[9] or 0,
                    'transaction_count': transaction_count,
                    'total_deposits': total_deposits
                })
                total_real_balance += balance
                print(f"[REAL] {username} - Balance: KSh {balance:.2f}, Transactions: {transaction_count}, Deposits: KSh {total_deposits:.2f}")
            else:
                print(f"[SKIP] {username} - No activity or balance")
        
        backup_data = {
            'users': real_users,
            'backup_date': datetime.now().isoformat(),
            'total_users': len(real_users),
            'total_balance': total_real_balance,
            'backup_type': 'REAL_USERS_ONLY'
        }
        
        # Save backup
        backup_json = json.dumps(backup_data, indent=2)
        
        # Update .env file with real user backup
        env_content = f'''# PayPal Configuration
PAYPAL_CLIENT_ID=AT-oazZhMmPUtklfCvlFyO9qL3FypQWL4VE-03iehC1wgrTaWRh4C3J6CBh2fykV-xUUrZ9KEjdC8lDq
PAYPAL_CLIENT_SECRET=EGmDqVftpYT7vR1fS1BprWAZ4xL4hIFGkSIkAbaMSzj3cLrMs5hHVMY871sVzlzjo3OkivzdLTl8pEtn
PAYPAL_BASE_URL=https://api-m.sandbox.paypal.com

# NOWPayments Configuration
NOWPAYMENTS_API_KEY=YSRK1WV-3AF4QJ8-MWQ7V1D-BZK2018
NOWPAYMENTS_WEBHOOK_SECRET=your-webhook-secret-here

# Security
SECRET_KEY=gamebet_secret_key_2024_secure_random_string

# Real User Backup Data (Auto-restore on deployment)
USER_BACKUP_DATA={backup_json.replace('"', '\\"')}
'''
        
        with open('.env', 'w') as f:
            f.write(env_content)
        
        # Also save as JSON file
        with open('real_users_backup.json', 'w') as f:
            f.write(backup_json)
        
        print(f"\n=== REAL USER BACKUP CREATED ===")
        print(f"Real users backed up: {len(real_users)}")
        print(f"Total real balance: KSh {total_real_balance:.2f}")
        print(f"Backup saved to .env and real_users_backup.json")
        
        return len(real_users), total_real_balance

if __name__ == "__main__":
    create_real_backup()