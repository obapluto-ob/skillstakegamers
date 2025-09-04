import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash

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
                    print(f"Recovered user: {username} (ID: {user_id})")
                except Exception as e:
                    print(f"Failed to recover user ID {user_id}: {e}")
            
            conn.commit()
            print(f"Emergency recovery completed: {recovered} users recovered")
            
    except Exception as e:
        print(f"Emergency recovery failed: {e}")

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
            
            backup_data = {
                'backup_timestamp': datetime.now().isoformat(),
                'users': [dict(zip(['id', 'username', 'email', 'password', 'balance', 'wins', 'losses', 
                                   'total_earnings', 'created_at', 'phone', 'referral_code', 'referred_by'], user)) 
                         for user in users],
                'transactions': [dict(zip(['id', 'user_id', 'type', 'amount', 'description', 'created_at'], tx)) 
                               for tx in transactions]
            }
            
            # Save to file
            backup_filename = f"user_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(backup_filename, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            print(f"Backup created: {backup_filename}")
            print(f"Users backed up: {len(users)}")
            print(f"Transactions backed up: {len(transactions)}")
            
            return backup_filename
            
    except Exception as e:
        print(f"Backup failed: {e}")
        return None

def recalculate_balances():
    """Recalculate user balances from transaction history"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Get all users
            c.execute('SELECT id, username FROM users WHERE username != "admin"')
            users = c.fetchall()
            
            for user_id, username in users:
                # Calculate balance from transactions
                c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ?', (user_id,))
                calculated_balance = c.fetchone()[0]
                
                # Update user balance
                c.execute('UPDATE users SET balance = ? WHERE id = ?', (calculated_balance, user_id))
                print(f"Updated {username}: KSh {calculated_balance}")
            
            conn.commit()
            print(f"Recalculated balances for {len(users)} users")
            
    except Exception as e:
        print(f"Balance recalculation failed: {e}")

if __name__ == "__main__":
    print("EMERGENCY USER DATA RECOVERY")
    print("1. Creating backup...")
    backup_file = backup_all_users()
    print("\n2. Running emergency recovery...")
    emergency_user_recovery()
    print("\n3. Recalculating balances...")
    recalculate_balances()
    print(f"\nRecovery complete! Backup saved as: {backup_file}")