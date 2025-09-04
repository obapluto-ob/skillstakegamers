import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime
import random

def add_lost_user(username, phone, balance=0.0, email=None):
    """Manually add a lost user back to the system"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Check if user already exists
            c.execute('SELECT id FROM users WHERE username = ? OR phone = ?', (username, phone))
            if c.fetchone():
                print(f"User {username} already exists!")
                return False
            
            # Generate missing data
            if not email:
                email = f"{phone}@recovered.local"
            
            password_hash = generate_password_hash("password123")
            referral_code = f"{username[:3].upper()}{random.randint(1000, 9999)}"
            
            # Insert user
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (username, email, password_hash, balance, phone, referral_code, datetime.now()))
            
            # Add recovery transaction
            user_id = c.lastrowid
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (user_id, 'admin_recovery', balance, f'User account recovered - Initial balance: KSh {balance}'))
            
            conn.commit()
            print(f"SUCCESS: Added {username} with KSh {balance}")
            print(f"Login: {username} / password123")
            return True
            
    except Exception as e:
        print(f"Failed to add {username}: {e}")
        return False

def bulk_recovery_from_list():
    """Recover multiple users from a list"""
    print("BULK USER RECOVERY")
    print("Enter user details (format: username,phone,balance)")
    print("Example: john,0712345678,500")
    print("Empty line to finish:")
    
    recovered = 0
    while True:
        line = input("User: ").strip()
        if not line:
            break
        
        try:
            parts = line.split(',')
            username = parts[0].strip()
            phone = parts[1].strip()
            balance = float(parts[2].strip()) if len(parts) > 2 else 0.0
            
            if add_lost_user(username, phone, balance):
                recovered += 1
        except Exception as e:
            print(f"Invalid format: {line} - {e}")
    
    print(f"Recovered {recovered} users")

def recover_from_backup_file(filename):
    """Recover users from a backup JSON file"""
    try:
        import json
        
        with open(filename, 'r') as f:
            backup_data = json.load(f)
        
        if 'users' not in backup_data:
            print("Invalid backup file format")
            return
        
        recovered = 0
        for user in backup_data['users']:
            try:
                username = user['username']
                phone = user.get('phone', f"070000{random.randint(1000, 9999)}")
                balance = user.get('balance', 0.0)
                email = user.get('email')
                
                if add_lost_user(username, phone, balance, email):
                    recovered += 1
            except Exception as e:
                print(f"Failed to recover user from backup: {e}")
        
        print(f"Recovered {recovered} users from backup")
        
    except Exception as e:
        print(f"Failed to read backup file: {e}")

def list_current_users():
    """List all current users"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            c.execute('''SELECT id, username, phone, balance, created_at 
                         FROM users WHERE username != "admin" 
                         ORDER BY created_at DESC''')
            users = c.fetchall()
            
            print(f"CURRENT USERS ({len(users)}):")
            print("-" * 60)
            for user_id, username, phone, balance, created_at in users:
                phone_str = phone or 'None'
            print(f"{user_id:3d} | {username:15s} | {phone_str:12s} | KSh {balance:8.2f} | {created_at}")
            
    except Exception as e:
        print(f"Error listing users: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "list":
            list_current_users()
        elif sys.argv[1] == "bulk":
            bulk_recovery_from_list()
        elif sys.argv[1] == "backup" and len(sys.argv) > 2:
            recover_from_backup_file(sys.argv[2])
        elif sys.argv[1] == "add" and len(sys.argv) >= 4:
            username = sys.argv[2]
            phone = sys.argv[3]
            balance = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
            add_lost_user(username, phone, balance)
    else:
        print("MANUAL USER RECOVERY SYSTEM")
        print("Commands:")
        print("  python manual_user_recovery.py list")
        print("  python manual_user_recovery.py add username phone [balance]")
        print("  python manual_user_recovery.py bulk")
        print("  python manual_user_recovery.py backup filename.json")
        print()
        list_current_users()