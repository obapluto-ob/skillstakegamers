import sqlite3
import json
import re
from datetime import datetime
from werkzeug.security import generate_password_hash

def find_users_from_transactions():
    """Find lost users from transaction descriptions and patterns"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Find unique usernames mentioned in transaction descriptions
            c.execute('SELECT DISTINCT description FROM transactions WHERE description IS NOT NULL')
            descriptions = c.fetchall()
            
            found_users = set()
            phone_numbers = set()
            
            for desc in descriptions:
                text = desc[0].lower()
                
                # Extract usernames from various patterns
                patterns = [
                    r'from (\w+)',
                    r'user (\w+)',
                    r'inviting (\w+)',
                    r'@(\w+)',
                    r'player (\w+)',
                    r'winner: (\w+)',
                    r'(\w+) \(',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, text)
                    for match in matches:
                        if len(match) > 2 and match not in ['admin', 'user', 'from', 'the']:
                            found_users.add(match)
                
                # Extract phone numbers
                phone_pattern = r'(\+?254\d{9}|\d{10})'
                phones = re.findall(phone_pattern, text)
                for phone in phones:
                    if phone.startswith('07') or phone.startswith('+254'):
                        phone_numbers.add(phone)
            
            print(f"Found {len(found_users)} potential usernames from transactions:")
            for user in sorted(found_users):
                print(f"  - {user}")
            
            print(f"\nFound {len(phone_numbers)} phone numbers:")
            for phone in sorted(phone_numbers):
                print(f"  - {phone}")
            
            return found_users, phone_numbers
            
    except Exception as e:
        print(f"Error finding users from transactions: {e}")
        return set(), set()

def find_users_from_matches():
    """Find lost users from match history"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Find user IDs that don't exist in users table
            c.execute('''SELECT DISTINCT player1_id FROM matches 
                         WHERE player1_id NOT IN (SELECT id FROM users)
                         UNION
                         SELECT DISTINCT player2_id FROM matches 
                         WHERE player2_id NOT IN (SELECT id FROM users) AND player2_id IS NOT NULL''')
            
            missing_user_ids = c.fetchall()
            
            print(f"Found {len(missing_user_ids)} missing user IDs from matches:")
            for user_id in missing_user_ids:
                print(f"  - User ID: {user_id[0]}")
            
            return [uid[0] for uid in missing_user_ids]
            
    except Exception as e:
        print(f"Error finding users from matches: {e}")
        return []

def recover_user_from_clues(username, phone=None, user_id=None):
    """Recover a single user from available clues"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Check if user already exists
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            if c.fetchone():
                print(f"User {username} already exists")
                return False
            
            # Calculate balance from transactions if user_id known
            balance = 0.0
            if user_id:
                c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ?', (user_id,))
                balance = c.fetchone()[0] or 0.0
            
            # Generate missing data
            email = f"{username}@recovered.local"
            if phone:
                email = f"{phone}@gamebet.local"
            
            password_hash = generate_password_hash("password123")
            
            if not phone:
                phone = f"0700{random.randint(100000, 999999)}"
            
            referral_code = f"{username[:3].upper()}{random.randint(1000, 9999)}"
            
            # Insert recovered user
            if user_id:
                c.execute('''INSERT INTO users (id, username, email, password, balance, phone, referral_code, created_at)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                         (user_id, username, email, password_hash, balance, phone, referral_code, datetime.now()))
            else:
                c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code, created_at)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (username, email, password_hash, balance, phone, referral_code, datetime.now()))
            
            conn.commit()
            print(f"Recovered user: {username} (Balance: KSh {balance})")
            return True
            
    except Exception as e:
        print(f"Failed to recover user {username}: {e}")
        return False

def interactive_recovery():
    """Interactive recovery process"""
    print("INTERACTIVE USER RECOVERY")
    print("Enter lost usernames (one per line, empty line to finish):")
    
    recovered = 0
    while True:
        username = input("Username: ").strip()
        if not username:
            break
        
        phone = input(f"Phone for {username} (optional): ").strip()
        if not phone:
            phone = None
        
        if recover_user_from_clues(username, phone):
            recovered += 1
    
    print(f"Recovered {recovered} users")

def auto_recovery():
    """Automatic recovery from transaction analysis"""
    print("AUTOMATIC USER RECOVERY")
    
    # Find clues
    usernames, phones = find_users_from_transactions()
    missing_ids = find_users_from_matches()
    
    recovered = 0
    
    # Recover users with IDs from matches
    for user_id in missing_ids:
        username = f"user_{user_id}"
        if recover_user_from_clues(username, user_id=user_id):
            recovered += 1
    
    # Recover users from transaction mentions
    for username in usernames:
        if len(username) > 2:
            if recover_user_from_clues(username):
                recovered += 1
    
    print(f"Auto-recovered {recovered} users")

if __name__ == "__main__":
    import sys
    import random
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "auto":
            auto_recovery()
        elif sys.argv[1] == "interactive":
            interactive_recovery()
        elif sys.argv[1] == "analyze":
            find_users_from_transactions()
            find_users_from_matches()
    else:
        print("LOST USER RECOVERY SYSTEM")
        print("1. Analyzing transaction history...")
        usernames, phones = find_users_from_transactions()
        print("\n2. Analyzing match history...")
        missing_ids = find_users_from_matches()
        
        print(f"\nRECOVERY OPTIONS:")
        print(f"- Run 'python find_lost_users.py auto' to auto-recover")
        print(f"- Run 'python find_lost_users.py interactive' for manual recovery")
        print(f"- Contact users to re-register with same phone numbers")