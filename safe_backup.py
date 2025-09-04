import sqlite3
import json
import os
from datetime import datetime

def create_deployment_backup():
    """Create backup for safe deployment to Render"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Get all users
            c.execute('''SELECT username, email, password, balance, phone, referral_code, created_at
                         FROM users WHERE username != "admin" ORDER BY created_at''')
            users = c.fetchall()
            
            # Create user data structure
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
            
            # Create backup data
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'users': user_data
            }
            
            # Save as JSON file
            with open('user_backup.json', 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            # Create environment variable format
            backup_json = json.dumps(backup_data, separators=(',', ':'))
            with open('.env.backup', 'w') as f:
                f.write(f'USER_BACKUP_DATA="{backup_json}"\n')
            
            print(f"Deployment backup created: {len(user_data)} users")
            print("Files created:")
            print("- user_backup.json (readable backup)")
            print("- .env.backup (for Render environment)")
            
            return True
            
    except Exception as e:
        print(f"Backup creation failed: {e}")
        return False

def show_backup_instructions():
    """Show instructions for safe deployment"""
    print("\nSAFE DEPLOYMENT INSTRUCTIONS:")
    print("1. Copy the content from .env.backup")
    print("2. In Render dashboard, go to Environment Variables")
    print("3. Add new variable: USER_BACKUP_DATA")
    print("4. Paste the entire JSON string as the value")
    print("5. Deploy your app")
    print("6. The app will automatically restore users on startup")

if __name__ == "__main__":
    print("CREATING SAFE DEPLOYMENT BACKUP")
    if create_deployment_backup():
        show_backup_instructions()
    else:
        print("BACKUP FAILED - DO NOT DEPLOY!")