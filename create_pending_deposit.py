# Create a pending M-Pesa deposit for testing admin notifications

import sqlite3
from datetime import datetime

def create_pending_deposit():
    """Create a pending M-Pesa deposit to test admin notifications"""
    
    try:
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
            
            # Get a real user ID
            c.execute('SELECT id, username FROM users WHERE username != "admin" LIMIT 1')
            user = c.fetchone()
            
            if not user:
                print("No users found")
                return
            
            user_id, username = user
            
            # Create pending M-Pesa deposit
            amount = 100
            description = f'M-Pesa deposit pending - User: {username} - Amount: KSh {amount} - Paybill: 400200 - Account: 1075794 - Screenshot uploaded'
            
            c.execute('''INSERT INTO transactions (user_id, type, amount, description, created_at) 
                       VALUES (?, ?, ?, ?, ?)''',
                     (user_id, 'pending_deposit', amount, description, datetime.now().isoformat()))
            
            transaction_id = c.lastrowid
            conn.commit()
            
            print(f"+ Created pending M-Pesa deposit:")
            print(f"   Transaction ID: {transaction_id}")
            print(f"   User: {username} (ID: {user_id})")
            print(f"   Amount: KSh {amount}")
            print(f"   Description: {description}")
            
            # Check admin dashboard will show this
            c.execute('SELECT COUNT(*) FROM transactions WHERE type = "pending_deposit"')
            pending_count = c.fetchone()[0]
            
            print(f"\n+ Admin Dashboard Status:")
            print(f"   Total Pending Deposits: {pending_count}")
            print(f"   This deposit should now appear in admin notifications!")
            
            return {
                'success': True,
                'transaction_id': transaction_id,
                'user_id': user_id,
                'username': username,
                'amount': amount,
                'pending_count': pending_count
            }
            
    except Exception as e:
        print(f"- Error: {e}")
        return {'success': False, 'error': str(e)}

if __name__ == "__main__":
    result = create_pending_deposit()
    print(f"\n=== RESULT ===")
    print(result)