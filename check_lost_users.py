import sqlite3
import json

def check_transaction_orphans():
    """Check for transactions without corresponding users"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Find transactions with user_ids that don't exist in users table
            c.execute('''SELECT DISTINCT t.user_id, COUNT(*) as tx_count, 
                                SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END) as deposits,
                                SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END) as withdrawals,
                                MIN(t.created_at) as first_tx,
                                MAX(t.created_at) as last_tx
                         FROM transactions t
                         LEFT JOIN users u ON t.user_id = u.id
                         WHERE u.id IS NULL AND t.user_id > 1
                         GROUP BY t.user_id
                         ORDER BY deposits DESC''')
            
            orphan_transactions = c.fetchall()
            
            if orphan_transactions:
                print(f"FOUND {len(orphan_transactions)} LOST USERS WITH MONEY!")
                print("=" * 60)
                
                total_lost_money = 0
                for user_id, tx_count, deposits, withdrawals, first_tx, last_tx in orphan_transactions:
                    balance = deposits - withdrawals
                    total_lost_money += balance
                    
                    print(f"User ID: {user_id}")
                    print(f"  Transactions: {tx_count}")
                    print(f"  Deposits: KSh {deposits}")
                    print(f"  Withdrawals: KSh {withdrawals}")
                    print(f"  BALANCE: KSh {balance}")
                    print(f"  First activity: {first_tx}")
                    print(f"  Last activity: {last_tx}")
                    print("-" * 40)
                
                print(f"TOTAL LOST MONEY: KSh {total_lost_money}")
                return orphan_transactions
            else:
                print("No lost users found - all transactions have corresponding users")
                return []
                
    except Exception as e:
        print(f"Error checking orphan transactions: {e}")
        return []

def get_user_details_from_transactions(user_id):
    """Extract user details from their transaction history"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Get all transactions for this user
            c.execute('''SELECT type, amount, description, created_at 
                         FROM transactions WHERE user_id = ? 
                         ORDER BY created_at''', (user_id,))
            transactions = c.fetchall()
            
            # Try to extract username and phone from descriptions
            username = None
            phone = None
            
            for tx_type, amount, desc, created_at in transactions:
                if desc:
                    # Look for phone numbers
                    import re
                    phone_match = re.search(r'(\+?254\d{9}|07\d{8})', desc)
                    if phone_match and not phone:
                        phone = phone_match.group(1)
                    
                    # Look for usernames in descriptions
                    if 'from' in desc.lower():
                        parts = desc.split('from')
                        if len(parts) > 1:
                            potential_name = parts[1].strip().split()[0]
                            if len(potential_name) > 2 and not username:
                                username = potential_name
            
            return {
                'user_id': user_id,
                'username': username or f'lost_user_{user_id}',
                'phone': phone or f'070000{user_id}',
                'transactions': len(transactions),
                'balance': sum(tx[1] for tx in transactions)
            }
            
    except Exception as e:
        print(f"Error getting details for user {user_id}: {e}")
        return None

def recover_lost_user(user_details):
    """Recover a lost user with their money"""
    try:
        from werkzeug.security import generate_password_hash
        import random
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            user_id = user_details['user_id']
            username = user_details['username']
            phone = user_details['phone']
            balance = user_details['balance']
            
            # Create user account
            email = f"{phone}@recovered.local"
            password_hash = generate_password_hash("password123")
            referral_code = f"{username[:3].upper()}{random.randint(1000, 9999)}"
            
            c.execute('''INSERT INTO users (id, username, email, password, balance, phone, referral_code, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))''',
                     (user_id, username, email, password_hash, balance, phone, referral_code))
            
            conn.commit()
            print(f"RECOVERED: {username} (ID: {user_id}) - Balance: KSh {balance}")
            return True
            
    except Exception as e:
        print(f"Failed to recover user {user_details['username']}: {e}")
        return False

if __name__ == "__main__":
    print("CHECKING FOR LOST USERS WITH MONEY...")
    
    orphans = check_transaction_orphans()
    
    if orphans:
        print("\nRECOVERING LOST USERS...")
        recovered = 0
        
        for user_id, tx_count, deposits, withdrawals, first_tx, last_tx in orphans:
            user_details = get_user_details_from_transactions(user_id)
            if user_details and recover_lost_user(user_details):
                recovered += 1
        
        print(f"\nRECOVERY COMPLETE: {recovered} users recovered with their money!")
    else:
        print("No lost users found.")