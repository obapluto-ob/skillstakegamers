# Test the unique features database
import sqlite3

def test_features():
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    print("TESTING UNIQUE FEATURES DATABASE:")
    print("=" * 50)
    
    # Test tables exist
    tables = ['skill_insurance', 'revenge_matches', 'skill_ratings', 'live_bets', 'skill_tokens']
    
    for table in tables:
        try:
            c.execute(f"SELECT COUNT(*) FROM {table}")
            count = c.fetchone()[0]
            print(f"✓ {table}: {count} records")
        except:
            print(f"✗ {table}: NOT FOUND")
    
    print("\nUSER BALANCES:")
    c.execute("SELECT username, balance FROM users WHERE username != 'admin' ORDER BY balance DESC LIMIT 5")
    users = c.fetchall()
    for user in users:
        print(f"  {user[0]}: KSh {user[1]}")
    
    print("\nRECENT TRANSACTIONS:")
    c.execute("SELECT type, amount, description FROM transactions ORDER BY created_at DESC LIMIT 3")
    transactions = c.fetchall()
    for tx in transactions:
        print(f"  {tx[0]}: KSh {tx[1]} - {tx[2]}")
    
    conn.close()

if __name__ == "__main__":
    test_features()