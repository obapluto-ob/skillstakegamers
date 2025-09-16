# Test unique features after adding routes
import sqlite3
import requests
import json

def test_database():
    """Test if unique features database is working"""
    try:
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
        
        print("TESTING UNIQUE FEATURES DATABASE:")
        print("=" * 50)
        
        # Test tables exist
        tables = ['skill_insurance', 'revenge_matches', 'skill_ratings', 'live_bets', 'skill_tokens']
        
        for table in tables:
            try:
                c.execute(f"SELECT COUNT(*) FROM {table}")
                count = c.fetchone()[0]
                print(f"OK {table}: {count} records")
            except Exception as e:
                print(f"ERROR {table}: {str(e)}")
        
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
        
            return True
        
    except Exception as e:
        print(f"DATABASE ERROR: {e}")
        return False

def test_routes():
    """Test if routes are working (requires Flask app running)"""
    try:
        print("\nTESTING ROUTES:")
        print("=" * 50)
        
        # Test unique dashboard route
        try:
            response = requests.get('http://localhost:5000/unique_dashboard', timeout=5)
            if response.status_code == 200:
                print("OK /unique_dashboard: Route accessible")
            else:
                print(f"ERROR /unique_dashboard: Status {response.status_code}")
        except:
            print("ERROR /unique_dashboard: Flask app not running or route not added")
        
        # Test API routes
        try:
            response = requests.get('http://localhost:5000/api/user_balance', timeout=5)
            if response.status_code in [200, 302]:  # 302 = redirect to login
                print("OK /api/user_balance: Route accessible")
            else:
                print(f"ERROR /api/user_balance: Status {response.status_code}")
        except:
            print("ERROR /api/user_balance: Flask app not running")
            
        return True
        
    except Exception as e:
        print(f"ROUTE TEST ERROR: {e}")
        return False

def create_test_data():
    """Create some test data for unique features"""
    try:
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
        
        print("\nCREATING TEST DATA:")
        print("=" * 50)
        
        # Get a test user
        c.execute("SELECT id FROM users WHERE username != 'admin' LIMIT 1")
        user = c.fetchone()
        
        if not user:
            print("ERROR: No test users found")
            return False
            
        user_id = user[0]
        
        # Add skill rating
        c.execute("INSERT OR REPLACE INTO skill_ratings (user_id, wins, losses, skill_score, win_streak, bounty_amount) VALUES (?, 5, 2, 1150, 3, 300)", (user_id,))
        
        # Add skill tokens
        c.execute("INSERT INTO skill_tokens (user_id, token_type, amount, source) VALUES (?, 'daily', 50, 'test_data')", (user_id,))
        c.execute("INSERT INTO skill_tokens (user_id, token_type, amount, source) VALUES (?, 'win', 25, 'test_data')", (user_id,))
        
            conn.commit()
            
            print("OK: Test data created successfully")
            return True
        
    except Exception as e:
        print(f"TEST DATA ERROR: {e}")
        return False

if __name__ == "__main__":
    print("SKILLSTAKE UNIQUE FEATURES TEST")
    print("=" * 60)
    
    # Test database
    db_ok = test_database()
    
    # Create test data
    if db_ok:
        create_test_data()
    
    # Test routes (optional - requires Flask running)
    test_routes()
    
    print("\n" + "=" * 60)
    if db_ok:
        print("SUCCESS: Database and unique features are ready!")
        print("NEXT STEPS:")
        print("1. Add the routes to your app.py file")
        print("2. Add link to dashboard template")
        print("3. Restart Flask app")
        print("4. Visit /unique_dashboard to test")
    else:
        print("ERROR: Database setup failed")
        print("Run: python setup_unique.py")