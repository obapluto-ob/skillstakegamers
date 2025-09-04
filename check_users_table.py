import sqlite3

with sqlite3.connect("gamebet.db") as conn:
    c = conn.cursor()
    
    # Get table schema
    c.execute("PRAGMA table_info(users)")
    columns = c.fetchall()
    
    print("Users table columns:")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    
    # Get sample user data
    c.execute("SELECT * FROM users WHERE username != 'admin' ORDER BY id DESC LIMIT 3")
    users = c.fetchall()
    
    print(f"\nSample users ({len(users)} found):")
    for user in users:
        print(f"  ID: {user[0]}, Username: {user[1]}, Columns: {len(user)}")
        print(f"  Data: {user}")