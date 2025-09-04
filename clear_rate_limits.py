import sqlite3

def clear_all_rate_limits():
    """Clear all rate limiting data"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Clear rate limit tracking
        c.execute('DROP TABLE IF EXISTS rate_limit_tracking')
        
        # Recreate empty table
        c.execute('''CREATE TABLE IF NOT EXISTS rate_limit_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT,
            endpoint TEXT,
            timestamp REAL,
            created_at DATETIME DEFAULT (datetime('now'))
        )''')
        
        conn.commit()
        print("All rate limits cleared!")

if __name__ == "__main__":
    clear_all_rate_limits()