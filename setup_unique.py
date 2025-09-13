# Setup unique features database
import sqlite3

def get_db_connection():
    return sqlite3.connect('gamebet.db')

def setup_tables():
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Skill Insurance
        c.execute('''CREATE TABLE IF NOT EXISTS skill_insurance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            insurance_fee REAL DEFAULT 50,
            activated INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Revenge Matches
        c.execute('''CREATE TABLE IF NOT EXISTS revenge_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_match_id INTEGER NOT NULL,
            challenger_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            multiplier REAL DEFAULT 1.5,
            humiliation_fee REAL DEFAULT 0,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Skill Ratings
        c.execute('''CREATE TABLE IF NOT EXISTS skill_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            wins INTEGER DEFAULT 0,
            losses INTEGER DEFAULT 0,
            skill_score REAL DEFAULT 1000,
            win_streak INTEGER DEFAULT 0,
            bounty_amount REAL DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Live Bets
        c.execute('''CREATE TABLE IF NOT EXISTS live_bets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER NOT NULL,
            bettor_id INTEGER NOT NULL,
            bet_type TEXT NOT NULL,
            bet_amount REAL NOT NULL,
            prediction TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Skill Tokens
        c.execute('''CREATE TABLE IF NOT EXISTS skill_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_type TEXT NOT NULL,
            amount INTEGER NOT NULL,
            source TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()
        print("SUCCESS: Database tables created!")

if __name__ == "__main__":
    setup_tables()
    print("READY: Unique features database setup complete!")