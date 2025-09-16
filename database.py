import os
import sqlite3
from urllib.parse import urlparse
from database_manager import db_manager

def get_db_connection():
    """LEGACY: Use db_manager for new code. Kept for compatibility."""
    database_url = os.getenv('DATABASE_URL')
    
    if database_url:
        # Production - PostgreSQL
        try:
            import psycopg2
            url = urlparse(database_url)
            conn = psycopg2.connect(
                database=url.path[1:],
                user=url.username,
                password=url.password,
                host=url.hostname,
                port=url.port
            )
            conn.autocommit = True
            return conn
        except ImportError:
            print("psycopg2 not installed, falling back to SQLite")
            # Use safe connection from db_manager
            return sqlite3.connect('gamebet.db', timeout=30.0)
    else:
        # Local development - SQLite with safety features
        try:
            conn = sqlite3.connect('gamebet.db', timeout=30.0)
            conn.execute('PRAGMA foreign_keys = ON')
            conn.execute('PRAGMA journal_mode = WAL')
            return conn
        except Exception:
            if 'conn' in locals():
                conn.close()
            raise

def init_database():
    """Initialize database tables - ENHANCED VERSION"""
    print("Initializing database with enhanced safety...")
    
    # Use the new database manager for safety
    try:
        db_manager.strengthen_database()
        print("Database initialized successfully with all safety features!")
    except Exception as e:
        print(f"Using fallback initialization: {e}")
        # Fallback to original method if needed
        _legacy_init_database()

def _legacy_init_database():
    """Legacy database initialization - kept for compatibility"""
    with get_db_connection() as conn:
        c = conn.cursor()
    
    database_url = os.getenv('DATABASE_URL')
    
    if database_url:
        # PostgreSQL syntax
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            phone TEXT,
            referral_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            wins INTEGER DEFAULT 0,
            losses INTEGER DEFAULT 0,
            total_earnings REAL DEFAULT 0.0,
            referred_by INTEGER,
            banned INTEGER DEFAULT 0,
            skill_tokens INTEGER DEFAULT 0,
            email_verified INTEGER DEFAULT 0,
            last_login TIMESTAMP
        )''')
    else:
        # SQLite syntax - ENHANCED
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            phone TEXT,
            referral_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            wins INTEGER DEFAULT 0,
            losses INTEGER DEFAULT 0,
            total_earnings REAL DEFAULT 0.0,
            referred_by INTEGER,
            banned INTEGER DEFAULT 0,
            skill_tokens INTEGER DEFAULT 0,
            email_verified INTEGER DEFAULT 0,
            last_login TIMESTAMP
        )''')
    
    if database_url:
        # PostgreSQL syntax
        c.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            payment_proof TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS game_matches (
            id SERIAL PRIMARY KEY,
            game_type TEXT NOT NULL,
            game_mode TEXT NOT NULL,
            creator_id INTEGER REFERENCES users(id),
            creator_game_username TEXT NOT NULL,
            opponent_id INTEGER REFERENCES users(id),
            opponent_game_username TEXT,
            stake_amount REAL NOT NULL,
            total_pot REAL NOT NULL,
            winner_id INTEGER REFERENCES users(id),
            status TEXT DEFAULT 'open',
            creator_score INTEGER DEFAULT 0,
            opponent_score INTEGER DEFAULT 0,
            commission REAL DEFAULT 0,
            match_start_time TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )''')
    else:
        # SQLite syntax - ENHANCED
        c.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            payment_proof TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS game_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_type TEXT NOT NULL,
            game_mode TEXT NOT NULL,
            creator_id INTEGER NOT NULL,
            creator_game_username TEXT NOT NULL,
            opponent_id INTEGER,
            opponent_game_username TEXT,
            stake_amount REAL NOT NULL,
            total_pot REAL NOT NULL,
            winner_id INTEGER,
            status TEXT DEFAULT 'open',
            creator_score INTEGER DEFAULT 0,
            opponent_score INTEGER DEFAULT 0,
            commission REAL DEFAULT 0,
            match_start_time TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (creator_id) REFERENCES users (id),
            FOREIGN KEY (opponent_id) REFERENCES users (id),
            FOREIGN KEY (winner_id) REFERENCES users (id)
        )''')
    
        if not database_url:
            conn.commit()

# Safe database operations
def safe_execute(query, params=None):
    """Execute database query safely"""
    return db_manager.safe_execute(query, params)

def export_user_data(user_id):
    """Export user data for recovery"""
    return db_manager.export_user_data(user_id)

def get_database_stats():
    """Get database statistics"""
    return db_manager.get_database_stats()