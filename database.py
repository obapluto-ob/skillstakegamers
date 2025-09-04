import os
import sqlite3
from urllib.parse import urlparse

def get_db_connection():
    """Get database connection - PostgreSQL for production, SQLite for local"""
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
            return sqlite3.connect('gamebet.db')
    else:
        # Local development - SQLite
        return sqlite3.connect('gamebet.db')

def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
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
            banned INTEGER DEFAULT 0
        )''')
    else:
        # SQLite syntax
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
            banned INTEGER DEFAULT 0
        )''')
    
    if database_url:
        # PostgreSQL syntax
        c.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            payment_proof TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS matches (
            id SERIAL PRIMARY KEY,
            game TEXT NOT NULL,
            player1_id INTEGER,
            player2_id INTEGER,
            bet_amount REAL NOT NULL,
            total_pot REAL NOT NULL,
            winner_id INTEGER,
            status TEXT DEFAULT 'pending',
            game_mode TEXT DEFAULT 'Standard',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verification_type TEXT DEFAULT 'ocr',
            match_type TEXT DEFAULT 'public'
        )''')
    else:
        # SQLite syntax
        c.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            payment_proof TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game TEXT NOT NULL,
            player1_id INTEGER,
            player2_id INTEGER,
            bet_amount REAL NOT NULL,
            total_pot REAL NOT NULL,
            winner_id INTEGER,
            status TEXT DEFAULT 'pending',
            game_mode TEXT DEFAULT 'Standard',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verification_type TEXT DEFAULT 'ocr',
            match_type TEXT DEFAULT 'public'
        )''')
    
    if not database_url:
        conn.commit()
    conn.close()