#!/usr/bin/env python3
"""
Database initialization script for GameBet application
Run this before starting the app for the first time
"""

import sqlite3
import os
from werkzeug.security import generate_password_hash

def init_database():
    """Initialize all required database tables"""
    
    # Ensure we're in the correct directory
    db_path = 'gamebet.db'
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    print("Creating database tables...")
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        phone TEXT UNIQUE,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        total_earnings REAL DEFAULT 0.0,
        referral_code TEXT UNIQUE,
        referred_by INTEGER,
        banned INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (referred_by) REFERENCES users (id)
    )''')
    
    # Matches table
    c.execute('''CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game TEXT NOT NULL,
        player1_id INTEGER NOT NULL,
        player2_id INTEGER,
        bet_amount REAL NOT NULL,
        total_pot REAL NOT NULL,
        winner_id INTEGER,
        status TEXT DEFAULT 'pending',
        game_mode TEXT DEFAULT 'Standard',
        verification_type TEXT DEFAULT 'ocr',
        match_type TEXT DEFAULT 'public',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (player1_id) REFERENCES users (id),
        FOREIGN KEY (player2_id) REFERENCES users (id),
        FOREIGN KEY (winner_id) REFERENCES users (id)
    )''')
    
    # Transactions table
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        payment_proof TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Streams table
    c.execute('''CREATE TABLE IF NOT EXISTS streams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        match_id INTEGER,
        tournament_id INTEGER,
        title TEXT,
        viewers INTEGER DEFAULT 0,
        status TEXT DEFAULT 'live',
        stream_key TEXT,
        stream_type TEXT DEFAULT 'screen',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (match_id) REFERENCES matches (id)
    )''')
    
    # Match screenshots table
    c.execute('''CREATE TABLE IF NOT EXISTS match_screenshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        screenshot_data TEXT NOT NULL,
        claimed_result TEXT NOT NULL,
        ocr_analysis TEXT,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Fake screenshot tracking table
    c.execute('''CREATE TABLE IF NOT EXISTS fake_screenshot_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        match_id INTEGER,
        game_type TEXT,
        screenshot_data TEXT,
        fake_count INTEGER DEFAULT 0,
        is_banned INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (match_id) REFERENCES matches (id)
    )''')
    
    # Deposit verifications table
    c.execute('''CREATE TABLE IF NOT EXISTS deposit_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        mpesa_number TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        receipt_screenshot TEXT NOT NULL,
        amount_sent REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (transaction_id) REFERENCES transactions (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # PayPal payments table
    c.execute('''CREATE TABLE IF NOT EXISTS paypal_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        order_id TEXT UNIQUE NOT NULL,
        amount_kes REAL NOT NULL,
        amount_usd REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Crypto payments table
    c.execute('''CREATE TABLE IF NOT EXISTS crypto_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        payment_id TEXT UNIQUE,
        order_id TEXT NOT NULL,
        amount_kes REAL NOT NULL,
        amount_usd REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Withdrawal chat table
    c.execute('''CREATE TABLE IF NOT EXISTS withdrawal_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        withdrawal_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT (datetime('now')),
        FOREIGN KEY (withdrawal_id) REFERENCES transactions (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Admin notifications table
    c.execute('''CREATE TABLE IF NOT EXISTS admin_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        transaction_id INTEGER,
        message TEXT NOT NULL,
        type TEXT NOT NULL,
        status TEXT DEFAULT 'unread',
        created_at DATETIME DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (transaction_id) REFERENCES transactions (id)
    )''')
    
    # Admin activity table
    c.execute('''CREATE TABLE IF NOT EXISTS admin_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        last_active DATETIME DEFAULT (datetime('now'))
    )''')
    
    # Support escalations table
    c.execute('''CREATE TABLE IF NOT EXISTS support_escalations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        admin_response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # AI chat history table
    c.execute('''CREATE TABLE IF NOT EXISTS ai_chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        response TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Match messages table
    c.execute('''CREATE TABLE IF NOT EXISTS match_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Match lobbies table
    c.execute('''CREATE TABLE IF NOT EXISTS match_lobbies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER UNIQUE NOT NULL,
        creator_id INTEGER NOT NULL,
        lobby_code TEXT NOT NULL,
        lobby_password TEXT,
        status TEXT DEFAULT 'waiting',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (creator_id) REFERENCES users (id)
    )''')
    
    # User friends table
    c.execute('''CREATE TABLE IF NOT EXISTS user_friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        status TEXT DEFAULT 'accepted',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, friend_id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (friend_id) REFERENCES users (id)
    )''')
    
    # Stream viewers table
    c.execute('''CREATE TABLE IF NOT EXISTS stream_viewers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(stream_id, user_id),
        FOREIGN KEY (stream_id) REFERENCES streams (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Streaming competitions table
    c.execute('''CREATE TABLE IF NOT EXISTS streaming_competitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        entry_fee REAL DEFAULT 0,
        prize_pool REAL DEFAULT 0,
        start_time DATETIME,
        end_time DATETIME,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Competition participants table
    c.execute('''CREATE TABLE IF NOT EXISTS competition_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        competition_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        earnings REAL DEFAULT 0,
        losses REAL DEFAULT 0,
        total_viewers INTEGER DEFAULT 0,
        stream_time INTEGER DEFAULT 0,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(competition_id, user_id),
        FOREIGN KEY (competition_id) REFERENCES streaming_competitions (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Admin messages table
    c.execute('''CREATE TABLE IF NOT EXISTS admin_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        sent_by TEXT DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    print("Creating admin user...")
    
    # Create admin user if it doesn't exist
    c.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        admin_password = generate_password_hash('admin123')
        c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code) 
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 ('admin', 'admin@gamebet.local', admin_password, 1000000.0, '0700000000', 'ADMIN001'))
        print("Admin user created with username: admin, password: admin123")
    else:
        print("Admin user already exists")
    
    # Create indexes for better performance
    print("Creating database indexes...")
    
    try:
        c.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_matches_players ON matches(player1_id, player2_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_streams_status ON streams(status)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_screenshots_match ON match_screenshots(match_id)')
    except sqlite3.OperationalError as e:
        print(f"Index creation warning: {e}")
    
    conn.commit()
    conn.close()
    
    print("Database initialization completed successfully!")
    print(f"Database file created at: {os.path.abspath(db_path)}")

if __name__ == '__main__':
    init_database()