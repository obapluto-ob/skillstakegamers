import os
import psycopg2
from urllib.parse import urlparse

def setup_postgres():
    """Setup PostgreSQL for Render deployment"""
    database_url = os.getenv('DATABASE_URL')
    
    if database_url:
        url = urlparse(database_url)
        conn = psycopg2.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
        
        # Create tables for PostgreSQL
        with conn.cursor() as cur:
            cur.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                balance DECIMAL(10,2) DEFAULT 0.00,
                phone VARCHAR(20),
                referral_code VARCHAR(20),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                wins INTEGER DEFAULT 0,
                losses INTEGER DEFAULT 0,
                total_earnings DECIMAL(10,2) DEFAULT 0.00,
                referred_by INTEGER,
                banned INTEGER DEFAULT 0,
                email_verified INTEGER DEFAULT 0,
                last_login TIMESTAMP
            )''')
            
            cur.execute('''CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                type VARCHAR(50) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            cur.execute('''CREATE TABLE IF NOT EXISTS game_matches (
                id SERIAL PRIMARY KEY,
                game_type VARCHAR(50) NOT NULL,
                game_mode VARCHAR(50) NOT NULL,
                creator_id INTEGER REFERENCES users(id),
                creator_game_username VARCHAR(100) NOT NULL,
                opponent_id INTEGER REFERENCES users(id),
                opponent_game_username VARCHAR(100),
                stake_amount DECIMAL(10,2) NOT NULL,
                total_pot DECIMAL(10,2) NOT NULL,
                winner_id INTEGER REFERENCES users(id),
                status VARCHAR(20) DEFAULT 'open',
                creator_score INTEGER DEFAULT 0,
                opponent_score INTEGER DEFAULT 0,
                commission DECIMAL(10,2) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )''')
            
        conn.commit()
        conn.close()
        print("PostgreSQL setup complete")

if __name__ == "__main__":
    setup_postgres()