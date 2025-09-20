import os
import sqlite3
import psycopg2
from urllib.parse import urlparse

def migrate_to_postgres():
    """Migrate SQLite data to PostgreSQL"""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        print("No DATABASE_URL found")
        return
    
    # Connect to PostgreSQL
    url = urlparse(database_url)
    pg_conn = psycopg2.connect(
        database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
    )
    
    # Connect to SQLite
    sqlite_conn = sqlite3.connect('gamebet.db')
    sqlite_conn.row_factory = sqlite3.Row
    
    with pg_conn.cursor() as pg_cur:
        # Create tables
        pg_cur.execute('''CREATE TABLE IF NOT EXISTS users (
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
        
        # Migrate users
        sqlite_cur = sqlite_conn.cursor()
        sqlite_cur.execute('SELECT * FROM users')
        users = sqlite_cur.fetchall()
        
        for user in users:
            pg_cur.execute('''INSERT INTO users 
                (username, email, password, balance, phone, referral_code, wins, losses, total_earnings, referred_by, banned, email_verified)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING''',
                (user['username'], user['email'], user['password'], user['balance'], 
                 user['phone'], user['referral_code'], user['wins'], user['losses'],
                 user['total_earnings'], user['referred_by'], user['banned'], user['email_verified']))
    
    pg_conn.commit()
    pg_conn.close()
    sqlite_conn.close()
    print("Migration completed!")

if __name__ == "__main__":
    migrate_to_postgres()