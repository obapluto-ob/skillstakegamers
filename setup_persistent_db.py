#!/usr/bin/env python3
"""
Setup Persistent Database for Production
This prevents user data loss during deployments
"""

import os

def setup_production_database():
    """Setup instructions for persistent database"""
    
    print("=== PERSISTENT DATABASE SETUP ===")
    print()
    print("OPTION 1: PostgreSQL (FREE - RECOMMENDED)")
    print("1. Go to https://render.com/docs/databases")
    print("2. Create a FREE PostgreSQL database")
    print("3. Get the DATABASE_URL")
    print("4. Add to your .env file:")
    print("   DATABASE_URL=postgresql://username:password@host:port/database")
    print()
    
    print("OPTION 2: Railway PostgreSQL (FREE)")
    print("1. Go to https://railway.app")
    print("2. Create PostgreSQL database")
    print("3. Get connection string")
    print()
    
    print("OPTION 3: Supabase (FREE)")
    print("1. Go to https://supabase.com")
    print("2. Create project")
    print("3. Get PostgreSQL connection string")
    print()
    
    # Create database configuration
    db_config = '''
# Add this to your app.py to use PostgreSQL instead of SQLite

import os
import psycopg2
from urllib.parse import urlparse

def get_db_connection():
    """Get database connection - PostgreSQL for production, SQLite for local"""
    database_url = os.getenv('DATABASE_URL')
    
    if database_url:
        # Production - PostgreSQL
        url = urlparse(database_url)
        conn = psycopg2.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
        return conn
    else:
        # Local development - SQLite
        import sqlite3
        return sqlite3.connect('gamebet.db')

# Replace all sqlite3.connect("gamebet.db") with get_db_connection()
'''
    
    with open('database_setup_instructions.txt', 'w') as f:
        f.write(db_config)
    
    print("CRITICAL STEPS TO PREVENT DATA LOSS:")
    print("1. Set up external PostgreSQL database")
    print("2. Add DATABASE_URL to Render environment variables")
    print("3. Modify app.py to use PostgreSQL in production")
    print("4. Run database migration to transfer existing data")
    print()
    print("Instructions saved to: database_setup_instructions.txt")

if __name__ == "__main__":
    setup_production_database()