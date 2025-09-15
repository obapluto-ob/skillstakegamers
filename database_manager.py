import sqlite3
import os
import json
import shutil
from datetime import datetime
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self, db_path='gamebet.db'):
        self.db_path = db_path
        self.backup_dir = 'db_backups'
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_backup(self):
        """Create backup before any database operations"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(self.backup_dir, f'gamebet_backup_{timestamp}.db')
        
        if os.path.exists(self.db_path):
            shutil.copy2(self.db_path, backup_path)
            print(f"Database backup created: {backup_path}")
            return backup_path
        return None
    
    @contextmanager
    def get_connection(self):
        """Safe database connection with automatic cleanup"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute('PRAGMA foreign_keys = ON')
            conn.execute('PRAGMA journal_mode = WAL')
            conn.execute('PRAGMA synchronous = NORMAL')
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    def safe_execute(self, query, params=None):
        """Execute query with error handling and backup"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return cursor.fetchall()
    
    def table_exists(self, table_name):
        """Check if table exists"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            return cursor.fetchone() is not None
    
    def column_exists(self, table_name, column_name):
        """Check if column exists in table"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = [row[1] for row in cursor.fetchall()]
            return column_name in columns
    
    def add_column_safe(self, table_name, column_name, column_type, default_value=None):
        """Safely add column if it doesn't exist"""
        if not self.column_exists(table_name, column_name):
            default_clause = f" DEFAULT {default_value}" if default_value else ""
            query = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}{default_clause}"
            self.safe_execute(query)
            print(f"Added column {column_name} to {table_name}")
    
    def create_indexes(self):
        """Create performance indexes"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_game_matches_creator ON game_matches(creator_id)",
            "CREATE INDEX IF NOT EXISTS idx_game_matches_opponent ON game_matches(opponent_id)",
            "CREATE INDEX IF NOT EXISTS idx_game_matches_status ON game_matches(status)",
            "CREATE INDEX IF NOT EXISTS idx_fpl_battles_creator ON fpl_battles(creator_id)",
            "CREATE INDEX IF NOT EXISTS idx_fpl_battles_opponent ON fpl_battles(opponent_id)"
        ]
        
        for index_query in indexes:
            try:
                self.safe_execute(index_query)
            except Exception as e:
                print(f"Index creation warning: {e}")
    
    def strengthen_database(self):
        """Strengthen existing database without losing data"""
        print("Strengthening database...")
        
        # Create backup first
        self.create_backup()
        
        # Add missing columns to existing tables
        self.add_column_safe('users', 'skill_tokens', 'INTEGER', '0')
        self.add_column_safe('users', 'email_verified', 'INTEGER', '0')
        self.add_column_safe('users', 'last_login', 'TIMESTAMP')
        self.add_column_safe('users', 'banned', 'INTEGER', '0')
        self.add_column_safe('users', 'total_earnings', 'REAL', '0.0')
        self.add_column_safe('users', 'wins', 'INTEGER', '0')
        self.add_column_safe('users', 'losses', 'INTEGER', '0')
        
        self.add_column_safe('transactions', 'payment_proof', 'TEXT')
        
        # Create missing tables safely
        self.create_missing_tables()
        
        # Create performance indexes
        self.create_indexes()
        
        print("Database strengthened successfully!")
    
    def create_missing_tables(self):
        """Create any missing tables"""
        tables = {
            'fpl_battles': '''CREATE TABLE IF NOT EXISTS fpl_battles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                battle_type TEXT NOT NULL,
                creator_id INTEGER NOT NULL,
                creator_fpl_id TEXT NOT NULL,
                opponent_id INTEGER,
                opponent_fpl_id TEXT,
                stake_amount REAL NOT NULL,
                total_pot REAL NOT NULL,
                winner_id INTEGER,
                status TEXT DEFAULT 'open',
                gameweek INTEGER DEFAULT 1,
                creator_points INTEGER DEFAULT 0,
                opponent_points INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (creator_id) REFERENCES users (id),
                FOREIGN KEY (opponent_id) REFERENCES users (id),
                FOREIGN KEY (winner_id) REFERENCES users (id)
            )''',
            
            'tournaments': '''CREATE TABLE IF NOT EXISTS tournaments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                game_type TEXT NOT NULL,
                entry_fee REAL NOT NULL,
                max_players INTEGER DEFAULT 16,
                prize_pool REAL DEFAULT 0,
                status TEXT DEFAULT 'open',
                current_players INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                starts_at TIMESTAMP,
                whatsapp_group TEXT
            )''',
            
            'tournament_participants': '''CREATE TABLE IF NOT EXISTS tournament_participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tournament_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (tournament_id) REFERENCES tournaments (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(tournament_id, user_id)
            )''',
            
            'vouchers': '''CREATE TABLE IF NOT EXISTS vouchers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                amount REAL NOT NULL,
                used_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (used_by) REFERENCES users (id)
            )''',
            
            'user_sessions': '''CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )''',
            
            'admin_logs': '''CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target_user_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES users (id),
                FOREIGN KEY (target_user_id) REFERENCES users (id)
            )'''
        }
        
        for table_name, create_query in tables.items():
            if not self.table_exists(table_name):
                self.safe_execute(create_query)
                print(f"Created table: {table_name}")
    
    def export_user_data(self, user_id):
        """Export all user data for recovery"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get user data
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user_data = cursor.fetchone()
            
            if not user_data:
                return None
            
            # Get transactions
            cursor.execute("SELECT * FROM transactions WHERE user_id = ?", (user_id,))
            transactions = cursor.fetchall()
            
            # Get matches
            cursor.execute("SELECT * FROM game_matches WHERE creator_id = ? OR opponent_id = ?", (user_id, user_id))
            matches = cursor.fetchall()
            
            # Get FPL battles
            cursor.execute("SELECT * FROM fpl_battles WHERE creator_id = ? OR opponent_id = ?", (user_id, user_id))
            fpl_battles = cursor.fetchall()
            
            export_data = {
                'user': user_data,
                'transactions': transactions,
                'matches': matches,
                'fpl_battles': fpl_battles,
                'export_date': datetime.now().isoformat()
            }
            
            return export_data
    
    def get_database_stats(self):
        """Get database statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            tables = ['users', 'transactions', 'game_matches', 'fpl_battles', 'tournaments']
            
            for table in tables:
                if self.table_exists(table):
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    stats[table] = cursor.fetchone()[0]
                else:
                    stats[table] = 0
            
            return stats

# Global database manager instance
db_manager = DatabaseManager()