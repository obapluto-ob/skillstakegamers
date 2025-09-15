#!/usr/bin/env python3
"""
Database Migration Script for SkillStake Gaming Platform
Safely migrates and strengthens existing database without data loss
"""

import os
import sys
import sqlite3
from datetime import datetime
from database_manager import db_manager

def backup_existing_data():
    """Backup all existing data before migration"""
    print("Creating comprehensive backup...")
    
    if not os.path.exists('gamebet.db'):
        print("No existing database found. Will create fresh database.")
        return True
    
    try:
        # Create timestamped backup
        backup_path = db_manager.create_backup()
        
        # Export critical user data
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if users table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone():
                cursor.execute("SELECT id, username, email, balance FROM users")
                users = cursor.fetchall()
                
                # Save user summary
                with open(f'user_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt', 'w') as f:
                    f.write("USER BACKUP SUMMARY\n")
                    f.write("==================\n")
                    for user in users:
                        f.write(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Balance: {user[3]}\n")
                
                print(f"Backed up {len(users)} users")
            
        return True
        
    except Exception as e:
        print(f"Backup failed: {e}")
        return False

def migrate_database():
    """Perform safe database migration"""
    print("Starting database migration...")
    
    try:
        # Strengthen existing database
        db_manager.strengthen_database()
        
        # Verify data integrity
        stats = db_manager.get_database_stats()
        print("Database Statistics:")
        for table, count in stats.items():
            print(f"  {table}: {count} records")
        
        print("Database migration completed successfully!")
        return True
        
    except Exception as e:
        print(f"Migration failed: {e}")
        return False

def verify_migration():
    """Verify migration was successful"""
    print("Verifying migration...")
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check critical tables exist
            required_tables = ['users', 'transactions', 'game_matches']
            for table in required_tables:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
                if not cursor.fetchone():
                    print(f"Critical table {table} missing!")
                    return False
            
            # Check user data integrity
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM transactions")
            transaction_count = cursor.fetchone()[0]
            
            print(f"Verification passed: {user_count} users, {transaction_count} transactions")
            return True
            
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def main():
    """Main migration process"""
    print("SkillStake Database Migration Tool")
    print("==================================")
    
    # Step 1: Backup
    if not backup_existing_data():
        print("Cannot proceed without backup. Exiting.")
        sys.exit(1)
    
    # Step 2: Migrate
    if not migrate_database():
        print("Migration failed. Check backups in db_backups/ folder.")
        sys.exit(1)
    
    # Step 3: Verify
    if not verify_migration():
        print("Migration verification failed. Check database manually.")
        sys.exit(1)
    
    print("\nDATABASE MIGRATION SUCCESSFUL!")
    print("Your user data is safe and database is strengthened.")
    print("Backup files are available in db_backups/ folder.")

if __name__ == "__main__":
    main()