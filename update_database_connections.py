#!/usr/bin/env python3
"""
Update all SQLite connections to use PostgreSQL-compatible connections
"""

import re

def update_app_py():
    """Update app.py to use get_db_connection() instead of sqlite3.connect()"""
    
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace all sqlite3.connect("gamebet.db") with get_db_connection()
    content = re.sub(
        r'sqlite3\.connect\(["\']gamebet\.db["\']\)',
        'get_db_connection()',
        content
    )
    
    # Replace with sqlite3.connect("gamebet.db") as conn: with get_db_connection() as conn:
    content = re.sub(
        r'with sqlite3\.connect\(["\']gamebet\.db["\']\) as conn:',
        'with get_db_connection() as conn:',
        content
    )
    
    # Replace ? placeholders with %s for PostgreSQL
    content = re.sub(
        r'c\.execute\(([^,]+),\s*\(([^)]+)\)\)',
        lambda m: f'c.execute({m.group(1).replace("?", "%s")}, ({m.group(2)}))',
        content
    )
    
    # Fix INSERT OR IGNORE for PostgreSQL
    content = re.sub(
        r'INSERT OR IGNORE INTO',
        'INSERT INTO',
        content
    )
    
    # Add ON CONFLICT DO NOTHING for unique constraints
    content = re.sub(
        r'INSERT INTO users \(([^)]+)\)\s*VALUES \(([^)]+)\)(?!\s*ON CONFLICT)',
        r'INSERT INTO users (\1) VALUES (\2) ON CONFLICT (username) DO NOTHING',
        content
    )
    
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("[OK] Updated app.py database connections")

if __name__ == "__main__":
    update_app_py()