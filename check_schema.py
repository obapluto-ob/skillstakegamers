import sqlite3

def get_db_connection():
    return sqlite3.connect('gamebet.db')

def check_tournaments_schema():
    """Check the actual tournaments table schema"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("PRAGMA table_info(tournaments)")
            columns = c.fetchall()
            print("Tournaments table columns:")
            for col in columns:
                print(f"  {col[1]} ({col[2]})")
    except Exception as e:
        print(f'Schema check error: {e}')

if __name__ == '__main__':
    check_tournaments_schema()