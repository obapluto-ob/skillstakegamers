import sqlite3
from contextlib import contextmanager

@contextmanager
def get_db_connection():
    """Get database connection with context manager"""
    conn = sqlite3.connect("gamebet.db")
    try:
        yield conn
    finally:
        conn.close()

def execute_query(query, params=None):
    """Execute query safely"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            conn.commit()
            return True, c.fetchall()
    except sqlite3.Error as e:
        return False, str(e)