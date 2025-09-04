import sqlite3

def get_db_connection():
    """Get database connection"""
    return sqlite3.connect("gamebet.db")

def execute_query(query, params=None):
    """Execute database query safely"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            return c.fetchall()
    except Exception as e:
        print(f"Database error: {e}")
        return None