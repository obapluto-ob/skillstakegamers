import sqlite3
from contextlib import contextmanager

@contextmanager
def atomic_match_update():
    """Atomic match update context manager"""
    conn = sqlite3.connect("gamebet.db")
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def safe_balance_update(user_id, amount):
    """Safely update user balance"""
    try:
        with atomic_match_update() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
            return True
    except sqlite3.Error:
        return False