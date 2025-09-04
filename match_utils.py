import sqlite3

def atomic_match_update(match_id, winner_id, status):
    """Atomically update match"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            c.execute('UPDATE matches SET winner_id = ?, status = ? WHERE id = ?', 
                     (winner_id, status, match_id))
            conn.commit()
            return True
    except Exception as e:
        print(f"Match update error: {e}")
        return False

def safe_balance_update(user_id, amount):
    """Safely update user balance"""
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', 
                     (amount, user_id))
            conn.commit()
            return True
    except Exception as e:
        print(f"Balance update error: {e}")
        return False